package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	maxUploadSize     = 100 * 1024 * 1024 // 100MB
	uploadChunkSize   = 64 * 1024         // 64KB
	uploadTimeout     = 30 * time.Second
	uploadBodyTimeout = 2 * time.Minute
	agentDropzonePath = "veyport://dropzone"
)

func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")

	// Check agent connected
	if _, ok := s.requireAgent(w, r); !ok {
		return
	}

	// Generate request ID and register for ack
	requestID := uuid.NewString()
	activity := s.beginAgentActivity(w, serverID, requestID, connmgr.ActivityUpload)
	if activity == nil {
		return
	}
	defer activity.Abandon()
	// Failure/cancellation requests cleanup; only the actual acknowledgement
	// releases the dispatched remote lifetime.
	completed := false
	defer func() {
		if completed || !activity.Dispatched() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.connMgr.SendToConnectionChecked(ctx, activity.Connection(), &pb.HubMessage{Payload: &pb.HubMessage_FileUploadAbort{FileUploadAbort: &pb.FileUploadAbort{RequestId: requestID}}}, nil)
	}()
	ch := s.pending.Register(serverID, requestID)
	defer s.pending.Remove(serverID, requestID)
	// Reserve before multipart parsing/body reads, including clients that hold
	// raw headers. A socket read deadline bounds stalled input without a reader goroutine.
	bodyCtx, cancelBody := context.WithTimeout(r.Context(), uploadBodyTimeout)
	defer cancelBody()
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(uploadBodyTimeout))
	readDeadlineDone := make(chan struct{})
	stopRead := context.AfterFunc(bodyCtx, func() { defer close(readDeadlineDone); _ = rc.SetReadDeadline(time.Now()) })
	defer func() {
		if !stopRead() {
			<-readDeadlineDone
		}
		_ = rc.SetReadDeadline(time.Time{})
	}()
	reader, filename, parseErr := parseMultipartFileStream(r)
	if parseErr != nil {
		respondError(w, parseErr.statusCode, parseErr.message)
		return
	}

	totalSize, streamErr := s.streamFileToActivity(bodyCtx, activity, requestID, filename, reader)
	if streamErr != nil {
		respondError(w, streamErr.statusCode, streamErr.message)
		return
	}

	// Wait for ack
	uploadTimer := time.NewTimer(uploadTimeout)
	defer uploadTimer.Stop()

	select {
	case msg := <-ch:
		ack, ok := msg.(*pb.FileUploadAck)
		if !ok {
			respondError(w, http.StatusInternalServerError, errUnexpectedResponse)
			return
		}
		s.connMgr.CompleteResponse(serverID, activity.Connection().Stream, ack)
		completed = true
		if !ack.Success {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("upload failed: %s", ack.Error))
			return
		}

		// Audit log
		userID := UserIDFromContext(r.Context())
		ip := clientIP(r)
		detail := filename
		s.auditLogRequest(r, model.AuditEntry{
			ID:        uuid.NewString(),
			UserID:    &userID,
			Action:    model.AuditFileUploaded,
			Target:    &serverID,
			Detail:    &detail,
			IPAddress: &ip,
		})
		if s.notifier != nil {
			uploaderName := userID
			if u, err := s.store.GetUserByID(userID); err == nil {
				uploaderName = u.Username
			}
			s.notifier.Notify(model.NotifyFileUploaded, map[string]string{
				"filename": filename, "server_name": serverID,
				"server_id": serverID, "username": uploaderName,
				"timestamp": time.Now().UTC().Format(model.NotifyTimestampFormat),
			})
		}

		respondJSON(w, http.StatusOK, model.UploadFileResponse{
			Filename: filename,
			Size:     totalSize,
		})
	case <-uploadTimer.C:
		respondError(w, http.StatusGatewayTimeout, "upload timeout")
	case <-bodyCtx.Done():
		return
	case <-activity.Connection().Done():
		respondError(w, http.StatusBadGateway, errAgentNotConnected)
	}
}

type uploadStreamError struct {
	statusCode int
	message    string
}

// parseMultipartFileStream returns a streaming reader for the "file" part of a
// multipart upload, plus the sanitised filename. It uses r.MultipartReader()
// so the body is never buffered in memory or to a temp file.
func parseMultipartFileStream(r *http.Request) (io.Reader, string, *uploadStreamError) {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return nil, "", &uploadStreamError{http.StatusBadRequest, "missing Content-Type header"}
	}

	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return nil, "", &uploadStreamError{http.StatusBadRequest, "expected multipart/form-data"}
	}

	boundary := params["boundary"]
	if boundary == "" {
		return nil, "", &uploadStreamError{http.StatusBadRequest, "missing multipart boundary"}
	}

	mr := multipart.NewReader(r.Body, boundary)

	// Iterate parts until we find the "file" field.
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return nil, "", &uploadStreamError{http.StatusBadRequest, "no file provided"}
		}
		if err != nil {
			return nil, "", &uploadStreamError{http.StatusBadRequest, "invalid multipart body"}
		}

		if part.FormName() != "file" {
			// Skip non-file parts (drain so the reader advances).
			continue
		}

		filename := filepath.Base(part.FileName())
		if filename == "" || filename == "." || filename == "/" {
			return nil, "", &uploadStreamError{http.StatusBadRequest, "filename is required"}
		}

		return part, filename, nil
	}
}

// streamFileToActivity sends the complete upload through its original admitted
// connection. The final acknowledgement, rather than this function's return,
// releases the remote lifetime.
func (s *Server) streamFileToActivity(ctx context.Context, activity *connmgr.Activity, requestID, filename string, file io.Reader) (int64, *uploadStreamError) {
	buf := make([]byte, uploadChunkSize)
	isFirst := true
	totalSize := int64(0)

	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			totalSize += int64(n)
			if totalSize > maxUploadSize {
				return 0, &uploadStreamError{http.StatusRequestEntityTooLarge, "file too large (max 100MB)"}
			}
			fname := chunkFilename(filename, &isFirst)
			if err := s.sendUploadActivity(ctx, activity, &pb.FileUploadRequest{RequestId: requestID, Filename: fname, Chunk: buf[:n]}); err != nil {
				return 0, err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return 0, &uploadStreamError{http.StatusInternalServerError, "failed to read file"}
		}
	}

	if finalErr := s.sendUploadActivity(ctx, activity, &pb.FileUploadRequest{RequestId: requestID, Filename: chunkFilename(filename, &isFirst), Done: true}); finalErr != nil {
		return 0, finalErr
	}
	return totalSize, nil
}

func (s *Server) sendUploadActivity(ctx context.Context, activity *connmgr.Activity, req *pb.FileUploadRequest) *uploadStreamError {
	call, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()
	if err := activity.Send(call, &pb.HubMessage{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: req}}); err != nil {
		return &uploadStreamError{http.StatusBadGateway, "failed to send to agent"}
	}
	return nil
}

// chunkFilename returns the filename for the first chunk and an empty string for subsequent chunks.
// It uses a pointer to track whether the first chunk has been sent.
func chunkFilename(filename string, isFirst *bool) string {
	if !*isFirst {
		return ""
	}
	*isFirst = false
	return filename
}

func (s *Server) handleDeleteDropzoneFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		respondError(w, http.StatusBadRequest, "filename is required")
		return
	}

	filename = filepath.Base(filename)
	if filename == "." || filename == "/" {
		respondError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	serverID, ok := s.requireAgent(w, r)
	if !ok {
		return
	}

	path := agentDropzonePath + "/" + filename
	raw := s.sendAgentRequestContext(r.Context(), w, serverID, uuid.NewString(), func(requestID string) *pb.HubMessage {
		return &pb.HubMessage{
			Payload: &pb.HubMessage_FileDeleteRequest{
				FileDeleteRequest: &pb.FileDeleteRequest{
					RequestId: requestID,
					Path:      path,
				},
			},
		}
	}, agentTimeoutDuration)
	if raw == nil {
		return
	}

	resp, ok := raw.(*pb.FileDeleteResponse)
	if !ok {
		respondError(w, http.StatusInternalServerError, errUnexpectedResponse)
		return
	}
	if !resp.Success {
		respondError(w, http.StatusInternalServerError, resp.Error)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListDropzone(w http.ResponseWriter, r *http.Request) {
	serverID, ok := s.requireAgent(w, r)
	if !ok {
		return
	}

	raw := s.sendAgentRequestContext(r.Context(), w, serverID, uuid.NewString(), func(requestID string) *pb.HubMessage {
		return &pb.HubMessage{
			Payload: &pb.HubMessage_FileListRequest{
				FileListRequest: &pb.FileListRequest{
					RequestId: requestID,
					Path:      agentDropzonePath,
				},
			},
		}
	}, agentTimeoutDuration)
	if raw == nil {
		return
	}

	resp, ok := raw.(*pb.FileListResponse)
	if !ok {
		respondError(w, http.StatusInternalServerError, errUnexpectedResponse)
		return
	}
	if resp.Error != "" {
		// Dropzone dir may not exist yet — return empty list
		respondJSON(w, http.StatusOK, model.FileListResult{Files: []*pb.FileNode{}})
		return
	}
	respondJSON(w, http.StatusOK, model.FileListResult{Files: resp.Files})
}
