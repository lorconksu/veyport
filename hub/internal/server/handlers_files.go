package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/proto/fileview"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	maxFileReadSize      = fileview.MaxTailSize
	maxFileViewSize      = fileview.MaxFileSize
	agentTimeoutDuration = 10 * time.Second
)

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	serverID := r.PathValue("id")
	if !s.checkFileAccess(w, r, serverID, path) {
		return
	}

	// Check agent is connected
	if _, ok := s.requireAgent(w, r); !ok {
		return
	}

	// Send request via gRPC and wait for response
	raw := s.sendAgentRequestContext(r.Context(), w, serverID, uuid.NewString(), func(requestID string) *pb.HubMessage {
		return &pb.HubMessage{
			Payload: &pb.HubMessage_FileListRequest{
				FileListRequest: &pb.FileListRequest{
					RequestId: requestID,
					Path:      path,
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
		respondError(w, http.StatusNotFound, resp.Error)
		return
	}
	respondJSON(w, http.StatusOK, model.FileListResult{Files: resp.Files})
}

func (s *Server) handleReadFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	serverID := r.PathValue("id")
	if !s.checkFileRead(w, r, serverID, path, r.Context()) {
		return
	}
	select {
	case s.fileTailSlots <- struct{}{}:
		defer func() { <-s.fileTailSlots }()
	default:
		respondError(w, http.StatusServiceUnavailable, "file reading is busy; try again")
		return
	}
	resp := s.readFile(w, r, serverID, path, pb.FileReadMode_FILE_READ_MODE_CHUNKED_TAIL, nil)
	if resp == nil {
		return
	}
	if resp.GetTotalSize() > maxFileViewSize {
		respondError(w, http.StatusRequestEntityTooLarge, "file too large for viewing")
		return
	}

	s.auditFileRead(r, serverID, path)
	respondJSON(w, http.StatusOK, model.FileReadResult{
		Data:      base64.StdEncoding.EncodeToString(resp.Data),
		TotalSize: resp.TotalSize,
		MimeType:  resp.MimeType,
	})
}

func (s *Server) checkFileRead(w http.ResponseWriter, r *http.Request, serverID, path string, setup context.Context) bool {
	if imageSetupEnded(r.Context(), setup, w) {
		return false
	}
	if path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return false
	}
	if !s.checkFileAccessContext(w, r, serverID, path, setup) {
		return false
	}
	if imageSetupEnded(r.Context(), setup, w) {
		return false
	}
	_, ok := s.requireAgent(w, r)
	return ok
}

func (s *Server) readFile(w http.ResponseWriter, r *http.Request, serverID, path string, mode pb.FileReadMode, setup context.Context) *pb.FileReadResponse {
	offset, limit := int64(-1), int64(maxFileReadSize)
	if mode == pb.FileReadMode_FILE_READ_MODE_IMAGE {
		// An older agent ignores Mode. Keep its one-shot answer below the
		// control stream receive limit before returning an upgrade error.
		offset, limit = 0, 1
	}
	requestID := uuid.NewString()
	msg := &pb.HubMessage{
		Payload: &pb.HubMessage_FileReadRequest{
			FileReadRequest: &pb.FileReadRequest{
				RequestId: requestID,
				Path:      path,
				Offset:    offset,
				Limit:     limit,
				Mode:      mode,
			},
		},
	}
	raw := s.sendAgentRequest(r.Context(), setup, w, serverID, requestID, msg, agentTimeoutDuration)
	if raw == nil {
		return nil
	}

	resp, ok := raw.(*pb.FileReadResponse)
	if !ok {
		respondError(w, http.StatusInternalServerError, errUnexpectedResponse)
		return nil
	}
	if resp.GetError() != "" {
		status := http.StatusNotFound
		switch resp.GetFailure() {
		case pb.FileReadFailure_FILE_READ_FAILURE_ACCESS_DENIED:
			if mode == pb.FileReadMode_FILE_READ_MODE_IMAGE {
				status = http.StatusForbidden
			}
		case pb.FileReadFailure_FILE_READ_FAILURE_TOO_LARGE:
			status = http.StatusRequestEntityTooLarge
		case pb.FileReadFailure_FILE_READ_FAILURE_CAPACITY:
			status = http.StatusServiceUnavailable
		case pb.FileReadFailure_FILE_READ_FAILURE_MAINTENANCE:
			status = http.StatusConflict
		case pb.FileReadFailure_FILE_READ_FAILURE_TIMEOUT:
			status = http.StatusGatewayTimeout
		}
		respondError(w, status, resp.GetError())
		return nil
	}
	return resp
}

func (s *Server) auditFileRead(r *http.Request, serverID, path string) {
	userID := UserIDFromContext(r.Context())
	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &userID,
		Action:    model.AuditFileRead,
		Target:    &serverID,
		Detail:    &path,
		IPAddress: &ip,
	})
}

// checkFileAccess validates the path and checks that the user is allowed to access it.
// Returns false (and writes the error response) if access should be denied.
func (s *Server) checkFileAccess(w http.ResponseWriter, r *http.Request, serverID, path string) bool {
	return s.checkFileAccessContext(w, r, serverID, path, r.Context())
}

func (s *Server) checkFileAccessContext(w http.ResponseWriter, r *http.Request, serverID, path string, ctx context.Context) bool {
	if err := validateRequestPath(path); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return false
	}

	role := UserRoleFromContext(r.Context())
	if role != "admin" {
		userID := UserIDFromContext(r.Context())
		allowed, err := s.isPathAllowed(ctx, userID, serverID, path)
		if imageSetupEnded(r.Context(), ctx, w) {
			return false
		}
		if err != nil || !allowed {
			respondError(w, http.StatusForbidden, "access denied")
			return false
		}
	}
	return true
}

// isPathAllowed checks if the requested path is under one of the user's allowed roots.
func (s *Server) isPathAllowed(ctx context.Context, userID, serverID, requestedPath string) (bool, error) {
	paths, err := s.store.GetUserPathsForServerContext(ctx, userID, serverID)
	if err != nil {
		return false, err
	}
	cleanedReq := filepath.Clean(requestedPath)
	for _, allowed := range paths {
		cleanedAllowed := filepath.Clean(allowed)
		rel, err := filepath.Rel(cleanedAllowed, cleanedReq)
		if err != nil {
			continue
		}
		// rel must not escape the allowed root — "." means exact match,
		// anything starting with ".." means the path is outside the root.
		if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..") {
			return true, nil
		}
	}
	return false, nil
}

// validateRequestPath checks for path traversal and ensures absolute path.
func validateRequestPath(path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path must be absolute")
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed")
	}
	return nil
}
