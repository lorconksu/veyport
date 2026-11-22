package client

import (
	"context"
	"errors"
	"time"

	"github.com/wyiu/veyport/agent/internal/filebrowser"
	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	"github.com/wyiu/veyport/proto/fileview"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func (s *activitySession) sendFileData(ctx context.Context, resp *pb.FileReadResponse) error {
	ctx, cancel := context.WithTimeout(ctx, fileview.FileDataIdleTimeout)
	defer cancel()
	record := fileDataRecord{
		ctx: ctx, sent: make(chan error, 1),
		message: &pb.AgentMessage{Payload: &pb.AgentMessage_FileReadResponse{FileReadResponse: resp}},
	}
	select {
	case s.fileData <- record:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-record.sent:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *activitySession) readTailInChunks(req *pb.FileReadRequest) {
	path := s.client.resolveAgentPath(req.GetPath())
	if !isPathAllowed(path, s.client.allowedPaths) {
		sendFileReadFailure(s.ctx, s.send, req, "path not in allowed list", pb.FileReadFailure_FILE_READ_FAILURE_ACCESS_DENIED)
		return
	}
	resp, _ := filebrowser.ReadFile(path, -1, fileview.MaxTailSize)
	if resp.GetError() != "" {
		sendFileReadFailure(s.ctx, s.send, req, resp.GetError(), pb.FileReadFailure_FILE_READ_FAILURE_UNSPECIFIED)
		return
	}
	if resp.GetTotalSize() > fileview.MaxFileSize {
		sendFileReadFailure(s.ctx, s.send, req, "file too large for viewing", pb.FileReadFailure_FILE_READ_FAILURE_TOO_LARGE)
		return
	}
	sendCtx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	for offset := 0; offset < len(resp.Data); offset += fileview.MaxChunkSize {
		end := min(offset+fileview.MaxChunkSize, len(resp.Data))
		err := s.sendFileData(sendCtx, &pb.FileReadResponse{
			RequestId: req.GetRequestId(), ChunkOffset: proto.Int64(int64(offset)), TotalSize: resp.GetTotalSize(), Data: resp.Data[offset:end],
		})
		if err != nil {
			sendFileReadFailure(s.ctx, s.send, req, "file data transfer timed out", pb.FileReadFailure_FILE_READ_FAILURE_TIMEOUT)
			return
		}
	}
	resp.RequestId = req.GetRequestId()
	resp.ChunkOffset = proto.Int64(int64(len(resp.Data)))
	resp.Data = nil
	resp.Done = true
	_ = sendFileRead(s.ctx, s.send, resp)
}

// startImageRead is called under the session admission lock. The process-wide
// slots and budget outlive reconnect until the actual worker exits.
func (s *activitySession) startImageRead(req *pb.FileReadRequest) {
	id := req.GetRequestId()
	if s.imageReads[id] != nil {
		return
	}
	select {
	case s.client.imagePreviewSlots <- struct{}{}:
	default:
		sendFileReadFailure(s.ctx, s.send, req, "agent image preview capacity reached", pb.FileReadFailure_FILE_READ_FAILURE_CAPACITY)
		return
	}
	release, err := s.budget.AcquireActivityWithError()
	if err != nil {
		<-s.client.imagePreviewSlots
		sendFileReadFailure(s.ctx, s.send, req, err.Error(), fileReadAdmissionFailure(err))
		return
	}
	readCtx, cancel := context.WithTimeout(s.ctx, fileview.ImageTransferTimeout)
	s.imageReads[id] = cancel
	go func() {
		defer release()
		defer func() { <-s.client.imagePreviewSlots }()
		defer cancel()
		s.readImage(readCtx, req)
		s.mu.Lock()
		delete(s.imageReads, id)
		s.mu.Unlock()
	}()
}

func (s *activitySession) readImage(ctx context.Context, req *pb.FileReadRequest) {
	size, err := s.streamImage(ctx, req)
	if err == nil {
		err = ctx.Err()
	}
	// The terminal record uses the generation context even after the read is
	// canceled. Only this record can confirm file closure to the Hub.
	switch {
	case errors.Is(err, filebrowser.ErrImageTooLarge):
		sendFileReadFailure(s.ctx, s.send, req, err.Error(), pb.FileReadFailure_FILE_READ_FAILURE_TOO_LARGE)
	case errors.Is(err, filebrowser.ErrImageAccess):
		sendFileReadFailure(s.ctx, s.send, req, err.Error(), pb.FileReadFailure_FILE_READ_FAILURE_ACCESS_DENIED)
	case errors.Is(err, context.DeadlineExceeded):
		sendFileReadFailure(s.ctx, s.send, req, "image transfer timed out", pb.FileReadFailure_FILE_READ_FAILURE_TIMEOUT)
	case errors.Is(err, context.Canceled):
		sendFileReadFailure(s.ctx, s.send, req, "image read canceled", pb.FileReadFailure_FILE_READ_FAILURE_UNSPECIFIED)
	case err != nil:
		sendFileReadFailure(s.ctx, s.send, req, err.Error(), pb.FileReadFailure_FILE_READ_FAILURE_UNSPECIFIED)
	default:
		_ = sendFileRead(s.ctx, s.send, &pb.FileReadResponse{
			RequestId: req.GetRequestId(), ChunkOffset: proto.Int64(size), TotalSize: size, Done: true,
		})
	}
}

func (s *activitySession) streamImage(ctx context.Context, req *pb.FileReadRequest) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	path := s.client.resolveAgentPath(req.GetPath())
	if !isPathAllowed(path, s.client.allowedPaths) {
		return 0, filebrowser.ErrImageAccess
	}
	return filebrowser.StreamImage(ctx, path, func(offset, size int64, data []byte) error {
		return s.sendFileData(ctx, &pb.FileReadResponse{
			RequestId: req.GetRequestId(), ChunkOffset: proto.Int64(offset), TotalSize: size, Data: data,
		})
	})
}

func fileReadAdmissionFailure(err error) pb.FileReadFailure {
	if errors.Is(err, sessionlimit.ErrActivityMaintenance) {
		return pb.FileReadFailure_FILE_READ_FAILURE_MAINTENANCE
	}
	return pb.FileReadFailure_FILE_READ_FAILURE_CAPACITY
}

func sendFileReadFailure(ctx context.Context, send chan<- *pb.AgentMessage, req *pb.FileReadRequest, message string, failure pb.FileReadFailure) {
	resp := &pb.FileReadResponse{RequestId: req.GetRequestId(), Error: message}
	if req.GetMode() != pb.FileReadMode_FILE_READ_MODE_LEGACY {
		resp.ChunkOffset = proto.Int64(0)
		resp.Done = true
		resp.Failure = failure
	}
	_ = sendFileRead(ctx, send, resp)
}

func sendFileRead(ctx context.Context, send chan<- *pb.AgentMessage, resp *pb.FileReadResponse) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case send <- &pb.AgentMessage{Payload: &pb.AgentMessage_FileReadResponse{FileReadResponse: resp}}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
