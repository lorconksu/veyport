package client

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/wyiu/veyport/agent/internal/dropzone"
	"github.com/wyiu/veyport/agent/internal/logtailer"
	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

const errActivityAdmission = "agent maintenance or activity capacity is active"

// activitySession closes admission before disconnect cleanup. Outstanding
// workers keep their process-wide reservations until they actually return.
type activitySession struct {
	mu                sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	controlCancel     context.CancelFunc
	client            *Client
	budget            *sessionlimit.Budget
	dropzone          *dropzone.Dropzone
	send              chan<- *pb.AgentMessage
	closed            bool
	tails             map[string]context.CancelFunc
	detach            func()
	capabilityTimeout time.Duration
	applications      *applicationTransport
}

func newActivitySession(ctx context.Context, c *Client, send chan<- *pb.AgentMessage, controlCancels ...context.CancelFunc) *activitySession {
	ctx, cancel := context.WithCancel(ctx)
	s := &activitySession{ctx: ctx, cancel: cancel, client: c, budget: c.budget, dropzone: dropzone.NewWithBudget(c.dropzone.Dir(), c.budget), send: send, tails: make(map[string]context.CancelFunc), capabilityTimeout: 5 * time.Second}
	if len(controlCancels) != 0 {
		s.controlCancel = controlCancels[0]
	}
	return s
}

func (s *activitySession) observe(base *pb.UpdateCapabilities, initialStatus *pb.AgentUpdateStatus) {
	// The immutable base avoids taking Runtime.mu while Budget.mu is held.
	initial := true
	s.detach = s.budget.ObserveActivities(func(count uint32) {
		capability := proto.Clone(base).(*pb.UpdateCapabilities)
		capability.ActivityQuiescenceVersion = 1
		capability.ActiveActivities = count
		s.sendCapability(&pb.AgentMessage{Payload: &pb.AgentMessage_UpdateCapabilities{UpdateCapabilities: capability}})
		if initial && initialStatus != nil {
			s.sendCapability(&pb.AgentMessage{Payload: &pb.AgentMessage_UpdateStatus{UpdateStatus: initialStatus}})
		}
		initial = false
	})
}

func (s *activitySession) sendCapability(message *pb.AgentMessage) {
	if s.ctx.Err() != nil {
		return
	}
	timer := time.NewTimer(s.capabilityTimeout)
	defer timer.Stop()
	select {
	case s.send <- message:
	case <-s.ctx.Done():
	case <-timer.C:
		// A count is never silently dropped while this session admits work.
		// Close admission and reconnect to retry the authoritative snapshot.
		s.cancel()
		if s.controlCancel != nil {
			// Cancel the underlying gRPC stream too: its Send may itself be
			// blocked and unable to consume the reconnect notification.
			s.controlCancel()
		} else {
			select {
			case s.client.reconnectCh <- struct{}{}:
			default:
			}
		}
	}
}

func (s *activitySession) close() {
	// Cancellation first unblocks queued responses/capabilities even if a
	// synchronous chunk handler holds admission while finishing its file.
	s.cancel()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	if s.detach != nil {
		s.detach()
	}
	s.dropzone.Cleanup()
}

// dispatch runs on the receive loop, not in a goroutine. This is the atomic
// admission boundary before any asynchronous file or tail worker exists.
func (s *activitySession) dispatch(message *pb.HubMessage) bool {
	switch message.Payload.(type) {
	case *pb.HubMessage_FileListRequest, *pb.HubMessage_FileReadRequest, *pb.HubMessage_FileDeleteRequest,
		*pb.HubMessage_FileUploadRequest, *pb.HubMessage_FileUploadAbort,
		*pb.HubMessage_LogStreamRequest, *pb.HubMessage_LogStreamStop:
	default:
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return true
	}
	switch p := message.Payload.(type) {
	case *pb.HubMessage_FileUploadRequest:
		req := p.FileUploadRequest
		if ack := s.dropzone.HandleChunk(req.RequestId, req.Filename, req.Chunk, req.Done); ack != nil {
			sendResponse(s.ctx, s.send, &pb.AgentMessage{Payload: &pb.AgentMessage_FileUploadAck{FileUploadAck: ack}})
		}
		return true
	case *pb.HubMessage_FileUploadAbort:
		ack := s.dropzone.Abort(p.FileUploadAbort.RequestId)
		sendResponse(s.ctx, s.send, &pb.AgentMessage{Payload: &pb.AgentMessage_FileUploadAck{FileUploadAck: ack}})
		return true
	case *pb.HubMessage_LogStreamStop:
		if stop := s.tails[p.LogStreamStop.RequestId]; stop != nil {
			stop()
		}
		return true
	case *pb.HubMessage_LogStreamRequest:
		s.startTail(p.LogStreamRequest)
		return true
	}
	release, admitted := s.budget.AcquireActivity()
	if !admitted {
		s.reject(message)
		return true
	}
	go func() {
		defer release()
		switch p := message.Payload.(type) {
		case *pb.HubMessage_FileListRequest:
			s.client.handleFileListRequest(p, s.send, s.ctx)
		case *pb.HubMessage_FileReadRequest:
			s.client.handleFileReadRequest(p, s.send, s.ctx)
		case *pb.HubMessage_FileDeleteRequest:
			s.client.handleFileDeleteRequest(p, s.send, s.ctx)
		}
	}()
	return true
}

func (s *activitySession) startTail(req *pb.LogStreamRequest) {
	path := s.client.resolveAgentPath(req.Path)
	reason := ""
	if !isPathAllowed(path, s.client.allowedPaths) {
		reason = "path not in allowed list"
	}
	s.client.tailSessionsMu.Lock()
	if s.client.tailSessions[req.RequestId] != nil {
		s.client.tailSessionsMu.Unlock()
		// A duplicate is not completion of the existing worker with this ID.
		sendResponse(s.ctx, s.send, &pb.AgentMessage{Payload: &pb.AgentMessage_LogStreamChunk{LogStreamChunk: &pb.LogStreamChunk{RequestId: req.RequestId, Error: "duplicate log stream request", Data: []byte("error: duplicate log stream request")}}})
		return
	}
	if len(s.client.tailSessions) >= maxTailSessions {
		reason = "too many active tail sessions"
	}
	if reason != "" {
		s.client.tailSessionsMu.Unlock()
		s.tailDone(req.RequestId, reason)
		return
	}
	release, admitted := s.budget.AcquireActivity()
	if !admitted {
		s.client.tailSessionsMu.Unlock()
		s.tailDone(req.RequestId, errActivityAdmission)
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	token := make(chan struct{})
	s.client.tailSessions[req.RequestId] = token
	s.client.tailSessionsMu.Unlock()
	s.tails[req.RequestId] = cancel
	go func() {
		err := logtailer.Tail(ctx, path, req.Grep, req.Offset, s.send, req.RequestId, nil)
		reason := ""
		if err != nil && !errors.Is(err, context.Canceled) {
			reason = err.Error()
		}
		s.tailDone(req.RequestId, reason)
		s.mu.Lock()
		delete(s.tails, req.RequestId)
		s.mu.Unlock()
		s.client.tailSessionsMu.Lock()
		if s.client.tailSessions[req.RequestId] == token {
			delete(s.client.tailSessions, req.RequestId)
		}
		s.client.tailSessionsMu.Unlock()
		cancel()
		release()
	}()
}

func (s *activitySession) tailDone(id, reason string) {
	chunk := &pb.LogStreamChunk{RequestId: id, Done: true, Error: reason}
	if reason != "" {
		chunk.Data = []byte("error: " + reason)
	}
	sendResponse(s.ctx, s.send, &pb.AgentMessage{Payload: &pb.AgentMessage_LogStreamChunk{LogStreamChunk: chunk}})
}

func (s *activitySession) reject(message *pb.HubMessage) {
	response := &pb.AgentMessage{}
	switch p := message.Payload.(type) {
	case *pb.HubMessage_FileListRequest:
		response.Payload = &pb.AgentMessage_FileListResponse{FileListResponse: &pb.FileListResponse{RequestId: p.FileListRequest.RequestId, Error: errActivityAdmission}}
	case *pb.HubMessage_FileReadRequest:
		response.Payload = &pb.AgentMessage_FileReadResponse{FileReadResponse: &pb.FileReadResponse{RequestId: p.FileReadRequest.RequestId, Error: errActivityAdmission}}
	case *pb.HubMessage_FileDeleteRequest:
		response.Payload = &pb.AgentMessage_FileDeleteResponse{FileDeleteResponse: &pb.FileDeleteResponse{RequestId: p.FileDeleteRequest.RequestId, Error: errActivityAdmission}}
	}
	sendResponse(s.ctx, s.send, response)
}

func responseContext(contexts []context.Context) context.Context {
	if len(contexts) != 0 {
		return contexts[0]
	}
	return context.Background()
}

func sendResponse(ctx context.Context, send chan<- *pb.AgentMessage, message *pb.AgentMessage) {
	if ctx.Err() != nil {
		return
	}
	select {
	case send <- message:
	case <-ctx.Done():
	}
}
