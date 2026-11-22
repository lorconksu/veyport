package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/proto/fileview"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

// requireAgent checks agent connectivity and returns the server ID.
// Returns ("", false) if the response has been written with an error.
func (s *Server) requireAgent(w http.ResponseWriter, r *http.Request) (string, bool) {
	serverID := r.PathValue("id")
	if s.connMgr == nil {
		respondError(w, http.StatusBadGateway, errAgentNotConnected)
		return "", false
	}
	if s.connMgr.GetConn(serverID) == nil {
		respondError(w, http.StatusBadGateway, errAgentNotConnected)
		return "", false
	}
	return serverID, true
}

// sendAgentRequestContext retains a typed connection reservation independently
// of its HTTP waiter, so timeout/cancellation cannot claim remote completion.
func (s *Server) sendAgentRequestContext(ctx context.Context, w http.ResponseWriter, serverID, requestID string, buildMsg func(string) *pb.HubMessage, timeout time.Duration) interface{} {
	return s.sendAgentRequest(ctx, nil, w, serverID, requestID, buildMsg(requestID), timeout)
}

func (s *Server) sendAgentRequest(ctx, setup context.Context, w http.ResponseWriter, serverID, requestID string, msg *pb.HubMessage, timeout time.Duration) interface{} {
	readRequest := msg.GetFileReadRequest()
	imageRead := readRequest.GetMode() == pb.FileReadMode_FILE_READ_MODE_IMAGE
	if imageRead && setup == nil {
		var cancel context.CancelFunc
		setup, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	conn := s.connMgr.GetConn(serverID)
	var activity *connmgr.Activity
	var err error
	if imageRead {
		activity, err = s.connMgr.BeginRequestContext(setup, conn, msg)
	} else {
		activity, err = s.connMgr.BeginRequest(conn, msg)
	}
	if err != nil {
		if imageRead && imageSetupEnded(ctx, setup, w) {
			return nil
		}
		status := http.StatusConflict
		if readRequest != nil && errors.Is(err, connmgr.ErrActivityCapacity) {
			status = http.StatusServiceUnavailable
		}
		respondError(w, status, err.Error())
		return nil
	}
	defer activity.Abandon()

	imageDispatched := false
	defer func() {
		if imageDispatched {
			activity.CancelImageRead()
		}
	}()
	var ch chan proto.Message
	window := agentResponseWindow{idle: timeout}
	if readRequest != nil && readRequest.GetMode() != pb.FileReadMode_FILE_READ_MODE_LEGACY {
		ch, window.progress = s.pending.RegisterFileRead(serverID, conn.Stream, readRequest)
	} else {
		ch = s.pending.Register(serverID, requestID)
	}
	defer s.pending.Remove(serverID, requestID)

	if imageRead {
		err = activity.SendImageRead(setup, msg, timeout)
		imageDispatched = err == nil
	} else {
		sendCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		err = activity.Send(sendCtx, msg)
	}
	if err != nil {
		if !imageRead || !imageSetupEnded(ctx, setup, w) {
			respondError(w, http.StatusBadGateway, errAgentNotConnected)
		}
		return nil
	}

	if imageRead {
		window.idle = fileview.FileDataIdleTimeout
		window.maximum = fileview.ImageTransferTimeout
	}
	return s.waitAgentResponse(ctx, w, conn, ch, window)
}

func imageSetupEnded(request, setup context.Context, w http.ResponseWriter) bool {
	if request.Err() != nil {
		return true
	}
	if setup.Err() != nil {
		respondError(w, http.StatusGatewayTimeout, "image request setup timed out")
		return true
	}
	return false
}

type agentResponseWindow struct {
	idle, maximum time.Duration
	progress      <-chan time.Time
}

func (s *Server) waitAgentResponse(ctx context.Context, w http.ResponseWriter, conn *connmgr.AgentConn, ch <-chan proto.Message, window agentResponseWindow) interface{} {
	waitCtx := ctx
	if window.maximum > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, window.maximum)
		defer cancel()
	}
	idle := time.NewTimer(window.idle)
	defer idle.Stop()
	for waitCtx.Err() == nil {
		select {
		case resp := <-ch:
			if resp == nil || s.connMgr.GetConn(conn.ServerID) != conn {
				respondError(w, http.StatusBadGateway, "incomplete or invalid agent response")
				return nil
			}
			s.connMgr.CompleteResponse(conn.ServerID, conn.Stream, resp)
			return resp
		case <-conn.Done():
			respondError(w, http.StatusBadGateway, errAgentNotConnected)
			return nil
		case <-waitCtx.Done():
			// The loop reports a transfer deadline separately from a caller cancel.
		case progress := <-window.progress:
			idle.Reset(time.Until(progress.Add(window.idle)))
		case <-idle.C:
			if recentAgentProgress(window, idle) {
				continue
			}
			respondError(w, http.StatusGatewayTimeout, "agent timeout")
			return nil
		}
	}
	if ctx.Err() == nil {
		respondError(w, http.StatusGatewayTimeout, "image transfer timed out")
	}
	return nil
}

func recentAgentProgress(window agentResponseWindow, timer *time.Timer) bool {
	select {
	case progress := <-window.progress:
		if remaining := time.Until(progress.Add(window.idle)); remaining > 0 {
			timer.Reset(remaining)
			return true
		}
	default:
	}
	return false
}

func (s *Server) beginAgentActivity(w http.ResponseWriter, node, id string, kind connmgr.ActivityKind) *connmgr.Activity {
	a, err := s.connMgr.BeginActivity(s.connMgr.GetConn(node), id, kind)
	if err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return nil
	}
	return a
}
