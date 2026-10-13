package server

import (
	"context"
	"net/http"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
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
	msg := buildMsg(requestID)
	conn := s.connMgr.GetConn(serverID)
	activity, err := s.connMgr.BeginRequest(conn, msg)
	if err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return nil
	}
	defer activity.Abandon()
	ch := s.pending.Register(serverID, requestID)
	defer s.pending.Remove(serverID, requestID)

	sendCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := activity.Send(sendCtx, msg); err != nil {
		respondError(w, http.StatusBadGateway, errAgentNotConnected)
		return nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case resp := <-ch:
		if p, ok := resp.(proto.Message); ok {
			s.connMgr.CompleteResponse(serverID, conn.Stream, p)
		}
		return resp
	case <-ctx.Done():
		return nil
	case <-conn.Done():
		respondError(w, http.StatusBadGateway, errAgentNotConnected)
		return nil
	case <-timer.C:
		respondError(w, http.StatusGatewayTimeout, "agent timeout")
		return nil
	}
}

func (s *Server) beginAgentActivity(w http.ResponseWriter, node, id string, kind connmgr.ActivityKind) *connmgr.Activity {
	a, err := s.connMgr.BeginActivity(s.connMgr.GetConn(node), id, kind)
	if err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return nil
	}
	return a
}
