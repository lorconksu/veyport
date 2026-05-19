package server

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
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

// sendAgentRequest generates a request ID, registers a pending channel, builds the message
// via buildMsg, sends it to the agent, and waits up to timeout for a response.
// Returns the raw response interface{}, or writes an error and returns nil.
func (s *Server) sendAgentRequest(w http.ResponseWriter, serverID string, buildMsg func(requestID string) *pb.HubMessage, timeout time.Duration) interface{} {
	requestID := uuid.NewString()
	return s.sendAgentRequestWithID(w, serverID, requestID, buildMsg, timeout)
}

func (s *Server) sendAgentRequestWithID(w http.ResponseWriter, serverID, requestID string, buildMsg func(requestID string) *pb.HubMessage, timeout time.Duration) interface{} {
	ch := s.pending.Register(serverID, requestID)
	defer s.pending.Remove(serverID, requestID)

	msg := buildMsg(requestID)
	if err := s.connMgr.SendToAgent(serverID, msg); err != nil {
		respondError(w, http.StatusBadGateway, errAgentNotConnected)
		return nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case resp := <-ch:
		return resp
	case <-timer.C:
		respondError(w, http.StatusGatewayTimeout, "agent timeout")
		return nil
	}
}
