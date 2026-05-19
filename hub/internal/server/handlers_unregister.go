package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// selfUnregisterToken computes the HMAC-SHA256 token for a server's self-unregister endpoint.
func (s *Server) selfUnregisterToken(serverID string) string {
	mac := hmac.New(sha256.New, []byte(s.jwtSecret))
	mac.Write([]byte("self-unregister:" + serverID))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) handleUnregisterServer(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")

	// Try to send unregister command to agent if it's connected
	if s.connMgr != nil {
		conn := s.connMgr.GetConn(serverID)
		if conn != nil {
			requestID := uuid.NewString()
			ch := s.pending.Register(serverID, requestID)
			defer s.pending.Remove(serverID, requestID)

			err := s.connMgr.SendToAgent(serverID, &pb.HubMessage{
				Payload: &pb.HubMessage_UnregisterRequest{
					UnregisterRequest: &pb.UnregisterRequest{
						RequestId: requestID,
					},
				},
			})
			if err == nil {
				// Wait for ack (10s timeout) — don't fail if timeout, still delete from DB
				ackTimer := time.NewTimer(10 * time.Second)
				select {
				case <-ch:
					ackTimer.Stop()
				case <-ackTimer.C:
					// Timeout — proceed with DB deletion anyway
				}
			}
		}
	}

	// Delete server from database (cascades permissions)
	if err := s.store.DeleteServer(serverID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete server")
		return
	}

	// Audit log
	userID := UserIDFromContext(r.Context())
	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &userID,
		Action:    model.AuditServerUnregistered,
		Target:    &serverID,
		IPAddress: &ip,
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "unregistered"})
}

// handleSelfUnregister is a public endpoint (no auth) called by the agent binary
// during a re-install. The server_id in the path acts as proof of installation.
// It only deletes the server from the DB — no agent cleanup (the install script handles that).
func (s *Server) handleSelfUnregister(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")

	// Verify the server actually exists
	_, err := s.store.GetServerByID(serverID)
	if err != nil {
		// Already gone — that's fine
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Validate HMAC-SHA256 unregister token
	token := r.Header.Get("X-Unregister-Token")
	expected := s.selfUnregisterToken(serverID)
	if !hmac.Equal([]byte(token), []byte(expected)) {
		respondError(w, http.StatusForbidden, "unauthorized")
		return
	}

	// Disconnect agent if connected
	if s.connMgr != nil {
		s.connMgr.Unregister(serverID)
	}

	// Delete from database
	if err := s.store.DeleteServer(serverID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete server")
		return
	}

	// Audit log (no user — this is agent-initiated)
	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		Action:    model.AuditServerUnregistered,
		Target:    &serverID,
		IPAddress: &ip,
		ActorType: model.AuditActorTypeDevice,
	})

	w.WriteHeader(http.StatusNoContent)
}
