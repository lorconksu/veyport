package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	maxViewerLogStreamsPerUser = 5
	maxAdminLogStreamsPerUser  = 10
	maxAgentLogStreams         = 50
)

func (s *Server) handleTailLog(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	path := r.URL.Query().Get("path")
	grep := r.URL.Query().Get("grep")
	if len(grep) > 256 {
		respondError(w, http.StatusBadRequest, "grep filter too long (max 256 characters)")
		return
	}

	if path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	if !s.checkFileAccess(w, r, serverID, path) {
		return
	}

	// Check agent connected
	if _, ok := s.requireAgent(w, r); !ok {
		return
	}

	// Check Flusher support
	flusher, ok := w.(http.Flusher)
	if !ok {
		respondError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// Extend write deadline for long-lived SSE connection
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{}) // No deadline

	userID := UserIDFromContext(r.Context())
	role := UserRoleFromContext(r.Context())
	if !s.tryAcquireLogTailSlot(serverID, userID, role) {
		respondError(w, http.StatusTooManyRequests, "too many active log streams")
		return
	}

	// Register log session
	requestID := uuid.NewString()
	ch := s.logSessions.Register(serverID, requestID)

	// Send LogStreamRequest to agent
	err := s.connMgr.SendToAgent(serverID, &pb.HubMessage{
		Payload: &pb.HubMessage_LogStreamRequest{
			LogStreamRequest: &pb.LogStreamRequest{
				RequestId: requestID,
				Path:      path,
				Grep:      grep,
			},
		},
	})
	if err != nil {
		s.releaseLogTailSlot(serverID, userID)
		s.logSessions.Remove(serverID, requestID)
		respondError(w, http.StatusBadGateway, "failed to send request to agent")
		return
	}

	// Audit log
	ip := clientIP(r)
	detail := path
	if grep != "" {
		detail += " grep=" + grep
	}
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &userID,
		Action:    model.AuditLogTailStarted,
		Target:    &serverID,
		Detail:    &detail,
		IPAddress: &ip,
	})

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Cleanup on exit
	defer func() {
		s.releaseLogTailSlot(serverID, userID)
		s.logSessions.Remove(serverID, requestID)
		// Send stop to agent
		_ = s.connMgr.SendToAgent(serverID, &pb.HubMessage{
			Payload: &pb.HubMessage_LogStreamStop{
				LogStreamStop: &pb.LogStreamStop{
					RequestId: requestID,
				},
			},
		})
	}()

	// Stream loop
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-ch:
			if !ok {
				return // Channel closed
			}
			encoded := base64.StdEncoding.EncodeToString(data)
			fmt.Fprintf(w, "data: %s\n\n", encoded)
			// Check for overflow after each chunk delivery
			if dropped := s.logSessions.DrainOverflow(serverID, requestID); dropped > 0 {
				fmt.Fprintf(w, "event: overflow\ndata: {\"dropped\":%d}\n\n", dropped)
			}
			flusher.Flush()
		}
	}
}

func (s *Server) tryAcquireLogTailSlot(serverID, userID, role string) bool {
	limit := maxViewerLogStreamsPerUser
	if role == "admin" {
		limit = maxAdminLogStreamsPerUser
	}

	key := serverID + ":" + userID
	s.logTailMu.Lock()
	defer s.logTailMu.Unlock()

	totalForServer := 0
	prefix := serverID + ":"
	for existingKey, count := range s.logTailSessions {
		if existingKey == key || strings.HasPrefix(existingKey, prefix) {
			totalForServer += count
		}
	}
	if role == "admin" {
		if totalForServer >= maxAgentLogStreams {
			return false
		}
	} else if totalForServer >= maxAgentLogStreams-maxAdminLogStreamsPerUser {
		return false
	}
	if s.logTailSessions[key] >= limit {
		return false
	}
	s.logTailSessions[key]++
	return true
}

func (s *Server) releaseLogTailSlot(serverID, userID string) {
	key := serverID + ":" + userID
	s.logTailMu.Lock()
	defer s.logTailMu.Unlock()

	if s.logTailSessions[key] <= 1 {
		delete(s.logTailSessions, key)
		return
	}
	s.logTailSessions[key]--
}
