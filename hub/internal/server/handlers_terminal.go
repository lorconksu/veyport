package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/grpcserver"
	"github.com/wyiu/aerodocs/hub/internal/model"
	pb "github.com/wyiu/aerodocs/proto/aerodocs/v1"
)

const (
	maxTerminalInputBytes         = 8192
	terminalStreamAttachDelay     = 30 * time.Second
	errTerminalServiceUnavailable = "terminal service unavailable"
	errTerminalSessionNotFound    = "terminal session not found"
)

type createTerminalSessionRequest struct {
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
	Cwd  string `json:"cwd"`
}

type terminalInputRequest struct {
	Data string `json:"data"`
}

type terminalResizeRequest struct {
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
}

func (s *Server) handleCreateTerminalSession(w http.ResponseWriter, r *http.Request) {
	serverID, ok := s.requireAgent(w, r)
	if !ok {
		return
	}
	if s.terminalSessions == nil {
		respondError(w, http.StatusInternalServerError, errTerminalServiceUnavailable)
		return
	}

	var req createTerminalSessionRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if req.Cwd != "" {
		if err := validateRequestPath(req.Cwd); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	userID := UserIDFromContext(r.Context())
	executionUser, ok := s.resolveTerminalExecutionUser(w, r, serverID)
	if !ok {
		return
	}
	sessionID := uuid.NewString()
	if _, created := s.terminalSessions.Register(serverID, sessionID, userID, executionUser); !created {
		respondError(w, http.StatusConflict, "terminal session already exists")
		return
	}

	resp := s.sendAgentRequestWithID(w, serverID, sessionID, func(requestID string) *pb.HubMessage {
		return &pb.HubMessage{
			Payload: &pb.HubMessage_TerminalOpenRequest{
				TerminalOpenRequest: &pb.TerminalOpenRequest{
					SessionId: requestID,
					Cols:      req.Cols,
					Rows:      req.Rows,
					Cwd:       req.Cwd,
					RunAsUser: executionUser,
				},
			},
		}
	}, 5*time.Second)
	if resp == nil {
		s.terminalSessions.Remove(serverID, sessionID)
		return
	}

	ack, ok := resp.(*pb.TerminalOpenAck)
	if !ok {
		s.terminalSessions.Remove(serverID, sessionID)
		respondError(w, http.StatusBadGateway, "unexpected terminal response")
		return
	}
	if !ack.Success {
		s.terminalSessions.Remove(serverID, sessionID)
		status := http.StatusBadGateway
		if strings.Contains(ack.Error, "cwd") {
			status = http.StatusBadRequest
		}
		respondError(w, status, ack.Error)
		return
	}
	s.expireUnattachedTerminalSession(serverID, sessionID)

	ip := clientIP(r)
	detail := "session_id=" + sessionID
	if req.Cwd != "" {
		detail += fmt.Sprintf(" cwd=%q", req.Cwd)
	}
	if executionUser != "" {
		detail += " execution_user=" + executionUser
	}
	s.auditLogRequest(r, model.AuditEntry{
		UserID:    &userID,
		Action:    model.AuditTerminalOpened,
		Target:    &serverID,
		Detail:    &detail,
		IPAddress: &ip,
	})

	respondJSON(w, http.StatusCreated, model.TerminalSessionResponse{
		SessionID: sessionID,
	})
}

func (s *Server) handleTerminalStream(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	sessionID := r.PathValue("sessionId")
	if s.terminalSessions == nil {
		respondError(w, http.StatusInternalServerError, errTerminalServiceUnavailable)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		respondError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	info, exists, attached := s.terminalSessions.AttachStream(serverID, sessionID, UserIDFromContext(r.Context()))
	if !exists {
		respondError(w, http.StatusNotFound, errTerminalSessionNotFound)
		return
	}
	if !attached {
		respondError(w, http.StatusConflict, "terminal session stream already attached")
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	defer s.closeTerminalSession(r, serverID, sessionID)

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-info.Ch:
			if !ok {
				return
			}
			switch event.Type {
			case grpcserver.TerminalEventData:
				fmt.Fprintf(w, "data: %s\n\n", base64.StdEncoding.EncodeToString(event.Data))
			case grpcserver.TerminalEventExit:
				payload, _ := json.Marshal(map[string]interface{}{
					"exit_code": event.ExitCode,
					"error":     event.Error,
				})
				fmt.Fprintf(w, "event: exit\ndata: %s\n\n", payload)
			}
			flusher.Flush()
		}
	}
}

func (s *Server) expireUnattachedTerminalSession(serverID, sessionID string) {
	time.AfterFunc(terminalStreamAttachDelay, func() {
		if s.terminalSessions == nil || !s.terminalSessions.RemoveUnattached(serverID, sessionID) {
			return
		}
		if s.connMgr != nil {
			_ = s.connMgr.SendToAgent(serverID, &pb.HubMessage{
				Payload: &pb.HubMessage_TerminalClose{
					TerminalClose: &pb.TerminalClose{
						SessionId: sessionID,
					},
				},
			})
		}
	})
}

func (s *Server) handleTerminalInput(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	sessionID := r.PathValue("sessionId")
	if _, ok := s.requireAgent(w, r); !ok {
		return
	}
	info, ok := s.requireTerminalSession(w, r, serverID, sessionID)
	if !ok {
		return
	}
	if info.Closed {
		respondError(w, http.StatusConflict, "terminal session is closed")
		return
	}

	var req terminalInputRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if len(req.Data) > maxTerminalInputBytes {
		respondError(w, http.StatusBadRequest, "terminal input too large")
		return
	}

	err := s.connMgr.SendToAgent(serverID, &pb.HubMessage{
		Payload: &pb.HubMessage_TerminalInput{
			TerminalInput: &pb.TerminalInput{
				SessionId: sessionID,
				Data:      []byte(req.Data),
			},
		},
	})
	if err != nil {
		respondError(w, http.StatusBadGateway, "failed to send terminal input")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleTerminalResize(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	sessionID := r.PathValue("sessionId")
	if _, ok := s.requireAgent(w, r); !ok {
		return
	}
	info, ok := s.requireTerminalSession(w, r, serverID, sessionID)
	if !ok {
		return
	}
	if info.Closed {
		respondError(w, http.StatusConflict, "terminal session is closed")
		return
	}

	var req terminalResizeRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	err := s.connMgr.SendToAgent(serverID, &pb.HubMessage{
		Payload: &pb.HubMessage_TerminalResize{
			TerminalResize: &pb.TerminalResize{
				SessionId: sessionID,
				Cols:      req.Cols,
				Rows:      req.Rows,
			},
		},
	})
	if err != nil {
		respondError(w, http.StatusBadGateway, "failed to resize terminal")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleCloseTerminalSession(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	sessionID := r.PathValue("sessionId")
	if _, ok := s.requireTerminalSession(w, r, serverID, sessionID); !ok {
		return
	}
	s.closeTerminalSession(r, serverID, sessionID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resolveTerminalExecutionUser(w http.ResponseWriter, r *http.Request, serverID string) (string, bool) {
	user, err := s.store.GetUserByID(UserIDFromContext(r.Context()))
	if err != nil {
		respondError(w, http.StatusForbidden, "terminal access required")
		return "", false
	}

	if user.Role == model.RoleAdmin {
		return ldapExecutionUsername(user), true
	}

	if user.AuthProvider != model.AuthProviderLDAP || !user.TerminalAccess {
		respondError(w, http.StatusForbidden, "terminal access required")
		return "", false
	}

	paths, err := s.store.GetUserPathsForServer(user.ID, serverID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to check server assignment")
		return "", false
	}
	if !hasTerminalServerAssignment(paths) {
		respondError(w, http.StatusForbidden, "root server assignment required for terminal access")
		return "", false
	}

	executionUser := ldapExecutionUsername(user)
	if executionUser == "" {
		respondError(w, http.StatusForbidden, "LDAP execution user not available")
		return "", false
	}
	return executionUser, true
}

func hasTerminalServerAssignment(paths []string) bool {
	for _, path := range paths {
		if path == "/" {
			return true
		}
	}
	return false
}

func ldapExecutionUsername(user *model.User) string {
	if user.AuthProvider != model.AuthProviderLDAP {
		return ""
	}
	if user.LDAPUsername != "" {
		return user.LDAPUsername
	}
	return user.Username
}

func (s *Server) requireTerminalSession(w http.ResponseWriter, r *http.Request, serverID, sessionID string) (grpcserver.TerminalSessionInfo, bool) {
	if s.terminalSessions == nil {
		respondError(w, http.StatusInternalServerError, errTerminalServiceUnavailable)
		return grpcserver.TerminalSessionInfo{}, false
	}
	info, ok := s.terminalSessions.Get(serverID, sessionID)
	if !ok {
		respondError(w, http.StatusNotFound, errTerminalSessionNotFound)
		return grpcserver.TerminalSessionInfo{}, false
	}
	if info.UserID != UserIDFromContext(r.Context()) {
		respondError(w, http.StatusNotFound, errTerminalSessionNotFound)
		return grpcserver.TerminalSessionInfo{}, false
	}
	return info, true
}

func (s *Server) closeTerminalSession(r *http.Request, serverID, sessionID string) {
	if s.terminalSessions == nil {
		return
	}
	if !s.terminalSessions.Remove(serverID, sessionID) {
		return
	}
	if s.connMgr != nil {
		_ = s.connMgr.SendToAgent(serverID, &pb.HubMessage{
			Payload: &pb.HubMessage_TerminalClose{
				TerminalClose: &pb.TerminalClose{
					SessionId: sessionID,
				},
			},
		})
	}

	userID := UserIDFromContext(r.Context())
	ip := clientIP(r)
	detail := "session_id=" + sessionID
	s.auditLogRequest(r, model.AuditEntry{
		UserID:    &userID,
		Action:    model.AuditTerminalClosed,
		Target:    &serverID,
		Detail:    &detail,
		IPAddress: &ip,
	})
}
