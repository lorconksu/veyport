package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	maxTerminalInputBytes         = 8192
	terminalStreamAttachDelay     = 30 * time.Second
	errTerminalServiceUnavailable = "terminal service unavailable"
	errTerminalSessionNotFound    = "terminal session not found"
	terminalSessionIDDetailPrefix = "session_id="
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

	// Capture signed authority before the request body can block. A later user
	// read may revoke this authority, but can never select a replacement epoch.
	claims, err := auth.ValidateToken(s.jwtSecret, readAccessToken(r))
	userID, sid := UserIDFromContext(r.Context()), SessionIDFromContext(r.Context())
	if err != nil || claims.TokenType != auth.TokenTypeAccess || claims.Subject != userID || sid == "" || claims.SessionID != sid || claims.ExpiresAt == nil {
		respondError(w, http.StatusForbidden, "terminal authorization changed")
		return
	}
	generation, expires := claims.TokenGeneration, claims.ExpiresAt.Time

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

	executionUser, ok := s.resolveTerminalExecutionUser(w, r, serverID)
	if !ok {
		return
	}
	sessionID := uuid.NewString()
	// Established shells are authorized by the durable credential generation,
	// owning server-side session and current terminal policy. The access token
	// that opened the shell is intentionally not a durable authority: browser
	// refresh replaces it every 15 minutes without replacing the session.
	validateLive := func() (string, error) {
		live, err := s.store.GetUserByID(userID)
		if err != nil || live.TokenGeneration != generation {
			return "", ErrTerminalNotAuthorized
		}
		if !s.store.TerminalSessionLive(context.Background(), sid, userID, s.now()) {
			return "", ErrTerminalNotAuthorized
		}

		if err := s.securityService().GuardInteractive(userID, serverID); err != nil {
			return "", err
		}
		runAs, err := AuthorizeTerminalExecution(s.store, userID, serverID)
		if err != nil {
			return "", ErrTerminalNotAuthorized
		}
		return runAs, nil
	}
	validateAdmission := func() (string, error) {
		if !s.now().Before(expires) {
			return "", ErrTerminalNotAuthorized
		}
		runAs, err := validateLive()
		if err != nil || !s.now().Before(expires) {
			return "", ErrTerminalNotAuthorized
		}
		return runAs, nil
	}
	// The shell is tied to the session that opened it, so revoking that
	// session closes the terminal with it (feature 009, FR-010).
	_, executionUser, err = s.terminalSessions.RegisterInteractive(s.store, s.connMgr, serverID, sessionID, userID, validateAdmission,
		grpcserver.WithKind(grpcserver.TerminalKindWeb),
		grpcserver.WithSessionID(sid),
		grpcserver.WithCredentialGeneration(generation, false),
		grpcserver.WithInteractiveLiveValidation(validateLive))
	if err != nil {
		status := http.StatusForbidden
		if errors.Is(err, grpcserver.ErrInteractiveRegistration) {
			status = http.StatusConflict
		}
		if errors.Is(err, grpcserver.ErrInteractiveAgentNotConnected) {
			status = http.StatusBadGateway
		}
		respondError(w, status, err.Error())
		return
	}
	resp := s.openInteractiveTerminal(w, r, serverID, sessionID, &pb.TerminalOpenRequest{SessionId: sessionID, Cols: req.Cols, Rows: req.Rows, Cwd: req.Cwd, RunAsUser: executionUser})
	if resp == nil {
		s.terminalSessions.CloseInteractive(serverID, sessionID)
		s.terminalSessions.Remove(serverID, sessionID)
		return
	}

	ack, ok := resp.(*pb.TerminalOpenAck)
	if !ok {
		s.terminalSessions.CloseInteractive(serverID, sessionID)
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
	info, exists := s.terminalSessions.Get(serverID, sessionID)
	if !exists || info.Closed {
		s.terminalSessions.CloseInteractive(serverID, sessionID)
		s.terminalSessions.Remove(serverID, sessionID)
		respondError(w, http.StatusForbidden, "terminal authorization changed")
		return
	}
	ip := clientIP(r)
	correlationID := RequestIDFromContext(r.Context())
	s.expireUnattachedTerminalSession(serverID, sessionID, userID, ip, correlationID)

	detail := terminalSessionIDDetailPrefix + sessionID
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
	_ = rc.SetWriteDeadline(time.Now().Add(time.Second))

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// A forced exit means the hub closed the shell under the person using it;
	// the agent still has it running, so the teardown has to say so.
	info.SetOutputAbort(func() { _ = rc.SetWriteDeadline(time.Now()) })
	defer info.SetOutputAbort(nil)
	forced := false
	defer func() {
		if _, revoked := info.ForcedExit(); revoked {
			forced = true
		}
		s.closeTerminalSession(r, serverID, sessionID, forced)
	}()

	writeExit := func(event grpcserver.TerminalEvent) {
		_ = rc.SetWriteDeadline(time.Now().Add(time.Second))
		forced = forced || event.Forced
		payload, _ := json.Marshal(map[string]interface{}{"exit_code": event.ExitCode, "error": event.Error})
		fmt.Fprintf(w, "event: exit\ndata: %s\n\n", payload)
		flusher.Flush()
	}
	for {
		if exit, revoked := info.ForcedExit(); revoked {
			writeExit(exit)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-info.Ch:
			if exit, revoked := info.ForcedExit(); revoked {
				writeExit(exit)
				return
			}
			if !ok {
				return
			}
			switch event.Type {
			case grpcserver.TerminalEventData:
				// Set the bound before entering the gate so this cannot
				// overwrite an abort installed concurrently by revocation.
				_ = rc.SetWriteDeadline(time.Now().Add(time.Second))
				_, err := info.ForwardData(func() error {
					_, err := fmt.Fprintf(w, "data: %s\n\n", base64.StdEncoding.EncodeToString(event.Data))
					if err == nil {
						flusher.Flush()
					}
					return err
				})
				if err != nil {
					return
				}
			case grpcserver.TerminalEventExit:
				writeExit(event)
				return
			}
		}
	}

}

func (s *Server) expireUnattachedTerminalSession(serverID, sessionID, userID, ip, correlationID string) {
	time.AfterFunc(terminalStreamAttachDelay, func() {
		if s.terminalSessions == nil {
			return
		}
		close, removed := s.terminalSessions.RemoveUnattachedWithClose(serverID, sessionID)
		if !removed {
			return
		}
		if close != nil {
			close()
		}
		uid, srvID, addr := userID, serverID, ip
		detail := terminalSessionIDDetailPrefix + sessionID + " expired_unattached"
		entry := model.AuditEntry{
			ID:     uuid.NewString(),
			Action: model.AuditTerminalClosed,
			Target: &srvID,
			Detail: &detail,
		}
		if uid != "" {
			entry.UserID = &uid
		}
		if addr != "" {
			entry.IPAddress = &addr
		}
		if correlationID != "" {
			entry.CorrelationID = &correlationID
		}
		_ = s.store.LogAudit(entry)
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

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	err := s.terminalSessions.SendInteractive(ctx, serverID, sessionID, &pb.HubMessage{
		Payload: &pb.HubMessage_TerminalInput{
			TerminalInput: &pb.TerminalInput{
				SessionId: sessionID,
				Data:      []byte(req.Data),
			},
		},
	})
	if err != nil {
		respondTerminalSendError(w, err, "failed to send terminal input")
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

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	err := s.terminalSessions.SendInteractive(ctx, serverID, sessionID, &pb.HubMessage{
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
	s.closeTerminalSession(r, serverID, sessionID, false)
	w.WriteHeader(http.StatusNoContent)
}

// Terminal authorization outcomes returned by AuthorizeTerminalExecution. They are
// transport-agnostic: the HTTP handler maps them to status codes, and the SSH
// gateway maps them to connection refusals and audit reasons.
var (
	// ErrTerminalNotAuthorized means the principal may not open a terminal at
	// all: unknown/deleted user, or a non-admin without LDAP terminal access.
	ErrTerminalNotAuthorized = errors.New("terminal access required")
	// ErrTerminalNoAssignment means the principal has terminal access but no
	// root ("/") assignment on the requested server.
	ErrTerminalNoAssignment = errors.New("root server assignment required for terminal access")
	// ErrTerminalNoExecUser means the principal is authorized but no execution
	// username could be resolved from their LDAP identity.
	ErrTerminalNoExecUser = errors.New("LDAP execution user not available")
	// ErrTerminalLookupFailed means the server-assignment lookup itself failed;
	// the decision is unknown rather than denied.
	ErrTerminalLookupFailed = errors.New("failed to check server assignment")
)

// AuthorizeTerminalExecution is the single authorization decision for opening a
// terminal on a server, shared by the web terminal and the SSH gateway. It is
// evaluated against live store state on every attempt — nothing is cached — so a
// deleted user or a revoked assignment is denied immediately.
//
// On success it returns the username the agent should run the shell as. Note that
// a local (non-LDAP) admin authorizes with an EMPTY execution user, which the
// agent interprets as its default RunAsUser.
func AuthorizeTerminalExecution(st *store.Store, userID, serverID string) (string, error) {
	user, err := st.GetUserByID(userID)
	if err != nil || user.MustChangePassword {
		return "", ErrTerminalNotAuthorized
	}
	policy, err := st.AccountPolicy()
	if err != nil {
		return "", ErrTerminalNotAuthorized
	}
	status := account.Evaluate(account.InputFromUser(user), time.Now().UTC(), policy)
	if _, refuse := account.Refusal(status); refuse {
		return "", ErrTerminalNotAuthorized
	}

	effective, err := authorization.New(st).Effective(user.ID)
	if err != nil {
		return "", ErrTerminalNotAuthorized
	}
	if effective.HasRole(model.RoleAdmin) {
		return ldapExecutionUsername(user), nil
	}

	if user.AuthProvider != model.AuthProviderLDAP || !user.TerminalAccess {
		return "", ErrTerminalNotAuthorized
	}

	paths, err := st.GetUserPathsForServer(user.ID, serverID)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTerminalLookupFailed, err)
	}
	if !hasTerminalServerAssignment(paths) {
		return "", ErrTerminalNoAssignment
	}

	executionUser := ldapExecutionUsername(user)
	if executionUser == "" {
		return "", ErrTerminalNoExecUser
	}
	return executionUser, nil
}

// resolveTerminalExecutionUser is the HTTP transport wrapper around
// AuthorizeTerminalExecution: it maps each authorization outcome to the status
// code and message the web terminal expects.
func (s *Server) resolveTerminalExecutionUser(w http.ResponseWriter, r *http.Request, serverID string) (string, bool) {
	if err := authorization.New(s.store).GuardInteractive(UserIDFromContext(r.Context()), serverID); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return "", false
	}
	executionUser, err := AuthorizeTerminalExecution(s.store, UserIDFromContext(r.Context()), serverID)
	if err != nil {
		respondError(w, terminalAuthzStatus(err), terminalAuthzMessage(err))
		return "", false
	}
	return executionUser, true
}

func terminalAuthzStatus(err error) int {
	if errors.Is(err, ErrTerminalLookupFailed) {
		return http.StatusInternalServerError
	}
	return http.StatusForbidden
}

func terminalAuthzMessage(err error) string {
	switch {
	case errors.Is(err, ErrTerminalNoAssignment):
		return ErrTerminalNoAssignment.Error()
	case errors.Is(err, ErrTerminalNoExecUser):
		return ErrTerminalNoExecUser.Error()
	case errors.Is(err, ErrTerminalLookupFailed):
		return ErrTerminalLookupFailed.Error()
	default:
		return ErrTerminalNotAuthorized.Error()
	}
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
	if r.Method != "DELETE" {
		if err := s.securityService().GuardInteractive(UserIDFromContext(r.Context()), serverID); err != nil {
			respondError(w, http.StatusForbidden, err.Error())
			return grpcserver.TerminalSessionInfo{}, false
		}
	}
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

// closeTerminalSession tears a terminal down on both sides and audits it.
//
// forced marks a shell the hub closed (a revoked session, a disabled account,
// an administrator ending it): the registry entry is closed before the stream
// notices, so "already closed" no longer implies the agent knows — its shell
// is still running and must be told to stop.
func (s *Server) closeTerminalSession(r *http.Request, serverID, sessionID string, forced bool) {
	if s.terminalSessions == nil {
		return
	}
	info, exists := s.terminalSessions.Get(serverID, sessionID)
	if exists && (!info.Closed || forced) {
		s.terminalSessions.CloseInteractive(serverID, sessionID)
	}
	alreadyClosed, removed := s.terminalSessions.RemoveIfHubInitiated(serverID, sessionID)
	alreadyClosed = alreadyClosed && info.Closed
	if !removed {
		return
	}
	// Production terminals always retain their exact admitted connection and
	// close through CloseInteractive. Never redirect a stale shell close to a
	// replacement generation; legacy unbound registrations are local-only.
	userID := UserIDFromContext(r.Context())
	ip := clientIP(r)
	detail := terminalSessionIDDetailPrefix + sessionID
	if alreadyClosed && !forced {
		detail += " agent_initiated"
	}
	if forced {
		detail += " reason=forced"
	}
	s.auditLogRequest(r, model.AuditEntry{
		UserID:    &userID,
		Action:    model.AuditTerminalClosed,
		Target:    &serverID,
		Detail:    &detail,
		IPAddress: &ip,
	})
}

// openInteractiveTerminal waits without holding policy or registry locks. A
// policy change can cancel the registration while its agent ACK is pending.
func (s *Server) openInteractiveTerminal(w http.ResponseWriter, r *http.Request, serverID, sessionID string, open *pb.TerminalOpenRequest) interface{} {
	ch := s.pending.Register(serverID, sessionID)
	defer s.pending.Remove(serverID, sessionID)
	info, exists := s.terminalSessions.Get(serverID, sessionID)
	if !exists || info.Closed {
		respondError(w, http.StatusForbidden, "terminal authorization changed")
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	err := s.terminalSessions.SendInteractive(ctx, serverID, sessionID, &pb.HubMessage{Payload: &pb.HubMessage_TerminalOpenRequest{TerminalOpenRequest: open}})
	if err != nil {
		respondError(w, http.StatusBadGateway, errAgentNotConnected)
		return nil
	}
	select {
	case resp := <-ch:
		return resp
	case <-info.AgentDone:
		respondError(w, http.StatusBadGateway, errAgentNotConnected)
	case <-info.Done:
		respondError(w, http.StatusForbidden, "terminal authorization changed")
	case <-ctx.Done():
		respondError(w, http.StatusGatewayTimeout, "agent timeout")
	}
	return nil
}

func respondTerminalSendError(w http.ResponseWriter, err error, fallback string) {
	if errors.Is(err, grpcserver.ErrInteractiveSessionClosed) || errors.Is(err, authorization.ErrInteractive) || errors.Is(err, authorization.ErrTransition) || errors.Is(err, authorization.ErrRecovery) || errors.Is(err, ErrTerminalNotAuthorized) || errors.Is(err, ErrTerminalNoAssignment) || errors.Is(err, ErrTerminalNoExecUser) {
		respondError(w, http.StatusForbidden, "terminal authorization changed")
		return
	}
	respondError(w, http.StatusBadGateway, fallback)
}
