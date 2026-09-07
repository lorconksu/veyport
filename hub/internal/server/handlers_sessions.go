package server

import (
	"log"
	"net/http"
	"strings"

	"github.com/wyiu/veyport/hub/internal/model"
)

// Session endpoints (feature 009).
//
// Two audiences read the same data through this file: an administrator acting
// on somebody else's account under /api/users/{id}/sessions, and a signed-in
// person managing their own under /api/auth/sessions. Both go through the same
// three operations — list, end one, end the rest — so the two views cannot
// drift apart in what they show or in what ending something means.
//
// The rules the endpoints add on top of session_helpers are about ownership
// and safety rather than storage:
//
//   - a session or shell that is not the account's in the path is answered
//     404, never 403, so the endpoints do not confirm ids that belong to other
//     people;
//   - ending something that was already ended is a 200 that says so, because a
//     retried revocation has achieved what the caller wanted;
//   - a user cannot end the session they are calling from, which would leave
//     their browser holding a dead credential with no sign-out to follow.

const (
	// sessionEndedStatus / sessionAlreadyEndedStatus are the two outcomes of
	// ending one session or shell.
	sessionEndedStatus        = "ended"
	sessionAlreadyEndedStatus = "already_ended"

	// currentSessionEndMessage refuses the one session a user must not end
	// from the list. Signing out is the control that ends it properly, because
	// it also clears the browser's cookies.
	currentSessionEndMessage = "cannot end the current session here — use logout"

	// sessionNotFoundMessage is the answer for any id that is not a live or
	// ended session of the account in the path, whether it exists elsewhere or
	// not at all.
	sessionNotFoundMessage = "session not found"

	// includeEndedParam asks the admin listing for the retention window's
	// history as well as the live rows.
	includeEndedParam = "include_ended"
)

// sessionStatusResponse is the body of the single-session DELETE endpoints.
type sessionStatusResponse struct {
	Status string `json:"status"`
}

// handleListUserSessions serves GET /api/users/{id}/sessions: an
// administrator's view of one account's sessions and open shells (FR-006).
func (s *Server) handleListUserSessions(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionTargetUser(w, r.PathValue("id"))
	if !ok {
		return
	}
	includeEnded := r.URL.Query().Get(includeEndedParam) == "true"
	s.respondSessionList(w, user.ID, SessionIDFromContext(r.Context()), includeEnded)
}

// handleEndUserSession serves DELETE /api/users/{id}/sessions/{sid}: an
// administrator ends one session or one shell (FR-007).
func (s *Server) handleEndUserSession(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionTargetUser(w, r.PathValue("id"))
	if !ok {
		return
	}
	adminID := UserIDFromContext(r.Context())
	s.endOneSession(w, r, &adminID, user, r.PathValue("sid"), model.SessionEndRevokedAdmin)
}

// handleEndUserSessions serves DELETE /api/users/{id}/sessions: an
// administrator signs an account out everywhere (FR-007).
func (s *Server) handleEndUserSessions(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionTargetUser(w, r.PathValue("id"))
	if !ok {
		return
	}
	adminID := UserIDFromContext(r.Context())
	ended, shells := s.endSessions(r, &adminID, user, nil, true, nil, model.SessionEndRevokedAdmin)
	respondJSON(w, http.StatusOK, model.EndedCountResponse{Ended: ended, ShellsClosed: shells})
}

// handleMySessions serves GET /api/auth/sessions: the caller's own live
// sessions, with the one they are calling from marked (FR-012).
//
// Ended rows are an administrator's history, not a user's: the person here
// wants to see where they are still signed in.
func (s *Server) handleMySessions(w http.ResponseWriter, r *http.Request) {
	s.respondSessionList(w, UserIDFromContext(r.Context()), SessionIDFromContext(r.Context()), false)
}

// handleEndMySession serves DELETE /api/auth/sessions/{sid}: a user ends one
// of their own other sessions or shells (FR-012).
func (s *Server) handleEndMySession(w http.ResponseWriter, r *http.Request) {
	callerID := UserIDFromContext(r.Context())
	if sid := r.PathValue("sid"); sid == SessionIDFromContext(r.Context()) && sid != "" {
		respondError(w, http.StatusBadRequest, currentSessionEndMessage)
		return
	}
	user, ok := s.sessionTargetUser(w, callerID)
	if !ok {
		return
	}
	s.endOneSession(w, r, &callerID, user, r.PathValue("sid"), model.SessionEndRevokedSelf)
}

// handleSignOutOthers serves POST /api/auth/sessions/sign-out-others: the
// caller keeps the session they are using and loses every other one, shells
// included (FR-012).
func (s *Server) handleSignOutOthers(w http.ResponseWriter, r *http.Request) {
	callerID := UserIDFromContext(r.Context())
	user, ok := s.sessionTargetUser(w, callerID)
	if !ok {
		return
	}
	currentSID := SessionIDFromContext(r.Context())
	ended, shells := s.endSessions(r, &callerID, user, nil, true, &currentSID, model.SessionEndRevokedSelf)
	respondJSON(w, http.StatusOK, model.EndedCountResponse{Ended: ended, ShellsClosed: shells})
}

// respondSessionList renders one user's session list.
func (s *Server) respondSessionList(w http.ResponseWriter, userID, currentSID string, includeEnded bool) {
	rows, err := s.sessionsFor(userID, currentSID, includeEnded)
	if err != nil {
		log.Printf("warning: failed to list sessions for %s: %v", userID, err)
		respondError(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}
	respondJSON(w, http.StatusOK, model.SessionListResponse{Sessions: rows})
}

// sessionTargetUser resolves the account an endpoint acts on, answering 404
// for one that does not exist.
func (s *Server) sessionTargetUser(w http.ResponseWriter, userID string) (*model.User, bool) {
	if userID == "" {
		respondError(w, http.StatusBadRequest, errMissingUserID)
		return nil, false
	}
	user, err := s.store.GetUserByID(userID)
	switch {
	case userNotFound(err):
		respondError(w, http.StatusNotFound, userNotFoundMessage)
		return nil, false
	case err != nil:
		log.Printf("warning: failed to load user %s: %v", userID, err)
		respondError(w, http.StatusInternalServerError, "failed to load user")
		return nil, false
	}
	return user, true
}

// endOneSession ends a single session or shell of target, whoever asked.
//
// The ownership check comes first and is answered as "not found": an id that
// belongs to another account must not be distinguishable from one that does
// not exist, or the endpoint becomes a way to probe for live sessions.
func (s *Server) endOneSession(
	w http.ResponseWriter, r *http.Request,
	actorID *string, target *model.User, sid, reason string,
) {
	if strings.HasPrefix(sid, shellRowPrefix) {
		s.endOneShell(w, target, sid, reason)
		return
	}

	sess, err := s.store.GetSession(sid)
	switch {
	// A session that does not exist and one that exists but belongs to
	// someone else answer identically: 404, so this endpoint cannot be used
	// to probe for other accounts' session ids.
	case isSessionNotFound(err) || (err == nil && sess.UserID != target.ID):
		respondError(w, http.StatusNotFound, sessionNotFoundMessage)
		return
	case err != nil:
		log.Printf("warning: failed to read session %s: %v", sid, err)
		respondError(w, http.StatusInternalServerError, "failed to read session")
		return
	case sess.EndedAt != nil:
		respondJSON(w, http.StatusOK, sessionStatusResponse{Status: sessionAlreadyEndedStatus})
		return
	}

	// endSessions reports how many rows it actually took from live to ended,
	// so a session that another request ended in between still answers
	// truthfully rather than claiming this call did it.
	ended, _ := s.endSessions(r, actorID, target, []string{sid}, false, nil, reason)
	respondJSON(w, http.StatusOK, sessionStatusResponse{Status: endStatus(ended > 0)})
}

// endOneShell closes one open shell of target, addressed by its synthetic id.
//
// Only the user's live shells can be named: the registry is the whole truth
// about open shells, so a shell that has already closed is gone rather than
// "already ended", and one belonging to someone else was never this account's.
func (s *Server) endOneShell(w http.ResponseWriter, target *model.User, sid, reason string) {
	serverID, terminalID, ok := parseShellRowID(sid)
	if !ok || s.terminalSessions == nil || !s.ownsShell(target.ID, serverID, terminalID) {
		respondError(w, http.StatusNotFound, sessionNotFoundMessage)
		return
	}
	closed := s.terminalSessions.EndOne(serverID, terminalID, shellExitCode, shellCloseMessage(reason))
	respondJSON(w, http.StatusOK, sessionStatusResponse{Status: endStatus(closed)})
}

// ownsShell reports whether a live shell of the user is the one named.
func (s *Server) ownsShell(userID, serverID, terminalID string) bool {
	for _, info := range s.terminalSessions.ListByUser(userID) {
		if info.ServerID == serverID && info.SessionID == terminalID {
			return true
		}
	}
	return false
}

// endStatus renders the outcome of ending one thing.
func endStatus(wasLive bool) string {
	if wasLive {
		return sessionEndedStatus
	}
	return sessionAlreadyEndedStatus
}

// parseShellRowID splits a shell row id back into the server and terminal
// session it names. It is the inverse of shellRowID; ids that are not shaped
// like one (an empty half, a missing separator) are rejected rather than
// guessed at.
func parseShellRowID(id string) (serverID, terminalID string, ok bool) {
	rest, found := strings.CutPrefix(id, shellRowPrefix)
	if !found {
		return "", "", false
	}
	serverID, terminalID, found = strings.Cut(rest, ":")
	if !found || serverID == "" || terminalID == "" {
		return "", "", false
	}
	return serverID, terminalID, true
}
