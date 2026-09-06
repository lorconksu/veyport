package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
)

// T013/T016 — the session endpoints as an administrator and as the signed-in
// user drive them.
//
// Every case goes through the real route table, so the guards (admin-only for
// the /api/users routes, an interactive login for the /api/auth ones), the
// path patterns and the JSON bodies are under test alongside the handlers.
// What each case asserts on is the visible result: the response body, the
// persisted row, the audit trail, and whether the credential that belonged to
// the ended session still works.

const (
	sessionsSuffix       = "/sessions"
	authSessionsPath     = "/api/auth/sessions"
	signOutOthersPath    = "/api/auth/sessions/sign-out-others"
	statusEnded          = "ended"
	statusAlreadyEnded   = "already_ended"
	wantStatusFmt        = "status = %q, want %q"
	wantCodeFmt          = "%s: expected %d, got %d: %s"
	unknownSessionID     = "11111111-1111-1111-1111-111111111111"
	unknownShellID       = shellRowPrefix + "srv-nope:term-nope"
	sessionsTestServerID = "srv-1"
	sessionsTestSrvName  = "web-01"
)

// sessionsFixture is a hub with a signed-in administrator, a viewer to act on,
// a controllable clock and a live terminal registry.
type sessionsFixture struct {
	s          *Server
	clk        *testClock
	adminID    string
	adminToken string
	adminSID   string
	viewer     *model.User
}

func newSessionsFixture(t *testing.T) *sessionsFixture {
	t.Helper()
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 12)

	adminToken := registerAndGetAdminToken(t, s)
	admin, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}

	return &sessionsFixture{
		s:          s,
		clk:        clk,
		adminID:    admin.ID,
		adminToken: adminToken,
		adminSID:   sidOf(t, s, adminToken),
		viewer:     newLocalUser(t, s, "sessionviewer", lockoutTestPassword),
	}
}

// do issues an authenticated request through the router.
func (f *sessionsFixture) do(t *testing.T, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	f.s.routes().ServeHTTP(rec, req)
	return rec
}

// userSessionsPath is the admin listing/ending route for a user.
func userSessionsPath(userID string) string {
	return testUsersPrefix + userID + sessionsSuffix
}

// sessionRowWithAgent records a session for a user as a given client would.
func sessionRowWithAgent(t *testing.T, s *Server, userID, userAgent string) *model.Session {
	t.Helper()
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		t.Fatalf("get user %s: %v", userID, err)
	}
	sess, err := s.newSession(sessionRequest(userAgent), user)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess
}

// decodeSessionList reads a session-listing response.
func decodeSessionList(t *testing.T, rec *httptest.ResponseRecorder) []model.Session {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf(wantCodeFmt, "list sessions", http.StatusOK, rec.Code, rec.Body.String())
	}
	var resp model.SessionListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode session list: %v", err)
	}
	return resp.Sessions
}

// decodeStatus reads a {"status":…} response.
func decodeStatus(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf(wantCodeFmt, "end session", http.StatusOK, rec.Code, rec.Body.String())
	}
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return resp.Status
}

// decodeEndedCount reads an {"ended":…,"shells_closed":…} response.
func decodeEndedCount(t *testing.T, rec *httptest.ResponseRecorder) model.EndedCountResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf(wantCodeFmt, "end sessions", http.StatusOK, rec.Code, rec.Body.String())
	}
	var resp model.EndedCountResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode ended counts: %v", err)
	}
	return resp
}

// sessionByIDIn finds a row in a listing.
func sessionByIDIn(rows []model.Session, id string) *model.Session {
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i]
		}
	}
	return nil
}

// registerShell puts a live shell in the registry for a user.
func registerShell(t *testing.T, s *Server, serverID, termID, userID, kind, sid string) chan grpcserver.TerminalEvent {
	t.Helper()
	opts := []grpcserver.RegisterOption{grpcserver.WithKind(kind)}
	if sid != "" {
		opts = append(opts, grpcserver.WithSessionID(sid))
	}
	ch, ok := s.terminalSessions.Register(serverID, termID, userID, "root", opts...)
	if !ok {
		t.Fatalf("register shell %s:%s", serverID, termID)
	}
	return ch
}

// expectShellClosed asserts a shell received its forced exit event.
func expectShellClosed(t *testing.T, ch chan grpcserver.TerminalEvent, wantMsg string) {
	t.Helper()
	select {
	case evt := <-ch:
		if evt.Type != grpcserver.TerminalEventExit {
			t.Fatalf("event type = %v, want exit", evt.Type)
		}
		if evt.Error != wantMsg {
			t.Fatalf("shell message = %q, want %q", evt.Error, wantMsg)
		}
		if evt.ExitCode != shellExitCode {
			t.Fatalf("exit code = %d, want %d", evt.ExitCode, shellExitCode)
		}
	default:
		t.Fatal("expected the shell to be closed with an exit event")
	}
}

// --- admin listing ----------------------------------------------------------

// The listing shows a user's web and CLI sessions with the metadata the panel
// renders, and their open shells alongside them.
func TestSessionsAPI_AdminListsSessionsAndShells(t *testing.T) {
	f := newSessionsFixture(t)
	if err := f.s.store.CreateServer(&model.Server{
		ID: sessionsTestServerID, Name: sessionsTestSrvName, Status: "offline",
	}); err != nil {
		t.Fatalf("create server: %v", err)
	}

	web := sessionRowWithAgent(t, f.s, f.viewer.ID, sessionTestUserAgent)
	cli := sessionRowWithAgent(t, f.s, f.viewer.ID, sessionTestCLIAgent)
	registerShell(t, f.s, sessionsTestServerID, "term-1", f.viewer.ID, grpcserver.TerminalKindSSH, "")

	rows := decodeSessionList(t, f.do(t, "GET", userSessionsPath(f.viewer.ID), f.adminToken))
	if len(rows) != 3 {
		t.Fatalf("expected two sessions and one shell, got %d rows: %+v", len(rows), rows)
	}

	webRow := sessionByIDIn(rows, web.ID)
	if webRow == nil || webRow.Kind != model.SessionKindWeb {
		t.Fatalf("missing or mis-kinded web row in %+v", rows)
	}
	if webRow.IP == "" || webRow.UserAgent == "" || webRow.LastSeenAt.IsZero() {
		t.Fatalf("web row is missing metadata: %+v", webRow)
	}
	if webRow.IdleDeadlineAt == nil {
		t.Fatal("a live row must carry the derived idle deadline")
	}
	if webRow.Current {
		t.Fatal("another user's session must never be marked as the caller's own")
	}
	if cliRow := sessionByIDIn(rows, cli.ID); cliRow == nil || cliRow.Kind != model.SessionKindCLI {
		t.Fatalf("missing or mis-kinded cli row in %+v", rows)
	}

	shellRow := sessionByIDIn(rows, shellRowID(sessionsTestServerID, "term-1"))
	if shellRow == nil {
		t.Fatalf("missing shell row in %+v", rows)
	}
	if shellRow.Kind != model.SessionKindSSH || shellRow.Server != sessionsTestSrvName {
		t.Fatalf("shell row kind/server = %q/%q, want ssh/%s",
			shellRow.Kind, shellRow.Server, sessionsTestSrvName)
	}
	if shellRow.StartedAt == nil || shellRow.LastActivityAt == nil {
		t.Fatal("a shell row must carry its start and last-activity times")
	}
}

// Ended sessions are hidden by default and shown on request, which is what
// makes the listing a history rather than only a snapshot.
func TestSessionsAPI_AdminListIncludeEnded(t *testing.T) {
	f := newSessionsFixture(t)
	live := sessionRowWithAgent(t, f.s, f.viewer.ID, sessionTestUserAgent)
	gone := sessionRowWithAgent(t, f.s, f.viewer.ID, sessionTestUserAgent)
	if _, err := f.s.store.EndSession(gone.ID, model.SessionEndLogout, &f.viewer.ID, f.clk.now()); err != nil {
		t.Fatalf("end session: %v", err)
	}

	rows := decodeSessionList(t, f.do(t, "GET", userSessionsPath(f.viewer.ID), f.adminToken))
	if len(rows) != 1 || rows[0].ID != live.ID {
		t.Fatalf("default listing must show only live rows, got %+v", rows)
	}

	rows = decodeSessionList(t, f.do(t, "GET",
		userSessionsPath(f.viewer.ID)+"?include_ended=true", f.adminToken))
	ended := sessionByIDIn(rows, gone.ID)
	if ended == nil {
		t.Fatalf("include_ended must add the ended row, got %+v", rows)
	}
	if ended.EndedAt == nil || ended.EndReason != model.SessionEndLogout {
		t.Fatalf("ended row = %+v, want an ended_at and the logout reason", ended)
	}
	if ended.IdleDeadlineAt != nil {
		t.Fatal("an ended session has no idle deadline left to run")
	}
}

// An administrator listing their own sessions sees which one they are using.
func TestSessionsAPI_AdminListMarksOwnCurrentSession(t *testing.T) {
	f := newSessionsFixture(t)
	rows := decodeSessionList(t, f.do(t, "GET", userSessionsPath(f.adminID), f.adminToken))
	current := sessionByIDIn(rows, f.adminSID)
	if current == nil {
		t.Fatalf("the admin's own session is missing from %+v", rows)
	}
	if !current.Current {
		t.Fatal("the session the admin is calling from must be marked current")
	}
}

// The listing is administrator-only and only exists for accounts that do.
func TestSessionsAPI_AdminListGuards(t *testing.T) {
	f := newSessionsFixture(t)
	viewerToken, _, _ := sessionTokenPair(t, f.s, f.viewer.ID)

	if rec := f.do(t, "GET", userSessionsPath(f.adminID), viewerToken); rec.Code != http.StatusForbidden {
		t.Fatalf(wantCodeFmt, "viewer listing an admin's sessions",
			http.StatusForbidden, rec.Code, rec.Body.String())
	}
	if rec := f.do(t, "GET", userSessionsPath(uuid.NewString()), f.adminToken); rec.Code != http.StatusNotFound {
		t.Fatalf(wantCodeFmt, "unknown user", http.StatusNotFound, rec.Code, rec.Body.String())
	}
}

// --- admin revocation -------------------------------------------------------

// Ending one session takes that credential out of service, leaves the user's
// other sessions alone, is idempotent, and is audited as an admin revocation.
func TestSessionsAPI_AdminEndsOneSession(t *testing.T) {
	f := newSessionsFixture(t)
	firstToken, _, firstSID := sessionTokenPair(t, f.s, f.viewer.ID)
	secondToken, _, _ := sessionTokenPair(t, f.s, f.viewer.ID)

	rec := f.do(t, "DELETE", userSessionsPath(f.viewer.ID)+"/"+firstSID, f.adminToken)
	if got := decodeStatus(t, rec); got != statusEnded {
		t.Fatalf(wantStatusFmt, got, statusEnded)
	}

	stored := reloadSession(t, f.s, firstSID)
	if stored.EndReason != model.SessionEndRevokedAdmin || stored.EndedAt == nil {
		t.Fatalf("session not revoked: reason %q ended_at %v", stored.EndReason, stored.EndedAt)
	}
	if stored.EndedBy == nil || *stored.EndedBy != f.adminID {
		t.Fatalf("ended by = %v, want the administrator (%q)", stored.EndedBy, f.adminID)
	}

	entries := auditEntriesFor(t, f.s, f.adminID, model.AuditSessionRevoked)
	if len(entries) != 1 {
		t.Fatalf("expected one %s entry, got %d", model.AuditSessionRevoked, len(entries))
	}
	detail := decodeSessionDetail(t, entries[0])
	if detail.SessionID != firstSID || detail.Reason != model.SessionEndRevokedAdmin {
		t.Fatalf("audit detail = %+v, want session %q revoked_admin", detail, firstSID)
	}

	// The revoked credential is refused with the wording that says someone
	// ended it; the user's other session keeps working.
	assertUnauthorized(t, authedGet(t, f.s, testMePath, firstToken), session.MsgEnded, "revoked session")
	if rec := authedGet(t, f.s, testMePath, secondToken); rec.Code != http.StatusOK {
		t.Fatalf(wantCodeFmt, "the other session", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Ending it again is a no-op that says so rather than failing.
	again := f.do(t, "DELETE", userSessionsPath(f.viewer.ID)+"/"+firstSID, f.adminToken)
	if got := decodeStatus(t, again); got != statusAlreadyEnded {
		t.Fatalf(wantStatusFmt, got, statusAlreadyEnded)
	}
	if got := len(auditEntriesFor(t, f.s, f.adminID, model.AuditSessionRevoked)); got != 1 {
		t.Fatalf("a repeated revocation must not audit again, got %d entries", got)
	}
}

// A session id that is not this user's is not found, whoever it belongs to:
// the endpoint is scoped to the account in the path.
func TestSessionsAPI_AdminEndSessionNotFound(t *testing.T) {
	f := newSessionsFixture(t)
	other := newLocalUser(t, f.s, "otherowner", lockoutTestPassword)
	otherSession := newSessionRow(t, f.s, other.ID)

	for name, sid := range map[string]string{
		"unknown session": unknownSessionID,
		"another user's":  otherSession.ID,
		"unknown shell":   unknownShellID,
	} {
		rec := f.do(t, "DELETE", userSessionsPath(f.viewer.ID)+"/"+sid, f.adminToken)
		if rec.Code != http.StatusNotFound {
			t.Fatalf(wantCodeFmt, name, http.StatusNotFound, rec.Code, rec.Body.String())
		}
	}
	if reloadSession(t, f.s, otherSession.ID).EndedAt != nil {
		t.Fatal("a 404 must not have ended the other user's session")
	}
}

// Revocation is administrator-only.
func TestSessionsAPI_AdminEndSessionForbiddenForViewer(t *testing.T) {
	f := newSessionsFixture(t)
	viewerToken, _, viewerSID := sessionTokenPair(t, f.s, f.viewer.ID)
	victim := newSessionRow(t, f.s, f.adminID)

	rec := f.do(t, "DELETE", userSessionsPath(f.adminID)+"/"+victim.ID, viewerToken)
	if rec.Code != http.StatusForbidden {
		t.Fatalf(wantCodeFmt, "viewer revoking", http.StatusForbidden, rec.Code, rec.Body.String())
	}
	if reloadSession(t, f.s, victim.ID).EndedAt != nil {
		t.Fatal("a forbidden request must not end anything")
	}
	if reloadSession(t, f.s, viewerSID).EndedAt != nil {
		t.Fatal("the caller's own session must be untouched")
	}
}

// Ending everything ends every live session and closes every shell, reporting
// both counts.
func TestSessionsAPI_AdminEndsAllSessions(t *testing.T) {
	f := newSessionsFixture(t)
	firstToken, _, _ := sessionTokenPair(t, f.s, f.viewer.ID)
	secondToken, _, secondSID := sessionTokenPair(t, f.s, f.viewer.ID)
	shell := registerShell(t, f.s, sessionsTestServerID, "term-1", f.viewer.ID,
		grpcserver.TerminalKindSSH, "")
	ownShell := registerShell(t, f.s, sessionsTestServerID, "term-2", f.viewer.ID,
		grpcserver.TerminalKindWeb, secondSID)

	counts := decodeEndedCount(t, f.do(t, "DELETE", userSessionsPath(f.viewer.ID), f.adminToken))
	if counts.Ended != 2 || counts.ShellsClosed != 2 {
		t.Fatalf("counts = %+v, want two sessions and two shells", counts)
	}

	assertUnauthorized(t, authedGet(t, f.s, testMePath, firstToken), session.MsgEnded, "first session")
	assertUnauthorized(t, authedGet(t, f.s, testMePath, secondToken), session.MsgEnded, "second session")
	expectShellClosed(t, shell, shellMsgAdminRevoked)
	expectShellClosed(t, ownShell, shellMsgAdminRevoked)

	if got := len(auditEntriesFor(t, f.s, f.adminID, model.AuditSessionRevoked)); got != 2 {
		t.Fatalf("expected one %s entry per session, got %d", model.AuditSessionRevoked, got)
	}
	// The administrator's own session is another user's business entirely.
	if rec := authedGet(t, f.s, testMePath, f.adminToken); rec.Code != http.StatusOK {
		t.Fatalf(wantCodeFmt, "admin's own session", http.StatusOK, rec.Code, rec.Body.String())
	}
}

// A shell is addressed by its synthetic id on the same route, and closing it
// tells the person at the terminal why it went away.
func TestSessionsAPI_AdminEndsShell(t *testing.T) {
	f := newSessionsFixture(t)
	shell := registerShell(t, f.s, sessionsTestServerID, "term-1", f.viewer.ID,
		grpcserver.TerminalKindSSH, "")
	id := shellRowID(sessionsTestServerID, "term-1")

	rec := f.do(t, "DELETE", userSessionsPath(f.viewer.ID)+"/"+id, f.adminToken)
	if got := decodeStatus(t, rec); got != statusEnded {
		t.Fatalf(wantStatusFmt, got, statusEnded)
	}
	expectShellClosed(t, shell, shellMsgAdminRevoked)

	if infos := f.s.terminalSessions.ListByUser(f.viewer.ID); len(infos) != 0 {
		t.Fatalf("the closed shell must leave the live list, got %+v", infos)
	}
	// Once closed it is no longer one of the user's shells at all.
	if again := f.do(t, "DELETE", userSessionsPath(f.viewer.ID)+"/"+id, f.adminToken); again.Code != http.StatusNotFound {
		t.Fatalf(wantCodeFmt, "closing a closed shell", http.StatusNotFound, again.Code, again.Body.String())
	}
}

// A shell belonging to someone else is not this user's to close.
func TestSessionsAPI_AdminEndShellOfAnotherUser(t *testing.T) {
	f := newSessionsFixture(t)
	other := newLocalUser(t, f.s, "shellowner", lockoutTestPassword)
	shell := registerShell(t, f.s, sessionsTestServerID, "term-9", other.ID,
		grpcserver.TerminalKindSSH, "")

	rec := f.do(t, "DELETE",
		userSessionsPath(f.viewer.ID)+"/"+shellRowID(sessionsTestServerID, "term-9"), f.adminToken)
	if rec.Code != http.StatusNotFound {
		t.Fatalf(wantCodeFmt, "another user's shell", http.StatusNotFound, rec.Code, rec.Body.String())
	}
	select {
	case evt := <-shell:
		t.Fatalf("the other user's shell was closed anyway: %+v", evt)
	default:
	}
}

// Disabling an account takes its sessions and shells with it (008 + FR-008).
func TestSessionsAPI_DisableEndsSessionsAndShells(t *testing.T) {
	f := newSessionsFixture(t)
	token, _, sid := sessionTokenPair(t, f.s, f.viewer.ID)
	shell := registerShell(t, f.s, sessionsTestServerID, "term-1", f.viewer.ID,
		grpcserver.TerminalKindSSH, "")

	rec := lifecycleRequest(t, f.s, "PUT", testUsersPrefix+f.viewer.ID+"/status", f.adminToken,
		model.UpdateUserStatusRequest{Disabled: true})
	if rec.Code != http.StatusOK {
		t.Fatalf(wantCodeFmt, "disable", http.StatusOK, rec.Code, rec.Body.String())
	}

	stored := reloadSession(t, f.s, sid)
	if stored.EndReason != model.SessionEndRevokedDisable || stored.EndedAt == nil {
		t.Fatalf("session end reason = %q, want %q", stored.EndReason, model.SessionEndRevokedDisable)
	}
	expectShellClosed(t, shell, shellMsgAccountDisabled)

	// The account check refuses the token before the session check does, so
	// the assertion here is only that the credential is dead.
	if rec := authedGet(t, f.s, testMePath, token); rec.Code != http.StatusUnauthorized &&
		rec.Code != http.StatusForbidden {
		t.Fatalf("a disabled user's token still works: %d: %s", rec.Code, rec.Body.String())
	}
	if got := len(auditEntriesFor(t, f.s, f.adminID, model.AuditSessionRevoked)); got != 1 {
		t.Fatalf("expected one %s entry from the disable, got %d", model.AuditSessionRevoked, got)
	}
}

// --- self service -----------------------------------------------------------

// The self listing shows only the caller's own rows and marks the one they are
// calling from, with the deadline the panel counts down to.
func TestSessionsAPI_SelfListsOwnSessions(t *testing.T) {
	f := newSessionsFixture(t)
	otherOwner := newSessionRow(t, f.s, f.viewer.ID)
	mine := newSessionRow(t, f.s, f.adminID)

	rows := decodeSessionList(t, f.do(t, "GET", authSessionsPath, f.adminToken))
	if sessionByIDIn(rows, otherOwner.ID) != nil {
		t.Fatalf("another user's session leaked into the self listing: %+v", rows)
	}
	if sessionByIDIn(rows, mine.ID) == nil {
		t.Fatalf("the caller's other session is missing from %+v", rows)
	}

	current := sessionByIDIn(rows, f.adminSID)
	if current == nil || !current.Current {
		t.Fatalf("the calling session must be listed and marked current: %+v", rows)
	}
	if current.IdleDeadlineAt == nil {
		t.Fatal("the self listing must carry the idle deadline")
	}
}

// A user can end another of their own sessions, and it is recorded as their
// own doing rather than an administrator's.
func TestSessionsAPI_SelfEndsAnotherOwnSession(t *testing.T) {
	f := newSessionsFixture(t)
	otherToken, _, otherSID := sessionTokenPair(t, f.s, f.adminID)

	rec := f.do(t, "DELETE", authSessionsPath+"/"+otherSID, f.adminToken)
	if got := decodeStatus(t, rec); got != statusEnded {
		t.Fatalf(wantStatusFmt, got, statusEnded)
	}
	if got := reloadSession(t, f.s, otherSID).EndReason; got != model.SessionEndRevokedSelf {
		t.Fatalf("end reason = %q, want %q", got, model.SessionEndRevokedSelf)
	}
	assertUnauthorized(t, authedGet(t, f.s, testMePath, otherToken), session.MsgEnded, "ended own session")

	entries := auditEntriesFor(t, f.s, f.adminID, model.AuditSessionRevoked)
	if len(entries) != 1 {
		t.Fatalf("expected one %s entry, got %d", model.AuditSessionRevoked, len(entries))
	}
	if detail := decodeSessionDetail(t, entries[0]); detail.Reason != model.SessionEndRevokedSelf {
		t.Fatalf("audit reason = %q, want %q", detail.Reason, model.SessionEndRevokedSelf)
	}
}

// The session you are using is ended by signing out, not from the list — the
// list would leave the browser holding a dead credential with no redirect.
func TestSessionsAPI_SelfCannotEndCurrentSession(t *testing.T) {
	f := newSessionsFixture(t)
	rec := f.do(t, "DELETE", authSessionsPath+"/"+f.adminSID, f.adminToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf(wantCodeFmt, "ending the current session",
			http.StatusBadRequest, rec.Code, rec.Body.String())
	}
	if got := errorBody(t, rec); got != currentSessionEndMessage {
		t.Fatalf("message = %q, want %q", got, currentSessionEndMessage)
	}
	if reloadSession(t, f.s, f.adminSID).EndedAt != nil {
		t.Fatal("the current session must survive the refusal")
	}
}

// Someone else's session is not there to be ended, and says so as a 404 rather
// than confirming that the id exists.
func TestSessionsAPI_SelfCannotEndAnotherUsersSession(t *testing.T) {
	f := newSessionsFixture(t)
	victim := newSessionRow(t, f.s, f.viewer.ID)
	shell := registerShell(t, f.s, sessionsTestServerID, "term-1", f.viewer.ID,
		grpcserver.TerminalKindSSH, "")

	for name, sid := range map[string]string{
		"another user's session": victim.ID,
		"another user's shell":   shellRowID(sessionsTestServerID, "term-1"),
		"unknown session":        unknownSessionID,
	} {
		rec := f.do(t, "DELETE", authSessionsPath+"/"+sid, f.adminToken)
		if rec.Code != http.StatusNotFound {
			t.Fatalf(wantCodeFmt, name, http.StatusNotFound, rec.Code, rec.Body.String())
		}
	}
	if reloadSession(t, f.s, victim.ID).EndedAt != nil {
		t.Fatal("a 404 must not have ended the other user's session")
	}
	select {
	case evt := <-shell:
		t.Fatalf("the other user's shell was closed anyway: %+v", evt)
	default:
	}
}

// Signing out everywhere else keeps the caller signed in and clears the rest,
// shells included.
func TestSessionsAPI_SelfSignsOutOtherSessions(t *testing.T) {
	f := newSessionsFixture(t)
	otherToken, _, otherSID := sessionTokenPair(t, f.s, f.adminID)
	shell := registerShell(t, f.s, sessionsTestServerID, "term-1", f.adminID,
		grpcserver.TerminalKindSSH, "")

	counts := decodeEndedCount(t, f.do(t, "POST", signOutOthersPath, f.adminToken))
	if counts.Ended != 1 || counts.ShellsClosed != 1 {
		t.Fatalf("counts = %+v, want one session and one shell", counts)
	}

	if reloadSession(t, f.s, otherSID).EndReason != model.SessionEndRevokedSelf {
		t.Fatalf("the other session was not ended as a self revocation")
	}
	assertUnauthorized(t, authedGet(t, f.s, testMePath, otherToken), session.MsgEnded, "signed-out session")
	expectShellClosed(t, shell, shellMsgSignedOut)

	if reloadSession(t, f.s, f.adminSID).EndedAt != nil {
		t.Fatal("the calling session must survive signing out everywhere else")
	}
	if rec := authedGet(t, f.s, testMePath, f.adminToken); rec.Code != http.StatusOK {
		t.Fatalf(wantCodeFmt, "calling session", http.StatusOK, rec.Code, rec.Body.String())
	}
}

// The self endpoints belong to a person at a keyboard: an API token has no
// session to manage and is refused.
func TestSessionsAPI_SelfEndpointsRefuseAPITokens(t *testing.T) {
	f := newSessionsFixture(t)
	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if err := f.s.store.CreateAPIToken(&model.APIToken{
		ID: uuid.NewString(), UserID: f.adminID, Name: "robot",
		TokenHash: hash, TokenPrefix: prefix,
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}

	for _, tc := range []struct{ method, path string }{
		{"GET", authSessionsPath},
		{"DELETE", authSessionsPath + "/" + unknownSessionID},
		{"POST", signOutOthersPath},
	} {
		rec := f.do(t, tc.method, tc.path, raw)
		if rec.Code != http.StatusForbidden {
			t.Fatalf(wantCodeFmt, tc.method+" "+tc.path,
				http.StatusForbidden, rec.Code, rec.Body.String())
		}
	}
}

// A session whose absolute limit has passed is reported as expired rather than
// ended, so the listing and the refusal agree about what happened.
func TestSessionsAPI_SelfListOmitsEndedRows(t *testing.T) {
	f := newSessionsFixture(t)
	gone := newSessionRow(t, f.s, f.adminID)
	if _, err := f.s.store.EndSession(gone.ID, model.SessionEndRevokedSelf, &f.adminID, f.clk.now()); err != nil {
		t.Fatalf("end session: %v", err)
	}
	f.clk.advance(time.Minute)

	rows := decodeSessionList(t, f.do(t, "GET", authSessionsPath, f.adminToken))
	if sessionByIDIn(rows, gone.ID) != nil {
		t.Fatalf("the self listing must not show ended rows: %+v", rows)
	}
}
