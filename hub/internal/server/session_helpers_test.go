package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
	"github.com/wyiu/veyport/hub/internal/store"
)

// T009 — unit tests for the shared session helpers.
//
// These pin the parts that every session-bearing path depends on: how a client
// is classified, what a sign-in writes, which of the two refusal messages each
// verdict produces, that an expiry is audited exactly once however many
// requests notice it, and what ending sessions does to rows, shells and the
// audit trail. The wiring tests then only have to prove each path calls these
// at the right point.

const (
	// sessionTestUserAgent is a browser-shaped agent: anything that is not the
	// CLI is a web client.
	sessionTestUserAgent = "Mozilla/5.0 (X11; Linux x86_64)"
	// sessionTestCLIAgent is what the vey CLI sends.
	sessionTestCLIAgent = "vey/2.0.37"
)

// sessionServer builds a test server with a controllable clock and a live
// terminal registry, so shell rows and forced closes can be exercised.
func sessionServer(t *testing.T) (*Server, *testClock) {
	t.Helper()
	s, clk := lockoutServer(t)
	s.terminalSessions = grpcserver.NewTerminalSessions()
	return s, clk
}

// setSessionPolicy writes the two session policy keys through the config
// store: idle in whole minutes, absolute in whole hours, 0 disabling either.
func setSessionPolicy(t *testing.T, s *Server, idleMinutes, maxHours int) {
	t.Helper()
	for key, value := range map[string]string{
		lockout.KeySessionIdleMinutes: strconv.Itoa(idleMinutes),
		lockout.KeySessionMaxHours:    strconv.Itoa(maxHours),
	} {
		if err := s.store.SetConfig(key, value); err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}
}

// sessionRequest builds a request carrying a user agent and a client address,
// the two things newSession records about the client.
func sessionRequest(userAgent string) *http.Request {
	r := httptest.NewRequest("POST", "/api/auth/login/totp", nil)
	r.RemoteAddr = "203.0.113.7:51234"
	if userAgent != "" {
		r.Header.Set("User-Agent", userAgent)
	} else {
		r.Header.Del("User-Agent")
	}
	return r
}

// newSessionRow creates a live session for a user the way a sign-in does.
func newSessionRow(t *testing.T, s *Server, userID string) *model.Session {
	t.Helper()
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		t.Fatalf("get user %s: %v", userID, err)
	}
	sess, err := s.newSession(sessionRequest(sessionTestUserAgent), user)
	if err != nil {
		t.Fatalf("create session for %s: %v", userID, err)
	}
	return sess
}

// sessionTokenPair mints an access/refresh pair bound to a fresh session, the
// way a completed sign-in does. Tests that used auth.GenerateTokenPair for an
// authenticated request need this instead: an unbound token is refused now.
func sessionTokenPair(t *testing.T, s *Server, userID string) (accessToken, refreshToken, sid string) {
	t.Helper()
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		t.Fatalf("get user %s: %v", userID, err)
	}
	sess := newSessionRow(t, s, userID)
	accessToken, refreshToken, err = auth.GenerateSessionTokenPair(
		s.jwtSecret, user.ID, string(user.Role), user.TokenGeneration, sess.ID,
	)
	if err != nil {
		t.Fatalf("generate session token pair: %v", err)
	}
	return accessToken, refreshToken, sess.ID
}

// reloadSession reads a session row back.
func reloadSession(t *testing.T, s *Server, id string) *model.Session {
	t.Helper()
	sess, err := s.store.GetSession(id)
	if err != nil {
		t.Fatalf("reload session %s: %v", id, err)
	}
	return sess
}

// sessionDetail is the JSON detail carried by the three session audit events.
type sessionDetail struct {
	SessionID string `json:"session_id"`
	Kind      string `json:"kind"`
	Reason    string `json:"reason"`
}

// decodeSessionDetail parses an audit entry's detail payload.
func decodeSessionDetail(t *testing.T, entry model.AuditEntry) sessionDetail {
	t.Helper()
	if entry.Detail == nil {
		t.Fatalf("audit entry %s carries no detail", entry.Action)
	}
	var detail sessionDetail
	if err := json.Unmarshal([]byte(*entry.Detail), &detail); err != nil {
		t.Fatalf("decode detail %q: %v", *entry.Detail, err)
	}
	return detail
}

// claimsFor builds the claims a request would carry for a session id.
func claimsFor(sid string) *auth.Claims {
	return &auth.Claims{SessionID: sid, TokenType: auth.TokenTypeAccess}
}

// assertSessionError checks that err is a session refusal with the given
// message.
func assertSessionError(t *testing.T, err error, want, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected a refusal, got nil", label)
	}
	sessErr, ok := err.(*sessionAccessError)
	if !ok {
		t.Fatalf("%s: expected *sessionAccessError, got %T (%v)", label, err, err)
	}
	if sessErr.Error() != want {
		t.Fatalf("%s: expected %q, got %q", label, want, sessErr.Error())
	}
}

// --- clientKind -------------------------------------------------------------

// The CLI is the only client identified positively; everything else, including
// an absent agent, is recorded as web (spec Edge Cases).
func TestClientKind_CLIPrefixOnly(t *testing.T) {
	for _, tc := range []struct {
		agent string
		want  string
	}{
		{sessionTestCLIAgent, model.SessionKindCLI},
		{"vey/dev", model.SessionKindCLI},
		{"vey/", model.SessionKindCLI},
		{sessionTestUserAgent, model.SessionKindWeb},
		{"", model.SessionKindWeb},
		{"veyport/1.0", model.SessionKindWeb},
		{"curl/8.5.0 vey/2.0.0", model.SessionKindWeb},
	} {
		if got := clientKind(sessionRequest(tc.agent)); got != tc.want {
			t.Errorf("clientKind(%q) = %q, want %q", tc.agent, got, tc.want)
		}
	}
}

// --- newSession -------------------------------------------------------------

// A sign-in writes the whole row and audits it, and the absolute expiry is
// stamped from the policy in force at that moment (FR-001, FR-004).
func TestNewSession_RecordsRowAndAudits(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 12)
	user := newLocalUser(t, s, "sam", lockoutTestPassword)

	sess, err := s.newSession(sessionRequest(sessionTestCLIAgent), user)
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}

	stored := reloadSession(t, s, sess.ID)
	if stored.UserID != user.ID {
		t.Fatalf("user id = %q, want %q", stored.UserID, user.ID)
	}
	if stored.Kind != model.SessionKindCLI {
		t.Fatalf("kind = %q, want %q", stored.Kind, model.SessionKindCLI)
	}
	if stored.IP != "203.0.113.7" {
		t.Fatalf("ip = %q, want %q", stored.IP, "203.0.113.7")
	}
	if stored.UserAgent != sessionTestCLIAgent {
		t.Fatalf("user agent = %q, want %q", stored.UserAgent, sessionTestCLIAgent)
	}
	if !stored.CreatedAt.Equal(clk.now()) || !stored.LastSeenAt.Equal(clk.now()) {
		t.Fatalf("created/last seen = %s/%s, want %s", stored.CreatedAt, stored.LastSeenAt, clk.now())
	}
	if stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(clk.now().Add(12*time.Hour)) {
		t.Fatalf("expires at = %v, want %s", stored.ExpiresAt, clk.now().Add(12*time.Hour))
	}
	if stored.EndedAt != nil {
		t.Fatalf("a new session must be live, got ended at %s", stored.EndedAt)
	}

	entries := auditEntriesFor(t, s, user.ID, model.AuditSessionCreated)
	if len(entries) != 1 {
		t.Fatalf("expected one %s entry, got %d", model.AuditSessionCreated, len(entries))
	}
	entry := entries[0]
	if entry.Outcome != model.AuditOutcomeSuccess || entry.ActorType != model.AuditActorTypeUser {
		t.Fatalf("outcome/actor = %q/%q, want success/user", entry.Outcome, entry.ActorType)
	}
	if entry.Target == nil || *entry.Target != user.ID {
		t.Fatalf("target = %v, want %q", entry.Target, user.ID)
	}
	if entry.ResourceType == nil || *entry.ResourceType != sessionResourceType {
		t.Fatalf("resource type = %v, want %q", entry.ResourceType, sessionResourceType)
	}
	detail := decodeSessionDetail(t, entry)
	if detail.SessionID != sess.ID || detail.Kind != model.SessionKindCLI {
		t.Fatalf("detail = %+v, want session %s kind cli", detail, sess.ID)
	}
}

// An absolute limit of 0 means the session has none at all, which is stored as
// a NULL expiry rather than a far-future one.
func TestNewSession_AbsoluteLimitDisabledLeavesNoExpiry(t *testing.T) {
	s, _ := sessionServer(t)
	setSessionPolicy(t, s, 15, 0)
	user := newLocalUser(t, s, "noexpiry", lockoutTestPassword)

	sess, err := s.newSession(sessionRequest(sessionTestUserAgent), user)
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	if reloadSession(t, s, sess.ID).ExpiresAt != nil {
		t.Fatal("expected no absolute expiry when the policy is 0")
	}
}

// A long user agent is truncated rather than rejected, and stays valid text.
func TestNewSession_TruncatesUserAgent(t *testing.T) {
	s, _ := sessionServer(t)
	user := newLocalUser(t, s, "verbose", lockoutTestPassword)

	long := strings.Repeat("a", maxUserAgentLength+64)
	sess, err := s.newSession(sessionRequest(long), user)
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	stored := reloadSession(t, s, sess.ID)
	if len(stored.UserAgent) != maxUserAgentLength {
		t.Fatalf("user agent length = %d, want %d", len(stored.UserAgent), maxUserAgentLength)
	}
}

// Truncation must not split a multi-byte character in half.
func TestTruncateUserAgent_KeepsValidUTF8(t *testing.T) {
	// "é" is two bytes, so a run of them straddles the byte limit.
	long := strings.Repeat("é", maxUserAgentLength)
	got := truncateUserAgent(long)
	if len(got) > maxUserAgentLength {
		t.Fatalf("length = %d, want <= %d", len(got), maxUserAgentLength)
	}
	if !strings.HasPrefix(long, got) {
		t.Fatal("truncation must keep a prefix of the original")
	}
	for _, r := range got {
		if r == '�' {
			t.Fatal("truncation split a multi-byte character")
		}
	}
}

// --- sessionAccessError -----------------------------------------------------

// A token with no session id is the pre-upgrade case: refused as expired, so
// every existing client signs in once after the upgrade (FR-002, R10).
func TestSessionAccessError_MissingSessionID(t *testing.T) {
	s, _ := sessionServer(t)
	assertSessionError(t, s.sessionAccessError(claimsFor("")), session.MsgExpired, "no sid")
}

// A session id that names no row is indistinguishable from one that was
// pruned, so it is refused the same way.
func TestSessionAccessError_UnknownSession(t *testing.T) {
	s, _ := sessionServer(t)
	assertSessionError(t, s.sessionAccessError(claimsFor(uuid.NewString())),
		session.MsgExpired, "unknown session")
}

// The touch throttle scales with the idle limit, so the staleness it allows in
// last_seen_at stays a small fraction of the window a session is judged
// against: a minute under the default, seconds under a one-minute limit, and
// the cheap cap when idle expiry is off entirely.
func TestTouchInterval_ScalesWithIdleLimit(t *testing.T) {
	cases := []struct {
		name string
		idle time.Duration
		want time.Duration
	}{
		{name: "default 15m", idle: 15 * time.Minute, want: 60 * time.Second},
		{name: "long 8h", idle: 8 * time.Hour, want: 60 * time.Second},
		{name: "exactly 10m", idle: 10 * time.Minute, want: 60 * time.Second},
		{name: "short 1m", idle: time.Minute, want: 6 * time.Second},
		{name: "short 2m", idle: 2 * time.Minute, want: 12 * time.Second},
		{name: "idle disabled", idle: 0, want: 60 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := touchInterval(lockout.Policy{SessionIdle: tc.idle})
			if got != tc.want {
				t.Fatalf("touchInterval(%s) = %s, want %s", tc.idle, got, tc.want)
			}
			if tc.idle > 0 && got > tc.idle/touchIntervalFraction {
				t.Fatalf("touchInterval(%s) = %s, more than a tenth of the idle limit", tc.idle, got)
			}
		})
	}
}

// A live session is allowed and its activity is recorded, throttled to one
// write per touchInterval — a minute under the 15-minute idle limit this test
// sets (FR-003).
func TestSessionAccessError_LiveSessionIsTouchedThrottled(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 12)
	user := newLocalUser(t, s, "live", lockoutTestPassword)
	sess := newSessionRow(t, s, user.ID)
	created := reloadSession(t, s, sess.ID).LastSeenAt

	clk.advance(30 * time.Second)
	if err := s.sessionAccessError(claimsFor(sess.ID)); err != nil {
		t.Fatalf("live session refused: %v", err)
	}
	if got := reloadSession(t, s, sess.ID).LastSeenAt; !got.Equal(created) {
		t.Fatalf("last seen moved after 30s (%s → %s); the throttle should hold it", created, got)
	}

	clk.advance(31 * time.Second)
	if err := s.sessionAccessError(claimsFor(sess.ID)); err != nil {
		t.Fatalf("live session refused: %v", err)
	}
	if got := reloadSession(t, s, sess.ID).LastSeenAt; !got.Equal(clk.now()) {
		t.Fatalf("last seen = %s, want %s after the throttle window", got, clk.now())
	}
}

// A deliberately ended session is the only case that says "ended" — the one
// piece of information the user needs to tell a revoke from a timeout.
func TestSessionAccessError_EndedSessionSaysEnded(t *testing.T) {
	s, clk := sessionServer(t)
	user := newLocalUser(t, s, "revoked", lockoutTestPassword)
	sess := newSessionRow(t, s, user.ID)

	if _, err := s.store.EndSession(sess.ID, model.SessionEndRevokedAdmin, &user.ID, clk.now()); err != nil {
		t.Fatalf("end session: %v", err)
	}
	assertSessionError(t, s.sessionAccessError(claimsFor(sess.ID)), session.MsgEnded, "ended session")
}

// Passing the idle limit marks the row and audits the expiry exactly once,
// however many requests of the same dead session arrive (FR-005).
func TestSessionAccessError_IdleExpiryMarksAndAuditsOnce(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 1, 12)
	user := newLocalUser(t, s, "idle", lockoutTestPassword)
	sess := newSessionRow(t, s, user.ID)

	clk.advance(2 * time.Minute)
	assertSessionError(t, s.sessionAccessError(claimsFor(sess.ID)), session.MsgExpired, "idle session")

	stored := reloadSession(t, s, sess.ID)
	if stored.EndReason != model.SessionEndExpiredIdle {
		t.Fatalf("end reason = %q, want %q", stored.EndReason, model.SessionEndExpiredIdle)
	}
	if stored.EndedBy != nil {
		t.Fatalf("expiry is the hub's own decision; ended_by = %v, want nil", stored.EndedBy)
	}

	entries := auditEntriesFor(t, s, user.ID, model.AuditSessionExpired)
	if len(entries) != 1 {
		t.Fatalf("expected one %s entry, got %d", model.AuditSessionExpired, len(entries))
	}
	entry := entries[0]
	if entry.ActorType != model.AuditActorTypeSystem || entry.Outcome != model.AuditOutcomeFailure {
		t.Fatalf("actor/outcome = %q/%q, want system/failure", entry.ActorType, entry.Outcome)
	}
	if detail := decodeSessionDetail(t, entry); detail.Reason != "idle" || detail.SessionID != sess.ID {
		t.Fatalf("detail = %+v, want reason idle for session %s", detail, sess.ID)
	}

	// A second request on the same dead session is refused identically and
	// must not produce a second audit entry.
	assertSessionError(t, s.sessionAccessError(claimsFor(sess.ID)), session.MsgExpired, "second request")
	if got := len(auditEntriesFor(t, s, user.ID, model.AuditSessionExpired)); got != 1 {
		t.Fatalf("expected still one %s entry, got %d", model.AuditSessionExpired, got)
	}
}

// The absolute limit outranks the idle one, so a session kept busy right up to
// its expiry is still reported as having run out of time.
func TestSessionAccessError_AbsoluteExpiryOutranksIdle(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 1)
	user := newLocalUser(t, s, "absolute", lockoutTestPassword)
	sess := newSessionRow(t, s, user.ID)

	// Busy every ten minutes, so the idle clock never runs out.
	for i := 0; i < 6; i++ {
		clk.advance(10 * time.Minute)
		if err := s.sessionAccessError(claimsFor(sess.ID)); err != nil && i < 5 {
			t.Fatalf("request at +%dm refused early: %v", (i+1)*10, err)
		}
	}

	assertSessionError(t, s.sessionAccessError(claimsFor(sess.ID)), session.MsgExpired, "absolute expiry")
	stored := reloadSession(t, s, sess.ID)
	if stored.EndReason != model.SessionEndExpiredAbsolute {
		t.Fatalf("end reason = %q, want %q", stored.EndReason, model.SessionEndExpiredAbsolute)
	}
	entries := auditEntriesFor(t, s, user.ID, model.AuditSessionExpired)
	if len(entries) != 1 {
		t.Fatalf("expected one %s entry, got %d", model.AuditSessionExpired, len(entries))
	}
	if detail := decodeSessionDetail(t, entries[0]); detail.Reason != "absolute" {
		t.Fatalf("detail reason = %q, want absolute", detail.Reason)
	}
}

// Both limits off means a session stays usable indefinitely.
func TestSessionAccessError_LimitsDisabledNeverExpire(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 0, 0)
	user := newLocalUser(t, s, "forever", lockoutTestPassword)
	sess := newSessionRow(t, s, user.ID)

	clk.advance(48 * time.Hour)
	if err := s.sessionAccessError(claimsFor(sess.ID)); err != nil {
		t.Fatalf("session refused with both limits disabled: %v", err)
	}
}

// --- endSessions ------------------------------------------------------------

// Ending a named session ends exactly that one, audits it once, and leaves the
// user's other sessions alone (FR-009).
func TestEndSessions_ByIDEndsOneAndAudits(t *testing.T) {
	s, _ := sessionServer(t)
	admin := newLocalUser(t, s, "adminuser", lockoutTestPassword)
	user := newLocalUser(t, s, "target", lockoutTestPassword)
	victim := newSessionRow(t, s, user.ID)
	survivor := newSessionRow(t, s, user.ID)

	ended, shells := s.endSessions(sessionRequest(sessionTestUserAgent), &admin.ID, user,
		[]string{victim.ID}, false, nil, model.SessionEndRevokedAdmin)
	if ended != 1 || shells != 0 {
		t.Fatalf("ended/shells = %d/%d, want 1/0", ended, shells)
	}

	stored := reloadSession(t, s, victim.ID)
	if stored.EndReason != model.SessionEndRevokedAdmin || stored.EndedAt == nil {
		t.Fatalf("victim not ended: reason %q ended_at %v", stored.EndReason, stored.EndedAt)
	}
	if stored.EndedBy == nil || *stored.EndedBy != admin.ID {
		t.Fatalf("ended by = %v, want %q", stored.EndedBy, admin.ID)
	}
	if reloadSession(t, s, survivor.ID).EndedAt != nil {
		t.Fatal("the user's other session must be untouched")
	}

	entries := auditEntriesFor(t, s, admin.ID, model.AuditSessionRevoked)
	if len(entries) != 1 {
		t.Fatalf("expected one %s entry, got %d", model.AuditSessionRevoked, len(entries))
	}
	entry := entries[0]
	if entry.Target == nil || *entry.Target != user.ID {
		t.Fatalf("target = %v, want %q", entry.Target, user.ID)
	}
	detail := decodeSessionDetail(t, entry)
	if detail.SessionID != victim.ID || detail.Reason != model.SessionEndRevokedAdmin ||
		detail.Kind != model.SessionKindWeb {
		t.Fatalf("detail = %+v, want session %s reason revoked_admin kind web", detail, victim.ID)
	}

	// A second revoke of the same session ends nothing and audits nothing.
	if again, _ := s.endSessions(nil, &admin.ID, user,
		[]string{victim.ID}, false, nil, model.SessionEndRevokedAdmin); again != 0 {
		t.Fatalf("re-ending an ended session reported %d, want 0", again)
	}
	if got := len(auditEntriesFor(t, s, admin.ID, model.AuditSessionRevoked)); got != 1 {
		t.Fatalf("expected still one revoke entry, got %d", got)
	}
}

// Ending everything spares the excepted session and audits one entry per
// session it actually ended (FR-008).
func TestEndSessions_AllExceptCurrent(t *testing.T) {
	s, _ := sessionServer(t)
	user := newLocalUser(t, s, "selfservice", lockoutTestPassword)
	current := newSessionRow(t, s, user.ID)
	other1 := newSessionRow(t, s, user.ID)
	other2 := newSessionRow(t, s, user.ID)

	ended, _ := s.endSessions(sessionRequest(sessionTestUserAgent), &user.ID, user,
		nil, true, &current.ID, model.SessionEndRevokedSelf)
	if ended != 2 {
		t.Fatalf("ended = %d, want 2", ended)
	}
	if reloadSession(t, s, current.ID).EndedAt != nil {
		t.Fatal("the excepted session must stay live")
	}
	for _, id := range []string{other1.ID, other2.ID} {
		if reloadSession(t, s, id).EndReason != model.SessionEndRevokedSelf {
			t.Fatalf("session %s was not ended as revoked_self", id)
		}
	}
	if got := len(auditEntriesFor(t, s, user.ID, model.AuditSessionRevoked)); got != 2 {
		t.Fatalf("expected two revoke entries, got %d", got)
	}
}

// With no actor the entry is filed against the target, so an account's own
// trail still shows what happened to its sessions.
func TestEndSessions_NoActorAttributesToTarget(t *testing.T) {
	s, _ := sessionServer(t)
	user := newLocalUser(t, s, "systemended", lockoutTestPassword)
	sess := newSessionRow(t, s, user.ID)

	if ended, _ := s.endSessions(nil, nil, user, []string{sess.ID}, false, nil,
		model.SessionEndRevokedDisable); ended != 1 {
		t.Fatal("expected one session ended")
	}
	entries := auditEntriesFor(t, s, user.ID, model.AuditSessionRevoked)
	if len(entries) != 1 {
		t.Fatalf("expected one revoke entry against the target, got %d", len(entries))
	}
}

// Ending everything also closes the user's shells, whether or not a session
// opened them, and tells the person at the terminal why (FR-010).
func TestEndSessions_ClosesShells(t *testing.T) {
	s, _ := sessionServer(t)
	admin := newLocalUser(t, s, "shelladmin", lockoutTestPassword)
	user := newLocalUser(t, s, "shellowner", lockoutTestPassword)
	sess := newSessionRow(t, s, user.ID)

	webShell, ok := s.terminalSessions.Register("srv-1", "term-1", user.ID, "root",
		grpcserver.WithKind(grpcserver.TerminalKindWeb), grpcserver.WithSessionID(sess.ID))
	if !ok {
		t.Fatal("register web shell")
	}
	sshShell, ok := s.terminalSessions.Register("srv-2", "term-2", user.ID, "root",
		grpcserver.WithKind(grpcserver.TerminalKindSSH))
	if !ok {
		t.Fatal("register ssh shell")
	}

	ended, shells := s.endSessions(sessionRequest(sessionTestUserAgent), &admin.ID, user,
		nil, true, nil, model.SessionEndRevokedAdmin)
	if ended != 1 || shells != 2 {
		t.Fatalf("ended/shells = %d/%d, want 1/2", ended, shells)
	}

	for label, ch := range map[string]chan grpcserver.TerminalEvent{
		"web": webShell, "ssh": sshShell,
	} {
		select {
		case evt := <-ch:
			if evt.Type != grpcserver.TerminalEventExit {
				t.Fatalf("%s shell: event type = %v, want exit", label, evt.Type)
			}
			if evt.Error != shellMsgAdminRevoked {
				t.Fatalf("%s shell: message = %q, want %q", label, evt.Error, shellMsgAdminRevoked)
			}
			if evt.ExitCode != shellExitCode {
				t.Fatalf("%s shell: exit code = %d, want %d", label, evt.ExitCode, shellExitCode)
			}
		default:
			t.Fatalf("%s shell: expected a forced exit event", label)
		}
	}
}

// The message the shell's client sees names the cause in the user's terms.
func TestShellCloseMessage_PerReason(t *testing.T) {
	for reason, want := range map[string]string{
		model.SessionEndRevokedAdmin:   shellMsgAdminRevoked,
		model.SessionEndRevokedSelf:    shellMsgSignedOut,
		model.SessionEndLogout:         shellMsgSignedOut,
		model.SessionEndRevokedDisable: shellMsgAccountDisabled,
	} {
		if got := shellCloseMessage(reason); got != want {
			t.Errorf("shellCloseMessage(%q) = %q, want %q", reason, got, want)
		}
	}
}

// --- shellRows and sessionsFor ---------------------------------------------

// Shells are rendered with a synthetic id, the transport as kind and the
// server's name rather than its id.
func TestShellRows_MapsRegistryEntries(t *testing.T) {
	s, _ := sessionServer(t)
	user := newLocalUser(t, s, "shells", lockoutTestPassword)
	if err := s.store.CreateServer(&model.Server{ID: "srv-1", Name: "web-01", Status: "offline"}); err != nil {
		t.Fatalf("create server: %v", err)
	}

	if _, ok := s.terminalSessions.Register("srv-1", "term-1", user.ID, "root",
		grpcserver.WithKind(grpcserver.TerminalKindSSH)); !ok {
		t.Fatal("register ssh shell")
	}
	if _, ok := s.terminalSessions.Register("srv-missing", "term-2", user.ID, "root",
		grpcserver.WithKind(grpcserver.TerminalKindWeb)); !ok {
		t.Fatal("register web shell")
	}

	rows := s.shellRows(user.ID)
	if len(rows) != 2 {
		t.Fatalf("expected two shell rows, got %d", len(rows))
	}
	byID := map[string]model.Session{}
	for _, row := range rows {
		byID[row.ID] = row
	}

	ssh, ok := byID["shell:srv-1:term-1"]
	if !ok {
		t.Fatalf("missing shell:srv-1:term-1 in %v", byID)
	}
	if ssh.Kind != model.SessionKindSSH || ssh.Server != "web-01" {
		t.Fatalf("ssh row kind/server = %q/%q, want ssh/web-01", ssh.Kind, ssh.Server)
	}
	if ssh.StartedAt == nil || ssh.LastActivityAt == nil {
		t.Fatal("shell rows must carry started and last-activity times")
	}

	web, ok := byID["shell:srv-missing:term-2"]
	if !ok {
		t.Fatalf("missing shell:srv-missing:term-2 in %v", byID)
	}
	if web.Kind != model.SessionKindTerminal {
		t.Fatalf("web terminal kind = %q, want %q", web.Kind, model.SessionKindTerminal)
	}
	if web.Server != "srv-missing" {
		t.Fatalf("unknown server should fall back to its id, got %q", web.Server)
	}
}

// Without a registry (a hub with no terminal transport wired up) there are
// simply no shell rows, rather than a panic.
func TestShellRows_NoRegistry(t *testing.T) {
	s, _ := lockoutServer(t)
	if rows := s.shellRows(uuid.NewString()); rows != nil {
		t.Fatalf("expected no shell rows without a registry, got %v", rows)
	}
}

// The listing derives the idle deadline from the live policy, marks the
// caller's own row, and appends the user's shells.
func TestSessionsFor_DerivesDeadlineMarksCurrentAndAppendsShells(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 12)
	user := newLocalUser(t, s, "lister", lockoutTestPassword)
	current := newSessionRow(t, s, user.ID)
	other := newSessionRow(t, s, user.ID)
	if _, ok := s.terminalSessions.Register("srv-1", "term-1", user.ID, "root",
		grpcserver.WithKind(grpcserver.TerminalKindSSH)); !ok {
		t.Fatal("register shell")
	}

	rows, err := s.sessionsFor(user.ID, current.ID, false)
	if err != nil {
		t.Fatalf("sessionsFor: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected two sessions and one shell, got %d rows", len(rows))
	}

	var currentRow, otherRow *model.Session
	for i := range rows {
		switch rows[i].ID {
		case current.ID:
			currentRow = &rows[i]
		case other.ID:
			otherRow = &rows[i]
		}
	}
	if currentRow == nil || otherRow == nil {
		t.Fatalf("both sessions should be listed, got %v", rows)
	}
	if !currentRow.Current {
		t.Fatal("the caller's own session must be marked current")
	}
	if otherRow.Current {
		t.Fatal("another session must not be marked current")
	}
	want := clk.now().Add(15 * time.Minute)
	if currentRow.IdleDeadlineAt == nil || !currentRow.IdleDeadlineAt.Equal(want) {
		t.Fatalf("idle deadline = %v, want %s", currentRow.IdleDeadlineAt, want)
	}
	if rows[len(rows)-1].Kind != model.SessionKindSSH {
		t.Fatalf("shells belong at the end of the list, got %q", rows[len(rows)-1].Kind)
	}
}

// With the idle limit off there is no deadline to show, so the field is
// omitted rather than rendered as a zero time.
func TestSessionsFor_NoIdleDeadlineWhenPolicyZero(t *testing.T) {
	s, _ := sessionServer(t)
	setSessionPolicy(t, s, 0, 12)
	user := newLocalUser(t, s, "nodeadline", lockoutTestPassword)
	sess := newSessionRow(t, s, user.ID)

	rows, err := s.sessionsFor(user.ID, sess.ID, false)
	if err != nil {
		t.Fatalf("sessionsFor: %v", err)
	}
	if len(rows) != 1 || rows[0].IdleDeadlineAt != nil {
		t.Fatalf("expected one row with no idle deadline, got %+v", rows)
	}
}

// Ended sessions are history: hidden by default and, when asked for, limited
// to the retention window (FR-013).
func TestSessionsFor_IncludeEndedWithinWindow(t *testing.T) {
	s, clk := sessionServer(t)
	user := newLocalUser(t, s, "history", lockoutTestPassword)
	live := newSessionRow(t, s, user.ID)
	recent := newSessionRow(t, s, user.ID)
	ancient := newSessionRow(t, s, user.ID)

	if _, err := s.store.EndSession(recent.ID, model.SessionEndLogout, &user.ID, clk.now()); err != nil {
		t.Fatalf("end recent: %v", err)
	}
	if _, err := s.store.EndSession(ancient.ID, model.SessionEndLogout, &user.ID,
		clk.now().Add(-sessionHistoryWindow-time.Hour)); err != nil {
		t.Fatalf("end ancient: %v", err)
	}

	liveOnly, err := s.sessionsFor(user.ID, live.ID, false)
	if err != nil {
		t.Fatalf("sessionsFor: %v", err)
	}
	if len(liveOnly) != 1 || liveOnly[0].ID != live.ID {
		t.Fatalf("expected only the live session, got %+v", liveOnly)
	}

	withEnded, err := s.sessionsFor(user.ID, live.ID, true)
	if err != nil {
		t.Fatalf("sessionsFor include ended: %v", err)
	}
	if len(withEnded) != 2 {
		t.Fatalf("expected the live session and the recent ended one, got %d rows", len(withEnded))
	}
	for _, row := range withEnded {
		if row.ID == ancient.ID {
			t.Fatal("a session ended outside the retention window must not be listed")
		}
	}
}

// A store failure surfaces rather than being reported as an empty list.
func TestSessionsFor_StoreErrorSurfaces(t *testing.T) {
	s, _ := sessionServer(t)
	s.store.Close()
	if _, err := s.sessionsFor(uuid.NewString(), "", false); err == nil {
		t.Fatal("expected an error from a closed store")
	}
}

// isSessionNotFound must recognise the store's sentinel and nothing else.
func TestIsSessionNotFound(t *testing.T) {
	if !isSessionNotFound(store.ErrSessionNotFound) {
		t.Fatal("the store's sentinel must be recognised")
	}
	if isSessionNotFound(http.ErrNoCookie) {
		t.Fatal("an unrelated error must not be treated as a missing session")
	}
}
