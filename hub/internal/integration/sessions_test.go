package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
)

// Server-side sessions through the real HTTP surface (task T011).
//
// These drive the published API: signing in establishes a session, requests
// keep it alive, a timed-out or ended session is refused with the wording the
// clients show their users, and a credential minted before this feature
// existed is refused too — the one-time re-sign-in at upgrade.
//
// Only the activity clock is reached behind the API, by writing the store
// directly. That is deliberate: the product has no back door for making a
// session look idle, and it must not grow one for tests.

const (
	logoutPath        = "/api/auth/logout"
	authSessionsPath  = "/api/auth/sessions"
	signOutOthersPath = "/api/auth/sessions/sign-out-others"
	sessionsAdminUser = "admin"
)

// adminUserID reads the harness administrator's id from the store.
func adminUserID(t *testing.T, h *TestHarness) string {
	t.Helper()
	user, err := h.Store.GetUserByUsername(sessionsAdminUser)
	if err != nil {
		t.Fatalf("get admin user: %v", err)
	}
	return user.ID
}

// liveSessions returns a user's live session rows.
func liveSessions(t *testing.T, h *TestHarness, userID string) []model.Session {
	t.Helper()
	sessions, err := h.Store.ListUserSessions(userID, false, time.Now().UTC())
	if err != nil {
		t.Fatalf("list sessions for %s: %v", userID, err)
	}
	return sessions
}

// sessionByID reads one session row back.
func sessionByID(t *testing.T, h *TestHarness, id string) *model.Session {
	t.Helper()
	sess, err := h.Store.GetSession(id)
	if err != nil {
		t.Fatalf("get session %s: %v", id, err)
	}
	return sess
}

// ageSession back-dates a session's activity clock so the next request finds
// it idle. There is no API for this, and there should not be one.
func ageSession(t *testing.T, h *TestHarness, id string, by time.Duration) {
	t.Helper()
	stamp := time.Now().UTC().Add(-by).Format(sqliteStampFormat)
	if _, err := h.Store.DB().Exec(
		`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, stamp, id,
	); err != nil {
		t.Fatalf("age session %s: %v", id, err)
	}
}

// sessionIDOf reads the session a token is bound to.
func sessionIDOf(t *testing.T, h *TestHarness, token string) string {
	t.Helper()
	claims, err := auth.ValidateToken(h.JWTSecret, token)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	return claims.SessionID
}

// setSessionPolicy applies the session limits through the admin settings API.
func setSessionPolicy(t *testing.T, h *TestHarness, adminToken string, idleMinutes, maxHours int) {
	t.Helper()
	resp := h.HTTPPut(t, hubSettingsPath, map[string]interface{}{
		"session_idle_minutes": idleMinutes,
		"session_max_hours":    maxHours,
	}, adminToken)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "put session policy")
}

// A completed sign-in records a session, binds the credentials it hands out to
// it, and the session is usable straight away (FR-001, FR-002).
func TestSessions_SignInCreatesSessionAndBindsTokens(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)
	userID := adminUserID(t, h)

	sessions := liveSessions(t, h, userID)
	if len(sessions) != 1 {
		t.Fatalf("expected one live session after signing in, got %d", len(sessions))
	}
	sess := sessions[0]

	if got := sessionIDOf(t, h, adminToken); got != sess.ID {
		t.Fatalf("the access token is bound to %q, want the session it created (%q)", got, sess.ID)
	}
	if sess.Kind != model.SessionKindWeb {
		t.Fatalf("kind = %q, want %q for a browser client", sess.Kind, model.SessionKindWeb)
	}
	if sess.ExpiresAt == nil {
		t.Fatal("expected an absolute expiry from the default policy")
	}
	if until := time.Until(*sess.ExpiresAt); until < 11*time.Hour || until > 13*time.Hour {
		t.Fatalf("absolute expiry is %s away, want roughly the 12-hour default", until)
	}
	if sess.EndedAt != nil {
		t.Fatalf("a session in use must be live, got ended at %s", sess.EndedAt)
	}

	assertResponse(t, h.HTTPGet(t, mePath, adminToken), "authenticated request", http.StatusOK, "")

	// The session's own idle deadline is derived, not stored, so the listing
	// helper is what surfaces it; the row itself only carries last-seen.
	if sessionByID(t, h, sess.ID).LastSeenAt.IsZero() {
		t.Fatal("expected the session to carry an activity timestamp")
	}
}

// A session left unused past the idle limit is refused on its next request,
// marked with the cause and audited (FR-003, FR-005).
func TestSessions_IdleSessionRefusedOnNextRequest(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)
	setSessionPolicy(t, h, adminToken, 1, 12)

	viewerID, tempPassword := createViewer(t, h, adminToken, "idleviewer")
	access, _, _ := completeFirstSignIn(t, h, "idleviewer", tempPassword)

	sessions := liveSessions(t, h, viewerID)
	if len(sessions) != 1 {
		t.Fatalf("expected one live session for the viewer, got %d", len(sessions))
	}
	sid := sessions[0].ID

	// Still fine while it is being used.
	assertResponse(t, requestWithCookies(t, h, "GET", mePath, access),
		"request before the idle limit", http.StatusOK, "")

	ageSession(t, h, sid, 2*time.Minute)
	assertResponse(t, requestWithCookies(t, h, "GET", mePath, access),
		"request after the idle limit", http.StatusUnauthorized, session.MsgExpired)

	ended := sessionByID(t, h, sid)
	if ended.EndReason != model.SessionEndExpiredIdle {
		t.Fatalf("end reason = %q, want %q", ended.EndReason, model.SessionEndExpiredIdle)
	}
	if ended.EndedBy != nil {
		t.Fatalf("an expiry is the hub's own decision; ended_by = %v, want nil", ended.EndedBy)
	}

	action := model.AuditSessionExpired
	entries, _, err := h.Store.ListAuditLogs(model.AuditFilter{
		UserID: &viewerID, Action: &action, Limit: 100,
	})
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one %s entry, got %d", action, len(entries))
	}

	// The admin's own session is untouched by another user's expiry.
	assertResponse(t, h.HTTPGet(t, mePath, adminToken), "admin request", http.StatusOK, "")
}

// A credential minted before server-side sessions existed carries no session
// and is refused on both the request path and the refresh path, which is the
// one-time re-sign-in at upgrade (FR-002, R10).
func TestSessions_PreUpgradeTokenRefused(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)
	userID := adminUserID(t, h)

	user, err := h.Store.GetUserByID(userID)
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	legacyAccess, legacyRefresh, err := auth.GenerateTokenPair(
		h.JWTSecret, user.ID, string(user.Role), user.TokenGeneration,
	)
	if err != nil {
		t.Fatalf("generate a pre-upgrade token pair: %v", err)
	}
	if sessionIDOf(t, h, legacyAccess) != "" {
		t.Fatal("a pre-upgrade token must carry no session id")
	}

	assertResponse(t, h.HTTPGet(t, mePath, legacyAccess),
		"pre-upgrade access token", http.StatusUnauthorized, session.MsgExpired)
	assertResponse(t, h.HTTPPost(t, refreshPath, model.RefreshRequest{RefreshToken: legacyRefresh}, ""),
		"pre-upgrade refresh token", http.StatusUnauthorized, session.MsgExpired)

	// The session-bound token issued by the same sign-in still works, so the
	// refusal is about the missing session and nothing else.
	assertResponse(t, h.HTTPGet(t, mePath, adminToken), "session-bound token", http.StatusOK, "")
}

// Signing out ends the session, so the refresh token that shared it stops
// working immediately rather than outliving the sign-out (FR-011).
func TestSessions_LogoutEndsSessionAndRefreshToken(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)

	viewerID, tempPassword := createViewer(t, h, adminToken, "leaver")
	access, refresh, _ := completeFirstSignIn(t, h, "leaver", tempPassword)
	sid := sessionIDOf(t, h, access.Value)
	if sid == "" {
		t.Fatal("the viewer's token carries no session id")
	}

	assertResponse(t, requestWithCookies(t, h, "POST", logoutPath, access),
		"sign out", http.StatusNoContent, "")

	ended := sessionByID(t, h, sid)
	if ended.EndReason != model.SessionEndLogout || ended.EndedAt == nil {
		t.Fatalf("session not ended by sign-out: reason %q ended_at %v", ended.EndReason, ended.EndedAt)
	}
	if ended.EndedBy == nil || *ended.EndedBy != viewerID {
		t.Fatalf("ended by = %v, want the user themselves (%q)", ended.EndedBy, viewerID)
	}
	if got := len(liveSessions(t, h, viewerID)); got != 0 {
		t.Fatalf("expected no live sessions after signing out, got %d", got)
	}

	assertResponse(t, requestWithCookies(t, h, "POST", refreshPath, refresh),
		"refresh after sign-out", http.StatusUnauthorized, session.MsgEnded)
}

// A refresh rotates inside the same session and never buys it more absolute
// time (FR-002).
func TestSessions_RefreshStaysInSession(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)
	sid := sessionIDOf(t, h, adminToken)
	before := sessionByID(t, h, sid)

	_, refreshToken, err := auth.GenerateSessionTokenPair(
		h.JWTSecret, adminUserID(t, h), string(model.RoleAdmin),
		mustTokenGeneration(t, h), sid,
	)
	if err != nil {
		t.Fatalf("mint a refresh token for the live session: %v", err)
	}

	resp := h.HTTPPost(t, refreshPath, model.RefreshRequest{RefreshToken: refreshToken}, "")
	defer resp.Body.Close()
	requireStatusOK(t, resp, "refresh")

	var pair model.TokenPair
	decodeJSON(t, resp, &pair, "refresh")
	if got := sessionIDOf(t, h, pair.AccessToken); got != sid {
		t.Fatalf("the rotated token is bound to %q, want the same session %q", got, sid)
	}

	after := sessionByID(t, h, sid)
	if before.ExpiresAt == nil || after.ExpiresAt == nil || !after.ExpiresAt.Equal(*before.ExpiresAt) {
		t.Fatalf("absolute expiry moved from %v to %v on refresh", before.ExpiresAt, after.ExpiresAt)
	}
}

// mustTokenGeneration reads the admin's current token generation.
func mustTokenGeneration(t *testing.T, h *TestHarness) int {
	t.Helper()
	user, err := h.Store.GetUserByID(adminUserID(t, h))
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	return user.TokenGeneration
}

// The self-service listing is what a signed-in person sees about their own
// sessions: their own rows only, the one they are calling from marked, and the
// deadline the panel counts down to (FR-012).
func TestSessions_SelfListingShowsCurrentSession(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)
	sid := sessionIDOf(t, h, adminToken)

	viewerID, tempPassword := createViewer(t, h, adminToken, "listviewer")
	if _, _, secret := completeFirstSignIn(t, h, "listviewer", tempPassword); secret == "" {
		t.Fatal("the viewer never completed a sign-in")
	}

	resp := h.HTTPGet(t, authSessionsPath, adminToken)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "list my sessions")

	var listing model.SessionListResponse
	decodeJSON(t, resp, &listing, "my sessions")
	if len(listing.Sessions) != 1 {
		t.Fatalf("expected only the caller's own session, got %d: %+v",
			len(listing.Sessions), listing.Sessions)
	}

	row := listing.Sessions[0]
	if row.ID != sid {
		t.Fatalf("listed session %q, want the calling session %q", row.ID, sid)
	}
	if !row.Current {
		t.Fatal("the session the request arrived on must be marked current")
	}
	if row.Kind != model.SessionKindWeb || row.IP == "" {
		t.Fatalf("row = %+v, want a web session with the client's address", row)
	}
	if row.IdleDeadlineAt == nil {
		t.Fatal("expected the derived idle deadline on a live session")
	}
	if until := time.Until(*row.IdleDeadlineAt); until <= 0 || until > 16*time.Minute {
		t.Fatalf("idle deadline is %s away, want it inside the 15-minute default", until)
	}
	if row.ExpiresAt == nil {
		t.Fatal("expected the absolute expiry stamped at sign-in")
	}

	// The viewer's session belongs to the viewer, not to the caller.
	if got := len(liveSessions(t, h, viewerID)); got != 1 {
		t.Fatalf("expected the viewer to hold one live session, got %d", got)
	}
}

// Signing out everywhere else keeps the caller signed in and ends the rest,
// through the real HTTP surface (FR-012).
func TestSessions_SignOutOthersKeepsTheCallingSession(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)
	callerSID := sessionIDOf(t, h, adminToken)

	viewerID, tempPassword := createViewer(t, h, adminToken, "otherviewer")
	viewerAccess, _, _ := completeFirstSignIn(t, h, "otherviewer", tempPassword)
	viewerSID := sessionIDOf(t, h, viewerAccess.Value)

	resp := h.HTTPPost(t, signOutOthersPath, nil, adminToken)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "sign out other sessions")

	var counts model.EndedCountResponse
	decodeJSON(t, resp, &counts, "sign out other sessions")
	if counts.Ended != 0 {
		t.Fatalf("ended = %d, want 0 — the admin has no other session", counts.Ended)
	}

	// The caller keeps working, and another account's session is none of its
	// business.
	assertResponse(t, h.HTTPGet(t, mePath, adminToken), "calling session", http.StatusOK, "")
	if sessionByID(t, h, callerSID).EndedAt != nil {
		t.Fatal("the calling session must survive")
	}
	if sessionByID(t, h, viewerSID).EndedAt != nil {
		t.Fatalf("another user's session was ended; viewer %s", viewerID)
	}
}
