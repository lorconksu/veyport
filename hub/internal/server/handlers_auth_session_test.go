package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
)

// T010 — the session lifecycle as the authentication paths actually run it.
//
// The helper tests pin what each piece does; these pin that sign-in, the
// middleware, refresh and sign-out call them at the right moment and in the
// right order. Every case drives real handlers and asserts on the persisted
// session row and the audit trail, so a path that forgets to create, check or
// end a session fails here rather than in production.
//
// The handlers are invoked directly rather than through s.routes() wherever a
// per-IP rate limiter sits in front of them (the sign-in stages and refresh),
// exactly as the lockout tests do. Requests that only need authenticating go
// through the router, because the middleware is what is under test.

// signInWith completes the code stage for a user and returns the tokens it
// issued together with the session they are bound to.
//
// userAgent is what the client announces, which is what decides whether the
// session is recorded as a browser or as the CLI.
func signInWith(t *testing.T, s *Server, user *model.User, totpSecret, userAgent string) (accessToken, refreshToken, sid string) {
	t.Helper()
	totpToken := primaryLoginTOTPToken(t, s, user.Username, lockoutTestPassword)

	req := httptest.NewRequest("POST", testLoginTOTPPath, mustJSON(t, model.LoginTOTPRequest{
		TOTPToken: totpToken,
		Code:      validTOTPCode(t, totpSecret),
	}))
	req.RemoteAddr = "198.51.100.4:44321"
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	rec := httptest.NewRecorder()
	s.handleLoginTOTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code stage: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.AuthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode auth response: %v", err)
	}
	return resp.AccessToken, resp.RefreshToken, sidOf(t, s, resp.AccessToken)
}

// sidOf reads the session id a token is bound to.
func sidOf(t *testing.T, s *Server, token string) string {
	t.Helper()
	claims, err := auth.ValidateToken(s.jwtSecret, token)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	return claims.SessionID
}

// signedInUser creates a TOTP-enabled account and signs it in as a browser.
func signedInUser(t *testing.T, s *Server, username string) (user *model.User, accessToken, refreshToken, sid string) {
	t.Helper()
	user = newLocalUser(t, s, username, lockoutTestPassword)
	secret := enableTOTPForUser(t, s, user)
	accessToken, refreshToken, sid = signInWith(t, s, user, secret, sessionTestUserAgent)
	return user, accessToken, refreshToken, sid
}

// authedGet issues an authenticated GET through the full router, which is what
// puts the authentication middleware in the path.
func authedGet(t *testing.T, s *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}

// postRefresh posts a refresh token straight at the handler, past the limiter.
func postRefresh(t *testing.T, s *Server, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", testRefreshPath, mustJSON(t, model.RefreshRequest{
		RefreshToken: refreshToken,
	}))
	rec := httptest.NewRecorder()
	s.handleRefresh(rec, req)
	return rec
}

// assertUnauthorized checks a 401 carrying an exact message.
func assertUnauthorized(t *testing.T, rec *httptest.ResponseRecorder, want, label string) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("%s: expected 401, got %d: %s", label, rec.Code, rec.Body.String())
	}
	if got := errorBody(t, rec); got != want {
		t.Fatalf("%s: expected %q, got %q", label, want, got)
	}
}

// (a) A completed code stage records the session, binds both tokens to it and
// audits its creation. The client's own announcement decides the kind.
func TestSession_LoginTOTPCreatesSession(t *testing.T) {
	for _, tc := range []struct {
		name      string
		userAgent string
		wantKind  string
	}{
		{"browser", sessionTestUserAgent, model.SessionKindWeb},
		{"cli", sessionTestCLIAgent, model.SessionKindCLI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, clk := sessionServer(t)
			setSessionPolicy(t, s, 15, 12)
			user := newLocalUser(t, s, "signin", lockoutTestPassword)
			secret := enableTOTPForUser(t, s, user)

			accessToken, refreshToken, sid := signInWith(t, s, user, secret, tc.userAgent)
			if sid == "" {
				t.Fatal("the access token carries no session id")
			}
			if got := sidOf(t, s, refreshToken); got != sid {
				t.Fatalf("refresh token bound to %q, want %q", got, sid)
			}

			stored := reloadSession(t, s, sid)
			if stored.UserID != user.ID || stored.Kind != tc.wantKind {
				t.Fatalf("session = user %q kind %q, want %q/%q",
					stored.UserID, stored.Kind, user.ID, tc.wantKind)
			}
			if stored.IP != "198.51.100.4" {
				t.Fatalf("ip = %q, want the client's address", stored.IP)
			}
			if stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(clk.now().Add(12*time.Hour)) {
				t.Fatalf("expires at = %v, want %s", stored.ExpiresAt, clk.now().Add(12*time.Hour))
			}

			entries := auditEntriesFor(t, s, user.ID, model.AuditSessionCreated)
			if len(entries) != 1 {
				t.Fatalf("expected one %s entry, got %d", model.AuditSessionCreated, len(entries))
			}
			if detail := decodeSessionDetail(t, entries[0]); detail.SessionID != sid {
				t.Fatalf("audit names session %q, want %q", detail.SessionID, sid)
			}

			if rec := authedGet(t, s, testMePath, accessToken); rec.Code != http.StatusOK {
				t.Fatalf("the freshly issued token was refused: %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// (b) A first sign-in completes at TOTP enrolment rather than at the code
// stage, so that path has to establish a session too.
func TestSession_FirstLoginTOTPEnableCreatesSession(t *testing.T) {
	s, _ := sessionServer(t)
	setSessionPolicy(t, s, 15, 12)

	user := newLocalUser(t, s, "firstrun", lockoutTestPassword)
	secret, err := auth.GenerateTOTPSecret(user.Username, "Veyport")
	if err != nil {
		t.Fatalf("generate totp secret: %v", err)
	}
	plaintext := secret.Secret()
	if err := s.store.UpdateUserTOTP(user.ID, &plaintext, false); err != nil {
		t.Fatalf("store totp secret: %v", err)
	}

	setupToken, err := auth.GenerateSetupToken(s.jwtSecret, user.ID, string(user.Role))
	if err != nil {
		t.Fatalf("generate setup token: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/auth/totp/enable", mustJSON(t, model.TOTPEnableRequest{
		Code: validTOTPCode(t, plaintext),
	}))
	req.Header.Set("Authorization", testBearerPrefix+setupToken)
	req.Header.Set("User-Agent", sessionTestCLIAgent)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("totp enable: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.AuthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode auth response: %v", err)
	}

	sid := sidOf(t, s, resp.AccessToken)
	if sid == "" {
		t.Fatal("the first-login token carries no session id")
	}
	if got := sidOf(t, s, resp.RefreshToken); got != sid {
		t.Fatalf("refresh token bound to %q, want %q", got, sid)
	}
	if stored := reloadSession(t, s, sid); stored.Kind != model.SessionKindCLI {
		t.Fatalf("kind = %q, want %q", stored.Kind, model.SessionKindCLI)
	}
	if got := len(auditEntriesFor(t, s, user.ID, model.AuditSessionCreated)); got != 1 {
		t.Fatalf("expected one %s entry, got %d", model.AuditSessionCreated, got)
	}
}

// (c) Requests keep the session alive, but the activity clock is written at
// most once a minute however busy the client is (FR-003).
func TestSession_RequestsTouchLastSeenThrottled(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 12)
	_, accessToken, _, sid := signedInUser(t, s, "busy")
	signedInAt := reloadSession(t, s, sid).LastSeenAt

	clk.advance(61 * time.Second)
	if rec := authedGet(t, s, testMePath, accessToken); rec.Code != http.StatusOK {
		t.Fatalf("request refused: %d: %s", rec.Code, rec.Body.String())
	}
	touched := reloadSession(t, s, sid).LastSeenAt
	if !touched.Equal(clk.now()) {
		t.Fatalf("last seen = %s, want %s", touched, clk.now())
	}
	if !touched.After(signedInAt) {
		t.Fatal("a request must move the activity clock forward")
	}

	clk.advance(30 * time.Second)
	if rec := authedGet(t, s, testMePath, accessToken); rec.Code != http.StatusOK {
		t.Fatalf("second request refused: %d: %s", rec.Code, rec.Body.String())
	}
	if got := reloadSession(t, s, sid).LastSeenAt; !got.Equal(touched) {
		t.Fatalf("last seen moved to %s within the throttle window (was %s)", got, touched)
	}
}

// (d) An idle session is refused with the expiry wording, marked with the
// cause, and audited exactly once however many requests notice (FR-005).
func TestSession_IdleExpiryRefusesAndAuditsOnce(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 1, 12)
	user, accessToken, _, sid := signedInUser(t, s, "sleepy")

	clk.advance(2 * time.Minute)
	assertUnauthorized(t, authedGet(t, s, testMePath, accessToken), session.MsgExpired, "idle session")

	stored := reloadSession(t, s, sid)
	if stored.EndReason != model.SessionEndExpiredIdle {
		t.Fatalf("end reason = %q, want %q", stored.EndReason, model.SessionEndExpiredIdle)
	}
	if got := len(auditEntriesFor(t, s, user.ID, model.AuditSessionExpired)); got != 1 {
		t.Fatalf("expected one %s entry, got %d", model.AuditSessionExpired, got)
	}

	// A second request is refused with the same wording — the session ran out
	// of time, it was not taken away — and adds no second audit entry.
	assertUnauthorized(t, authedGet(t, s, testMePath, accessToken), session.MsgExpired, "second request")
	if got := len(auditEntriesFor(t, s, user.ID, model.AuditSessionExpired)); got != 1 {
		t.Fatalf("expected still one %s entry, got %d", model.AuditSessionExpired, got)
	}
}

// (e) A session kept busy right up to its absolute expiry still ends there:
// activity postpones the idle limit, never the absolute one.
func TestSession_AbsoluteExpiryRefusesBusySession(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 1)
	user, accessToken, _, sid := signedInUser(t, s, "marathon")

	for minutes := 10; minutes <= 50; minutes += 10 {
		clk.advance(10 * time.Minute)
		if rec := authedGet(t, s, testMePath, accessToken); rec.Code != http.StatusOK {
			t.Fatalf("request at +%dm refused early: %d: %s", minutes, rec.Code, rec.Body.String())
		}
	}

	clk.advance(11 * time.Minute)
	assertUnauthorized(t, authedGet(t, s, testMePath, accessToken), session.MsgExpired, "absolute expiry")

	if got := reloadSession(t, s, sid).EndReason; got != model.SessionEndExpiredAbsolute {
		t.Fatalf("end reason = %q, want %q", got, model.SessionEndExpiredAbsolute)
	}
	entries := auditEntriesFor(t, s, user.ID, model.AuditSessionExpired)
	if len(entries) != 1 {
		t.Fatalf("expected one %s entry, got %d", model.AuditSessionExpired, len(entries))
	}
	if detail := decodeSessionDetail(t, entries[0]); detail.Reason != "absolute" {
		t.Fatalf("audit reason = %q, want absolute", detail.Reason)
	}
}

// (f) A refresh rotates inside the same session, counts as activity, and never
// buys the session more absolute time (FR-002).
func TestSession_RefreshStaysInSessionAndKeepsExpiry(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 12)
	_, _, refreshToken, sid := signedInUser(t, s, "rotator")
	before := reloadSession(t, s, sid)

	clk.advance(61 * time.Second)
	rec := postRefresh(t, s, refreshToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var pair model.TokenPair
	if err := json.Unmarshal(rec.Body.Bytes(), &pair); err != nil {
		t.Fatalf("decode token pair: %v", err)
	}
	if got := sidOf(t, s, pair.AccessToken); got != sid {
		t.Fatalf("new access token bound to %q, want the same session %q", got, sid)
	}
	if got := sidOf(t, s, pair.RefreshToken); got != sid {
		t.Fatalf("new refresh token bound to %q, want the same session %q", got, sid)
	}

	after := reloadSession(t, s, sid)
	if before.ExpiresAt == nil || after.ExpiresAt == nil || !after.ExpiresAt.Equal(*before.ExpiresAt) {
		t.Fatalf("absolute expiry moved from %v to %v on refresh", before.ExpiresAt, after.ExpiresAt)
	}
	if !after.LastSeenAt.Equal(clk.now()) {
		t.Fatalf("last seen = %s, want %s — a refresh is activity", after.LastSeenAt, clk.now())
	}

	// Once the session has gone idle the refresh token is worth nothing: it
	// cannot resurrect a session that timed out.
	clk.advance(16 * time.Minute)
	assertUnauthorized(t, postRefresh(t, s, pair.RefreshToken), session.MsgExpired, "refresh after idle")
}

// (g) A token minted before this feature carries no session and is refused on
// both the middleware and the refresh path — the one-time re-sign-in at
// upgrade (FR-002, R10).
func TestSession_LegacyTokensWithoutSessionAreRefused(t *testing.T) {
	s, _ := sessionServer(t)
	user, _, _, _ := signedInUser(t, s, "upgrader")
	current := reloadUser(t, s, user.ID)

	legacyAccess, legacyRefresh, err := auth.GenerateTokenPair(
		s.jwtSecret, current.ID, string(current.Role), current.TokenGeneration,
	)
	if err != nil {
		t.Fatalf("generate legacy token pair: %v", err)
	}

	assertUnauthorized(t, authedGet(t, s, testMePath, legacyAccess), session.MsgExpired, "legacy access token")
	assertUnauthorized(t, postRefresh(t, s, legacyRefresh), session.MsgExpired, "legacy refresh token")
}

// (h) API tokens are not sessions: they keep their own expiry and revocation
// and are untouched by any of the session limits (FR-006).
func TestSession_APITokensUnaffectedByLimits(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 1, 1)
	user := newLocalUser(t, s, "automation", lockoutTestPassword)

	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if err := s.store.CreateAPIToken(&model.APIToken{
		ID: uuid.NewString(), UserID: user.ID, Name: "robot",
		TokenHash: hash, TokenPrefix: prefix,
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}

	clk.advance(48 * time.Hour)
	if rec := authedGet(t, s, testMePath, raw); rec.Code != http.StatusOK {
		t.Fatalf("api token refused after the session limits elapsed: %d: %s", rec.Code, rec.Body.String())
	}
	if got := len(auditEntriesFor(t, s, user.ID, model.AuditSessionExpired)); got != 0 {
		t.Fatalf("an api token must not produce session expiry events, got %d", got)
	}
}

// (i) Both limits set to zero turn the timers off: the session stays usable
// until something ends it (FR-004).
func TestSession_LimitsDisabledNeverExpire(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 0, 0)
	_, accessToken, refreshToken, sid := signedInUser(t, s, "eternal")

	if reloadSession(t, s, sid).ExpiresAt != nil {
		t.Fatal("a session created with no absolute limit must have no expiry")
	}

	clk.advance(48 * time.Hour)
	if rec := authedGet(t, s, testMePath, accessToken); rec.Code != http.StatusOK {
		t.Fatalf("request refused with the limits disabled: %d: %s", rec.Code, rec.Body.String())
	}
	if rec := postRefresh(t, s, refreshToken); rec.Code != http.StatusOK {
		t.Fatalf("refresh refused with the limits disabled: %d: %s", rec.Code, rec.Body.String())
	}
}

// (j) The absolute limit is stamped once, at sign-in: changing the policy
// afterwards leaves existing sessions where they are and applies to the next
// sign-in (FR-004).
func TestSession_AbsoluteLimitChangeAppliesToNewSessionsOnly(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 12)

	_, _, _, existingSID := signedInUser(t, s, "before")
	stamped := reloadSession(t, s, existingSID).ExpiresAt
	if stamped == nil {
		t.Fatal("expected an absolute expiry on the first session")
	}

	setSessionPolicy(t, s, 15, 1)
	if got := reloadSession(t, s, existingSID).ExpiresAt; got == nil || !got.Equal(*stamped) {
		t.Fatalf("existing expiry moved from %s to %v after a policy change", stamped, got)
	}

	// A separate account, because the one-time-code replay guard refuses the
	// same code twice inside its window.
	_, _, _, freshSID := signedInUser(t, s, "after")
	want := clk.now().Add(time.Hour)
	if got := reloadSession(t, s, freshSID).ExpiresAt; got == nil || !got.Equal(want) {
		t.Fatalf("new session expiry = %v, want %s from the new policy", got, want)
	}
}

// Signing out ends the server-side session, so the refresh token that shared
// it dies with the access token rather than outliving it (FR-011).
func TestSession_LogoutEndsTheSession(t *testing.T) {
	s, _ := sessionServer(t)
	user, accessToken, refreshToken, sid := signedInUser(t, s, "leaver")

	req := httptest.NewRequest("POST", testLogoutPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	stored := reloadSession(t, s, sid)
	if stored.EndReason != model.SessionEndLogout || stored.EndedAt == nil {
		t.Fatalf("session not ended by logout: reason %q ended_at %v", stored.EndReason, stored.EndedAt)
	}
	if stored.EndedBy == nil || *stored.EndedBy != user.ID {
		t.Fatalf("ended by = %v, want the user themselves (%q)", stored.EndedBy, user.ID)
	}

	assertUnauthorized(t, postRefresh(t, s, refreshToken), session.MsgEnded, "refresh after logout")
}

// A session ended by someone else says so, which is what tells a user they
// were signed out rather than timed out (FR-009).
func TestSession_RevokedSessionSaysEnded(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 12)
	user, accessToken, _, sid := signedInUser(t, s, "revoked")

	if _, err := s.store.EndSession(sid, model.SessionEndRevokedAdmin, &user.ID, clk.now()); err != nil {
		t.Fatalf("end session: %v", err)
	}
	assertUnauthorized(t, authedGet(t, s, testMePath, accessToken), session.MsgEnded, "revoked session")
}

// One session of a user going away leaves the others alone (FR-009).
func TestSession_EndingOneLeavesOthersWorking(t *testing.T) {
	s, clk := sessionServer(t)
	setSessionPolicy(t, s, 15, 12)
	user, firstToken, _, firstSID := signedInUser(t, s, "twoplaces")
	secondToken, _, _ := sessionTokenPair(t, s, user.ID)

	if _, err := s.store.EndSession(firstSID, model.SessionEndRevokedAdmin, &user.ID, clk.now()); err != nil {
		t.Fatalf("end session: %v", err)
	}

	assertUnauthorized(t, authedGet(t, s, testMePath, firstToken), session.MsgEnded, "ended session")
	if rec := authedGet(t, s, testMePath, secondToken); rec.Code != http.StatusOK {
		t.Fatalf("the other session was refused: %d: %s", rec.Code, rec.Body.String())
	}
}

// The request context carries the session the caller is using, which is what
// lets a handler mark "this session" in a listing.
func TestSession_ContextCarriesSessionID(t *testing.T) {
	s, _ := sessionServer(t)
	user := newLocalUser(t, s, "ctx", lockoutTestPassword)
	accessToken, _, sid := sessionTokenPair(t, s, user.ID)

	var seen string
	handler := s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			seen = SessionIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if seen != sid {
		t.Fatalf("context session id = %q, want %q", seen, sid)
	}
}

// Setup and one-time-code tokens have no session and must keep working on
// their own endpoints — only access tokens are session-checked.
func TestSession_SetupTokensAreNotSessionChecked(t *testing.T) {
	s, _ := sessionServer(t)
	user := newLocalUser(t, s, "enrolling", lockoutTestPassword)

	setupToken, err := auth.GenerateSetupToken(s.jwtSecret, user.ID, string(user.Role))
	if err != nil {
		t.Fatalf("generate setup token: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/auth/totp/setup", nil)
	req.Header.Set("Authorization", testBearerPrefix+setupToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("setup token refused: %d: %s", rec.Code, rec.Body.String())
	}
}
