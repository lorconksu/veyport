package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// Account-lockout handler tests (tasks T011). Every case drives the real
// handler and asserts on the persisted account state, so a regression that
// evaluates credentials before the lock check, or that miscounts, fails here.
//
// The handlers are invoked directly rather than through s.routes() on purpose:
// the per-IP rate limiters in front of /api/auth/login (10/min) and
// /api/auth/login/totp (3/min) would reject a threshold-length run of attempts
// long before the account lock could be observed. The limiters are unchanged by
// this feature and are covered by their own tests.

const (
	lockedBodyMessage    = "account temporarily locked — try again later"
	lockoutTestPassword  = "LockoutP@ssw0rd!1"
	lockoutWrongPassword = "wrong-password"
)

// testClock is a manually advanced clock safe for use under -race.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// lockoutServer builds a test server whose clock the test controls.
func lockoutServer(t *testing.T) (*Server, *testClock) {
	t.Helper()
	s := testServer(t)
	clk := newTestClock()
	s.SetClock(clk.now)
	return s, clk
}

// setLockoutPolicy writes the three policy keys through the config store.
func setLockoutPolicy(t *testing.T, s *Server, threshold, windowMinutes, durationMinutes int) {
	t.Helper()
	values := map[string]string{
		lockout.KeyThreshold:       strconv.Itoa(threshold),
		lockout.KeyWindowMinutes:   strconv.Itoa(windowMinutes),
		lockout.KeyDurationMinutes: strconv.Itoa(durationMinutes),
	}
	for key, value := range values {
		if err := s.store.SetConfig(key, value); err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}
}

// newLocalUser creates a password-authenticated user directly in the store.
func newLocalUser(t *testing.T, s *Server, username, password string) *model.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.NewString(),
		Username:     username,
		Email:        username + "@test.com",
		PasswordHash: hash,
		Role:         model.RoleViewer,
	}
	if err := s.store.CreateUser(user); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	return user
}

// enableTOTPForUser stores a plaintext TOTP secret and marks TOTP enabled,
// returning the secret so the test can generate valid codes.
func enableTOTPForUser(t *testing.T, s *Server, user *model.User) string {
	t.Helper()
	key, err := auth.GenerateTOTPSecret(user.Username, "Veyport")
	if err != nil {
		t.Fatalf("generate totp secret: %v", err)
	}
	secret := key.Secret()
	if err := s.store.UpdateUserTOTP(user.ID, &secret, true); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	return secret
}

// attemptLogin posts a password-stage login attempt straight at the handler.
func attemptLogin(t *testing.T, s *Server, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", testLoginPath, mustJSON(t, model.LoginRequest{
		Username: username,
		Password: password,
	}))
	rec := httptest.NewRecorder()
	s.handleLogin(rec, req)
	return rec
}

// attemptTOTP posts a code-stage login attempt straight at the handler.
func attemptTOTP(t *testing.T, s *Server, totpToken, code string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", testLoginTOTPPath, mustJSON(t, model.LoginTOTPRequest{
		TOTPToken: totpToken,
		Code:      code,
	}))
	rec := httptest.NewRecorder()
	s.handleLoginTOTP(rec, req)
	return rec
}

// reloadUser reads the persisted account state back.
func reloadUser(t *testing.T, s *Server, userID string) *model.User {
	t.Helper()
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	return user
}

// primaryLoginTOTPToken completes the password stage and returns the TOTP token.
func primaryLoginTOTPToken(t *testing.T, s *Server, username, password string) string {
	t.Helper()
	rec := attemptLogin(t, s, username, password)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 from password stage, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.LoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if resp.TOTPToken == "" {
		t.Fatal("expected a totp token from the password stage")
	}
	return resp.TOTPToken
}

func assertLockedResponse(t *testing.T, rec *httptest.ResponseRecorder, label string) {
	t.Helper()
	if rec.Code != http.StatusLocked {
		t.Fatalf("%s: expected 423, got %d: %s", label, rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: decode body: %v", label, err)
	}
	if body["error"] != lockedBodyMessage {
		t.Fatalf("%s: expected %q, got %q", label, lockedBodyMessage, body["error"])
	}
}

// (a) A locked account is refused identically whether the supplied password is
// right or wrong — the refusal must not become a credential oracle (SC-002).
func TestLockout_LockedRefusalIdenticalForRightAndWrongPassword(t *testing.T) {
	s, _ := lockoutServer(t)
	setLockoutPolicy(t, s, 5, 15, 15)
	user := newLocalUser(t, s, "alice", lockoutTestPassword)

	for i := 1; i <= 5; i++ {
		rec := attemptLogin(t, s, user.Username, lockoutWrongPassword)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: expected 401, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	correct := attemptLogin(t, s, user.Username, lockoutTestPassword)
	assertLockedResponse(t, correct, "correct password while locked")

	wrong := attemptLogin(t, s, user.Username, lockoutWrongPassword)
	assertLockedResponse(t, wrong, "wrong password while locked")

	if correct.Body.String() != wrong.Body.String() {
		t.Fatalf("refusal bodies differ:\n correct=%q\n wrong  =%q", correct.Body.String(), wrong.Body.String())
	}
	if correct.Header().Get(testContentType) != wrong.Header().Get(testContentType) {
		t.Fatalf("refusal content types differ: %q vs %q",
			correct.Header().Get(testContentType), wrong.Header().Get(testContentType))
	}
}

// (b) A refused-while-locked attempt must not touch the failure counter: the
// counter is the sentinel proving the credential path was never entered.
func TestLockout_RefusedAttemptDoesNotChangeCounter(t *testing.T) {
	s, _ := lockoutServer(t)
	setLockoutPolicy(t, s, 5, 15, 15)
	user := newLocalUser(t, s, "bob", lockoutTestPassword)

	for i := 0; i < 5; i++ {
		attemptLogin(t, s, user.Username, lockoutWrongPassword)
	}

	before := reloadUser(t, s, user.ID)
	if before.FailedLoginCount != 5 {
		t.Fatalf("expected count 5 after locking failure, got %d", before.FailedLoginCount)
	}
	if before.LockedUntil == nil {
		t.Fatal("expected the account to be locked")
	}

	for i := 0; i < 3; i++ {
		assertLockedResponse(t, attemptLogin(t, s, user.Username, lockoutTestPassword), "refused attempt")
	}

	after := reloadUser(t, s, user.ID)
	if after.FailedLoginCount != before.FailedLoginCount {
		t.Fatalf("refusals changed the counter: %d → %d", before.FailedLoginCount, after.FailedLoginCount)
	}
	if !after.LockedUntil.Equal(*before.LockedUntil) {
		t.Fatalf("refusals moved the lock expiry: %s → %s", before.LockedUntil, after.LockedUntil)
	}
}

// (c) A completed sign-in (password stage plus one-time code) resets the
// counter and stamps the last-login time.
func TestLockout_CompletedSignInResetsCounter(t *testing.T) {
	s, _ := lockoutServer(t)
	setLockoutPolicy(t, s, 5, 15, 15)
	user := newLocalUser(t, s, "carol", lockoutTestPassword)
	secret := enableTOTPForUser(t, s, user)

	for i := 0; i < 4; i++ {
		if rec := attemptLogin(t, s, user.Username, lockoutWrongPassword); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: expected 401, got %d", i+1, rec.Code)
		}
	}
	if got := reloadUser(t, s, user.ID).FailedLoginCount; got != 4 {
		t.Fatalf("expected count 4 before success, got %d", got)
	}

	totpToken := primaryLoginTOTPToken(t, s, user.Username, lockoutTestPassword)

	code, err := auth.GenerateValidCode(secret)
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	rec := attemptTOTP(t, s, totpToken, code)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from the code stage, got %d: %s", rec.Code, rec.Body.String())
	}

	after := reloadUser(t, s, user.ID)
	if after.FailedLoginCount != 0 {
		t.Fatalf("expected the counter to reset, got %d", after.FailedLoginCount)
	}
	if after.LastLoginAt == nil {
		t.Fatal("expected last_login_at to be stamped")
	}
	if after.LockedUntil != nil {
		t.Fatalf("expected no lock after a successful sign-in, got %s", after.LockedUntil)
	}
}

// (d) A failure arriving after the counting window has elapsed restarts the
// streak at 1 instead of accumulating toward the threshold.
func TestLockout_FailureAfterWindowRestartsCount(t *testing.T) {
	s, clk := lockoutServer(t)
	setLockoutPolicy(t, s, 5, 15, 15)
	user := newLocalUser(t, s, "dave", lockoutTestPassword)

	attemptLogin(t, s, user.Username, lockoutWrongPassword)
	attemptLogin(t, s, user.Username, lockoutWrongPassword)
	if got := reloadUser(t, s, user.ID).FailedLoginCount; got != 2 {
		t.Fatalf("expected count 2 inside the window, got %d", got)
	}

	clk.advance(16 * time.Minute)
	attemptLogin(t, s, user.Username, lockoutWrongPassword)

	after := reloadUser(t, s, user.ID)
	if after.FailedLoginCount != 1 {
		t.Fatalf("expected the count to restart at 1 after the window, got %d", after.FailedLoginCount)
	}
	if after.LockedUntil != nil {
		t.Fatalf("expected no lock, got %s", after.LockedUntil)
	}
}

// (e) Once the lock expiry passes, the correct password is accepted again with
// no administrator action.
func TestLockout_ExpiredLockAllowsSignIn(t *testing.T) {
	s, clk := lockoutServer(t)
	setLockoutPolicy(t, s, 5, 15, 15)
	user := newLocalUser(t, s, "erin", lockoutTestPassword)

	for i := 0; i < 5; i++ {
		attemptLogin(t, s, user.Username, lockoutWrongPassword)
	}
	assertLockedResponse(t, attemptLogin(t, s, user.Username, lockoutTestPassword), "while locked")

	clk.advance(16 * time.Minute)

	rec := attemptLogin(t, s, user.Username, lockoutTestPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after the lock expired, got %d: %s", rec.Code, rec.Body.String())
	}
}

// (f) The one-time-code stage counts toward the same threshold, and once the
// account locks even a valid code is refused with 423 and issues no tokens.
func TestLockout_TOTPStageLocksAndRefusesValidCode(t *testing.T) {
	s, _ := lockoutServer(t)
	setLockoutPolicy(t, s, 3, 15, 15)
	user := newLocalUser(t, s, "frank", lockoutTestPassword)
	secret := enableTOTPForUser(t, s, user)

	totpToken := primaryLoginTOTPToken(t, s, user.Username, lockoutTestPassword)

	for i := 1; i <= 3; i++ {
		rec := attemptTOTP(t, s, totpToken, "000000")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: expected 401, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	locked := reloadUser(t, s, user.ID)
	if locked.LockedUntil == nil {
		t.Fatal("expected code-stage failures to lock the account")
	}
	if locked.FailedLoginCount != 3 {
		t.Fatalf("expected count 3 from code-stage failures, got %d", locked.FailedLoginCount)
	}

	code, err := auth.GenerateValidCode(secret)
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	rec := attemptTOTP(t, s, totpToken, code)
	assertLockedResponse(t, rec, "valid code while locked")

	if findCookie(rec.Result().Cookies(), cookieAccess) != nil {
		t.Fatal("expected no access cookie on a locked code-stage refusal")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode refusal body: %v", err)
	}
	if _, ok := body["access_token"]; ok {
		t.Fatal("expected no access token on a locked code-stage refusal")
	}
}

// (g) A threshold of zero disables locking: failures are still counted and
// timestamped, but the account never locks.
func TestLockout_ThresholdZeroNeverLocks(t *testing.T) {
	s, _ := lockoutServer(t)
	setLockoutPolicy(t, s, 0, 15, 15)
	user := newLocalUser(t, s, "grace", lockoutTestPassword)

	for i := 1; i <= 10; i++ {
		rec := attemptLogin(t, s, user.Username, lockoutWrongPassword)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 with locking disabled, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	after := reloadUser(t, s, user.ID)
	if after.LockedUntil != nil {
		t.Fatalf("expected no lock with threshold 0, got %s", after.LockedUntil)
	}
	if after.FailedLoginCount != 10 {
		t.Fatalf("expected 10 counted failures, got %d", after.FailedLoginCount)
	}
	if after.LastFailedLoginAt == nil {
		t.Fatal("expected last_failed_login_at to be stamped even with locking disabled")
	}
}

// (h) An expired temporary password is a policy refusal, not a credential
// failure, so it must not move the lockout counter.
func TestLockout_ExpiredTemporaryPasswordDoesNotCount(t *testing.T) {
	s, _ := lockoutServer(t)
	setLockoutPolicy(t, s, 5, 15, 15)

	hash, err := auth.HashPassword(lockoutTestPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	expired := time.Now().UTC().Add(-time.Hour)
	user := &model.User{
		ID:                    uuid.NewString(),
		Username:              "heidi",
		Email:                 "heidi@test.com",
		PasswordHash:          hash,
		Role:                  model.RoleViewer,
		MustChangePassword:    true,
		TempPasswordExpiresAt: &expired,
	}
	if err := s.store.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	rec := attemptLogin(t, s, user.Username, lockoutTestPassword)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an expired temporary password, got %d: %s", rec.Code, rec.Body.String())
	}

	after := reloadUser(t, s, user.ID)
	if after.FailedLoginCount != 0 {
		t.Fatalf("expected the counter untouched, got %d", after.FailedLoginCount)
	}
	if after.LastFailedLoginAt != nil {
		t.Fatalf("expected no failure stamp, got %s", after.LastFailedLoginAt)
	}
	if after.LockedUntil != nil {
		t.Fatalf("expected no lock, got %s", after.LockedUntil)
	}
}

// (i) Golden: an attempt against a username that matches no account keeps
// exactly today's status and body, and creates no account state (FR-007).
func TestLockout_UnknownUsernameResponseUnchanged(t *testing.T) {
	s, _ := lockoutServer(t)
	setLockoutPolicy(t, s, 5, 15, 15)
	neighbour := newLocalUser(t, s, "ivan", lockoutTestPassword)

	before, err := s.store.UserCount()
	if err != nil {
		t.Fatalf("user count: %v", err)
	}

	rec := attemptLogin(t, s, "nobody", lockoutWrongPassword)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unknown username, got %d", rec.Code)
	}
	const goldenBody = "{\"error\":\"invalid credentials\"}\n"
	if rec.Body.String() != goldenBody {
		t.Fatalf("unknown-user body changed:\n want %q\n got  %q", goldenBody, rec.Body.String())
	}

	after, err := s.store.UserCount()
	if err != nil {
		t.Fatalf("user count: %v", err)
	}
	if after != before {
		t.Fatalf("unknown-user attempt changed the user table: %d → %d", before, after)
	}
	if _, err := s.store.GetUserByUsername("nobody"); err == nil {
		t.Fatal("unknown-user attempt must not create an account")
	}

	// The account standing next to it keeps its pristine lockout state.
	unchanged := reloadUser(t, s, neighbour.ID)
	if unchanged.FailedLoginCount != 0 || unchanged.LastFailedLoginAt != nil || unchanged.LockedUntil != nil {
		t.Fatalf("unknown-user attempt touched another account: %+v", unchanged)
	}
}

// ---------------------------------------------------------------------------
// Lock side effects: audit + notification (tasks T025 / T029).
//
// The Server holds a concrete *notify.Notifier rather than an interface, so
// there is no seam to inject a fake through. These tests therefore observe the
// real notification path end to end: SMTP is pointed at an in-process sink that
// captures the rendered message, which also proves the account_locked template
// renders the values the caller passes.
// ---------------------------------------------------------------------------

const (
	lockoutTestIP       = "192.0.2.1"
	lockedSubject       = "Subject: [Veyport] Account Locked: "
	lockoutIndefinitely = "until an administrator intervenes"
)

// smtpMailbox is a minimal SMTP server that records each delivered message.
type smtpMailbox struct {
	messages chan string
	barriers int
}

// startMailbox listens on an ephemeral port, points the hub's SMTP config at
// it, and returns the sink. Every notification the hub emits from now on is
// delivered here.
func startMailbox(t *testing.T, s *Server) *smtpMailbox {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for mock smtp: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	mb := &smtpMailbox{messages: make(chan string, 64)}
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go mb.serve(conn)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	settings := map[string]string{
		"smtp_enabled": "true",
		"smtp_host":    "127.0.0.1",
		"smtp_port":    strconv.Itoa(port),
		"smtp_from":    "hub@test.com",
	}
	for key, value := range settings {
		if err := s.store.SetConfig(key, value); err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}
	return mb
}

// serve walks one SMTP conversation and publishes everything the client sent.
func (m *smtpMailbox) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var conversation string
	defer func() { m.messages <- conversation }()

	fmt.Fprint(conn, "220 localhost ESMTP\r\n")
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		data := string(buf[:n])
		conversation += data
		switch {
		case strings.HasPrefix(data, "EHLO"), strings.HasPrefix(data, "HELO"):
			fmt.Fprint(conn, "250-localhost\r\n250 OK\r\n")
		case strings.HasPrefix(data, "MAIL FROM"), strings.HasPrefix(data, "RCPT TO"):
			fmt.Fprint(conn, "250 OK\r\n")
		case strings.HasPrefix(data, "DATA"):
			fmt.Fprint(conn, "354 Send data\r\n")
		case strings.Contains(data, "\r\n.\r\n"):
			fmt.Fprint(conn, "250 OK\r\n")
		case strings.HasPrefix(data, "QUIT"):
			fmt.Fprint(conn, "221 Bye\r\n")
			return
		}
	}
}

// drain returns every message delivered so far, without sleeping.
//
// Delivery is asynchronous (one worker draining one FIFO queue), so the test
// cannot simply look at the channel. It instead enqueues a barrier
// notification — a failed sign-in for a throwaway account — and collects until
// that barrier arrives. Anything the code under test emitted was queued first
// and is therefore already in hand. The barrier account opts out of both
// events, so it never doubles the recipient list.
func (m *smtpMailbox) drain(t *testing.T, s *Server) []string {
	t.Helper()
	m.barriers++
	name := fmt.Sprintf("mail-barrier-%d", m.barriers)
	barrier := newLocalUser(t, s, name, lockoutTestPassword)
	for _, event := range []string{model.NotifyLoginFailed, model.NotifyAccountLocked} {
		if err := s.store.SetNotificationPreference(barrier.ID, event, false); err != nil {
			t.Fatalf("silence barrier account for %s: %v", event, err)
		}
	}
	attemptLogin(t, s, name, lockoutWrongPassword)

	marker := "Username: " + name
	collected := []string{}
	for {
		select {
		case msg := <-m.messages:
			if strings.Contains(msg, marker) {
				return collected
			}
			collected = append(collected, msg)
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for mail barrier %s", name)
		}
	}
}

// lockedMails narrows captured messages to account-locked notifications.
func lockedMails(messages []string, username string) []string {
	var out []string
	for _, msg := range messages {
		if strings.Contains(msg, lockedSubject+username) {
			out = append(out, msg)
		}
	}
	return out
}

// auditEntriesFor reads back one user's entries for a single action.
func auditEntriesFor(t *testing.T, s *Server, userID, action string) []model.AuditEntry {
	t.Helper()
	entries, _, err := s.store.ListAuditLogs(model.AuditFilter{
		UserID: &userID,
		Action: &action,
		Limit:  100,
	})
	if err != nil {
		t.Fatalf("list audit logs (%s): %v", action, err)
	}
	return entries
}

// lockDetail is the JSON payload carried by a user.locked audit entry.
type lockDetail struct {
	Threshold   int    `json:"threshold"`
	IP          string `json:"ip"`
	LockedUntil string `json:"locked_until"`
}

// assertLockAudit checks the single user.locked entry and returns its detail.
func assertLockAudit(t *testing.T, s *Server, user *model.User, threshold int) lockDetail {
	t.Helper()
	entries := auditEntriesFor(t, s, user.ID, model.AuditUserLocked)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one %s entry, got %d", model.AuditUserLocked, len(entries))
	}
	entry := entries[0]
	if entry.ActorType != model.AuditActorTypeSystem {
		t.Fatalf("expected actor type %q, got %q", model.AuditActorTypeSystem, entry.ActorType)
	}
	if entry.Outcome != model.AuditOutcomeSuccess {
		t.Fatalf("expected outcome %q, got %q", model.AuditOutcomeSuccess, entry.Outcome)
	}
	if entry.ResourceType == nil || *entry.ResourceType != "user" {
		t.Fatalf("expected resource type \"user\", got %v", entry.ResourceType)
	}
	if entry.Target == nil || *entry.Target != user.ID {
		t.Fatalf("expected target %q, got %v", user.ID, entry.Target)
	}
	if entry.UserID == nil || *entry.UserID != user.ID {
		t.Fatalf("expected user id %q, got %v", user.ID, entry.UserID)
	}
	if entry.IPAddress == nil || *entry.IPAddress != lockoutTestIP {
		t.Fatalf("expected ip %q, got %v", lockoutTestIP, entry.IPAddress)
	}
	if entry.Detail == nil {
		t.Fatal("expected a JSON detail on the lock entry")
	}
	var detail lockDetail
	if err := json.Unmarshal([]byte(*entry.Detail), &detail); err != nil {
		t.Fatalf("decode lock detail %q: %v", *entry.Detail, err)
	}
	if detail.Threshold != threshold {
		t.Fatalf("expected threshold %d in the detail, got %d", threshold, detail.Threshold)
	}
	if detail.IP != lockoutTestIP {
		t.Fatalf("expected ip %q in the detail, got %q", lockoutTestIP, detail.IP)
	}
	return detail
}

// assertLockedUntilDetail checks the detail's RFC3339 stamp against the stored expiry.
func assertLockedUntilDetail(t *testing.T, detail lockDetail, want time.Time) {
	t.Helper()
	got, err := time.Parse(time.RFC3339, detail.LockedUntil)
	if err != nil {
		t.Fatalf("locked_until %q is not RFC3339: %v", detail.LockedUntil, err)
	}
	if !got.Equal(want) {
		t.Fatalf("expected locked_until %s, got %s", want.Format(time.RFC3339), got.Format(time.RFC3339))
	}
}

// (j) The failure that crosses the threshold writes exactly one user.locked
// audit entry and sends exactly one account-locked notification.
func TestLockout_LockEmitsAuditAndNotification(t *testing.T) {
	s, clk := lockoutServer(t)
	mailbox := startMailbox(t, s)
	setLockoutPolicy(t, s, 5, 15, 15)
	user := newLocalUser(t, s, "jane", lockoutTestPassword)

	for i := 0; i < 5; i++ {
		attemptLogin(t, s, user.Username, lockoutWrongPassword)
	}

	locked := reloadUser(t, s, user.ID)
	if locked.LockedUntil == nil {
		t.Fatal("expected the account to be locked")
	}

	detail := assertLockAudit(t, s, user, 5)
	assertLockedUntilDetail(t, detail, *locked.LockedUntil)

	mails := lockedMails(mailbox.drain(t, s), user.Username)
	if len(mails) != 1 {
		t.Fatalf("expected exactly one account-locked notification, got %d", len(mails))
	}
	body := mails[0]
	for _, want := range []string{
		"Username: " + user.Username,
		"Source IP: " + lockoutTestIP,
		"Locked until: " + locked.LockedUntil.UTC().Format(model.NotifyTimestampFormat),
		"Time: " + clk.now().Format(model.NotifyTimestampFormat),
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("account-locked notification missing %q:\n%s", want, body)
		}
	}
}

// (k) Attempts refused because the account is already locked are audited as
// login failures but neither re-lock the account nor re-notify.
func TestLockout_RefusedAttemptsDoNotReNotify(t *testing.T) {
	s, _ := lockoutServer(t)
	mailbox := startMailbox(t, s)
	setLockoutPolicy(t, s, 5, 15, 15)
	user := newLocalUser(t, s, "kirk", lockoutTestPassword)

	for i := 0; i < 5; i++ {
		attemptLogin(t, s, user.Username, lockoutWrongPassword)
	}
	if got := len(lockedMails(mailbox.drain(t, s), user.Username)); got != 1 {
		t.Fatalf("expected one account-locked notification for the lock, got %d", got)
	}

	for i := 0; i < 2; i++ {
		assertLockedResponse(t, attemptLogin(t, s, user.Username, lockoutTestPassword), "refused attempt")
	}

	refused := 0
	for _, entry := range auditEntriesFor(t, s, user.ID, model.AuditUserLoginFailed) {
		if entry.Detail == nil || *entry.Detail != lockedDetail {
			continue
		}
		refused++
		if entry.Outcome != model.AuditOutcomeFailure {
			t.Fatalf("expected outcome %q on a refused attempt, got %q", model.AuditOutcomeFailure, entry.Outcome)
		}
	}
	if refused != 2 {
		t.Fatalf("expected two %q login failures, got %d", lockedDetail, refused)
	}

	if got := len(auditEntriesFor(t, s, user.ID, model.AuditUserLocked)); got != 1 {
		t.Fatalf("refusals changed the %s entry count: got %d, want 1", model.AuditUserLocked, got)
	}
	if extra := mailbox.drain(t, s); len(extra) != 0 {
		t.Fatalf("refused attempts sent %d further notifications:\n%v", len(extra), extra)
	}
}

// (l) With auto-unlock disabled the lock has no expiry to display, so the
// notification says so in words while the audit trail keeps the sentinel.
func TestLockout_IndefiniteLockAuditAndNotification(t *testing.T) {
	s, _ := lockoutServer(t)
	mailbox := startMailbox(t, s)
	setLockoutPolicy(t, s, 3, 15, 0)
	user := newLocalUser(t, s, "liam", lockoutTestPassword)

	for i := 0; i < 3; i++ {
		attemptLogin(t, s, user.Username, lockoutWrongPassword)
	}

	locked := reloadUser(t, s, user.ID)
	if locked.LockedUntil == nil || !locked.LockedUntil.Equal(lockout.NoAutoUnlock) {
		t.Fatalf("expected an indefinite lock, got %v", locked.LockedUntil)
	}

	detail := assertLockAudit(t, s, user, 3)
	assertLockedUntilDetail(t, detail, lockout.NoAutoUnlock)

	mails := lockedMails(mailbox.drain(t, s), user.Username)
	if len(mails) != 1 {
		t.Fatalf("expected exactly one account-locked notification, got %d", len(mails))
	}
	if !strings.Contains(mails[0], "Locked until: "+lockoutIndefinitely) {
		t.Fatalf("expected the indefinite phrasing in the notification:\n%s", mails[0])
	}
}

// (m) A lock reached through the one-time-code stage emits the same single
// audit entry and notification as one reached at the password stage.
func TestLockout_TOTPStageLockEmitsAuditAndNotification(t *testing.T) {
	s, _ := lockoutServer(t)
	mailbox := startMailbox(t, s)
	setLockoutPolicy(t, s, 3, 15, 15)
	user := newLocalUser(t, s, "mira", lockoutTestPassword)
	enableTOTPForUser(t, s, user)

	totpToken := primaryLoginTOTPToken(t, s, user.Username, lockoutTestPassword)
	for i := 0; i < 3; i++ {
		attemptTOTP(t, s, totpToken, "000000")
	}

	locked := reloadUser(t, s, user.ID)
	if locked.LockedUntil == nil {
		t.Fatal("expected code-stage failures to lock the account")
	}

	detail := assertLockAudit(t, s, user, 3)
	assertLockedUntilDetail(t, detail, *locked.LockedUntil)

	mails := mailbox.drain(t, s)
	if len(mails) != 1 {
		t.Fatalf("expected exactly one notification from a code-stage lock, got %d:\n%v", len(mails), mails)
	}
	if len(lockedMails(mails, user.Username)) != 1 {
		t.Fatalf("expected the notification to be the account-locked one:\n%s", mails[0])
	}
}

// (n) A hub running without a notifier still audits the lock instead of
// panicking on the nil dependency.
func TestLockout_LockWithoutNotifierStillAudits(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	t.Cleanup(func() { st.Close() })

	jwtSecret, err := InitJWTSecret(st)
	if err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}
	s := New(Config{Addr: ":0", Store: st, JWTSecret: jwtSecret, IsDev: true})
	clk := newTestClock()
	s.SetClock(clk.now)

	setLockoutPolicy(t, s, 5, 15, 15)
	user := newLocalUser(t, s, "nadia", lockoutTestPassword)

	for i := 0; i < 5; i++ {
		attemptLogin(t, s, user.Username, lockoutWrongPassword)
	}

	locked := reloadUser(t, s, user.ID)
	if locked.LockedUntil == nil {
		t.Fatal("expected the account to be locked without a notifier")
	}
	detail := assertLockAudit(t, s, user, 5)
	assertLockedUntilDetail(t, detail, *locked.LockedUntil)
}
