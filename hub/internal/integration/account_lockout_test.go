package integration

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

// Account lockout through the real HTTP surface (task T013). These tests drive
// the published API only — policy through PUT /api/settings/hub, attempts
// through POST /api/auth/login, visibility through GET /api/users — so they
// fail if any layer between the router and the store drops the behaviour.

const (
	lockoutMessage    = "account temporarily locked — try again later"
	hubSettingsPath   = "/api/settings/hub"
	loginPath         = "/api/auth/login"
	loginTOTPPath     = "/api/auth/login/totp"
	refreshPath       = "/api/auth/refresh"
	usersPath         = "/api/users"
	adminPassword     = "TestPassword123!"
	wrongPasswordText = "definitely-not-the-password"
)

// integrationClock is a manually advanced clock installed on the hub so a lock
// can be observed expiring without a real-time wait.
type integrationClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *integrationClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *integrationClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// setLockoutPolicy applies the lockout policy through the admin settings API.
func setLockoutPolicy(t *testing.T, h *TestHarness, adminToken string, threshold, durationMinutes int) {
	t.Helper()
	resp := h.HTTPPut(t, hubSettingsPath, map[string]interface{}{
		"lockout_threshold":        threshold,
		"lockout_duration_minutes": durationMinutes,
	}, adminToken)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "put lockout policy")
}

// loginAttempt posts one password-stage attempt and returns status and body.
func loginAttempt(t *testing.T, h *TestHarness, username, password string) (int, string) {
	t.Helper()
	resp := h.HTTPPost(t, loginPath, model.LoginRequest{Username: username, Password: password}, "")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read login response: %v", err)
	}
	return resp.StatusCode, string(body)
}

// createViewer creates a viewer account and returns its ID and temporary password.
func createViewer(t *testing.T, h *TestHarness, adminToken, username string) (userID, tempPassword string) {
	t.Helper()
	resp := h.HTTPPost(t, usersPath, model.CreateUserRequest{
		Username: username,
		Email:    username + "@test.com",
		Role:     model.RoleViewer,
	}, adminToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create viewer: status=%d body=%s", resp.StatusCode, body)
	}
	var created model.CreateUserResponse
	decodeJSON(t, resp, &created, "create user")
	if created.TemporaryPassword == "" {
		t.Fatal("expected a temporary password for the new viewer")
	}
	return created.User.ID, created.TemporaryPassword
}

// findListedUser returns one user from the admin user list.
func findListedUser(t *testing.T, h *TestHarness, adminToken, userID string) model.User {
	t.Helper()
	resp := h.HTTPGet(t, usersPath, adminToken)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "list users")

	var list model.UserListResponse
	decodeJSON(t, resp, &list, "list users")
	for _, u := range list.Users {
		if u.ID == userID {
			return u
		}
	}
	t.Fatalf("user %s not present in the admin user list", userID)
	return model.User{}
}

// TestAccountLockout_LocksThenAutoUnlocks walks the full operator-visible
// lifecycle: policy set through the API, an account locked by repeated wrong
// passwords, the lock visible to an administrator, and the account usable again
// once the expiry passes (spec SC-001, FR-002, FR-005, FR-011).
func TestAccountLockout_LocksThenAutoUnlocks(t *testing.T) {
	h := StartHarness(t)
	clk := &integrationClock{t: time.Now().UTC()}
	h.HTTPServer.SetClock(clk.now)

	adminToken := h.SetupAdmin(t)
	setLockoutPolicy(t, h, adminToken, 2, 1)

	viewerID, tempPassword := createViewer(t, h, adminToken, "lockoutviewer")

	for i := 1; i <= 2; i++ {
		status, body := loginAttempt(t, h, "lockoutviewer", wrongPasswordText)
		if status != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: expected 401, got %d: %s", i, status, body)
		}
	}

	status, body := loginAttempt(t, h, "lockoutviewer", tempPassword)
	if status != http.StatusLocked {
		t.Fatalf("expected 423 on the attempt after the threshold, got %d: %s", status, body)
	}
	if !strings.Contains(body, lockoutMessage) {
		t.Fatalf("expected the locked message in the body, got %s", body)
	}

	listed := findListedUser(t, h, adminToken, viewerID)
	if listed.FailedLoginCount != 2 {
		t.Fatalf("expected failed_login_count 2 in the admin list, got %d", listed.FailedLoginCount)
	}
	if listed.LockedUntil == nil {
		t.Fatal("expected locked_until to be exposed to the administrator")
	}
	if !listed.LockedUntil.After(clk.now()) {
		t.Fatalf("expected locked_until in the future, got %s (now %s)", listed.LockedUntil, clk.now())
	}

	// Let the one-minute lock elapse on the hub's clock.
	clk.advance(2 * time.Minute)

	status, body = loginAttempt(t, h, "lockoutviewer", tempPassword)
	if status == http.StatusLocked {
		t.Fatalf("expected the lock to have expired, still got 423: %s", body)
	}
	if status == http.StatusUnauthorized {
		t.Fatalf("expected the temporary password to be accepted after expiry, got 401: %s", body)
	}
	if status != http.StatusOK {
		t.Fatalf("expected 200 continuing sign-in after expiry, got %d: %s", status, body)
	}
}

// TestAccountLockout_LeavesExistingCredentialsAlone pins FR-010 and SC-007: a
// lock stops new sign-ins and nothing else. A refresh token minted before the
// lock still refreshes, and an API token issued before the lock still
// authenticates.
func TestAccountLockout_LeavesExistingCredentialsAlone(t *testing.T) {
	h := StartHarness(t)
	adminToken, totpSecret := h.SetupAdminWithTOTP(t)

	admin, err := h.Store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}

	// An API token issued while the account is healthy.
	rawAPIToken, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if err := h.Store.CreateAPIToken(&model.APIToken{
		ID:          uuid.NewString(),
		UserID:      admin.ID,
		Name:        "pre-lock token",
		TokenHash:   hash,
		TokenPrefix: prefix,
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}

	// A full interactive sign-in, so we hold a refresh cookie minted before the
	// lock. The replay cache is cleared because setup already consumed the code
	// for the current time step.
	h.HTTPServer.ClearTOTPCache()
	refreshCookie := completeAdminLogin(t, h, totpSecret)

	setLockoutPolicy(t, h, adminToken, 2, 15)

	for i := 1; i <= 2; i++ {
		if status, body := loginAttempt(t, h, "admin", wrongPasswordText); status != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: expected 401, got %d: %s", i, status, body)
		}
	}
	if status, body := loginAttempt(t, h, "admin", adminPassword); status != http.StatusLocked {
		t.Fatalf("expected the admin account to be locked, got %d: %s", status, body)
	}

	// FR-010: the API token still authenticates.
	apiResp := h.HTTPGet(t, "/api/servers", rawAPIToken)
	defer apiResp.Body.Close()
	requireStatusOK(t, apiResp, "api token request while locked")

	// SC-007: the pre-lock refresh token still refreshes.
	refreshResp := postWithCookie(t, h, refreshPath, refreshCookie)
	defer refreshResp.Body.Close()
	requireStatusOK(t, refreshResp, "refresh while locked")
}

// completeAdminLogin performs password + one-time-code sign-in for the admin and
// returns the refresh cookie it was issued.
func completeAdminLogin(t *testing.T, h *TestHarness, totpSecret string) *http.Cookie {
	t.Helper()

	loginResp := h.HTTPPost(t, loginPath, model.LoginRequest{
		Username: "admin",
		Password: adminPassword,
	}, "")
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("admin password stage: status=%d body=%s", loginResp.StatusCode, body)
	}
	var login model.LoginResponse
	decodeJSON(t, loginResp, &login, "login")

	code, err := auth.GenerateValidCode(totpSecret)
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	totpResp := h.HTTPPost(t, loginTOTPPath, model.LoginTOTPRequest{
		TOTPToken: login.TOTPToken,
		Code:      code,
	}, "")
	defer totpResp.Body.Close()
	requireStatusOK(t, totpResp, "admin code stage")

	cookie := findCookie(totpResp, cookieRefresh)
	if cookie == nil {
		t.Fatal("expected a refresh cookie from the completed sign-in")
	}
	return cookie
}

// postWithCookie issues a POST carrying only the supplied cookie.
func postWithCookie(t *testing.T, h *TestHarness, path string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", "http://"+h.HTTPAddr+path, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}
