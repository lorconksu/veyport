package integration

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

// Account lifecycle through the real HTTP surface (tasks T014, T017 and T021).
// Everything here goes through the published API — the admin endpoints, both
// sign-in stages, refresh, API tokens — so a regression anywhere between the
// router and the store shows up as a wrong status code rather than a silently
// weakened guard. The only thing reached behind the API is the activity clock,
// which is aged by writing the store directly: the product has no back door for
// making an account look old, and it must not grow one for tests.

const (
	viewerNewPassword = "ViewerP@ssw0rd!99"
	mePath            = "/api/auth/me"
	serversPath       = "/api/servers"
	statusPathFormat  = "/api/users/%s/status"
	unlockPathFormat  = "/api/users/%s/unlock"
	exemptPathFormat  = "/api/users/%s/dormancy-exemption"
	sqliteStampFormat = "2006-01-02 15:04:05"
	expectStatusFmt   = "%s: expected %d, got %d: %s"
)

// requestWithCookies issues a request carrying browser cookies instead of a
// bearer token, which is how the web app authenticates.
func requestWithCookies(t *testing.T, h *TestHarness, method, path string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+h.HTTPAddr+path, nil)
	if err != nil {
		t.Fatalf("create %s %s request: %v", method, path, err)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// assertResponse checks a status code and, when wantBody is non-empty, that the
// body carries that message verbatim. It always closes the response.
func assertResponse(t *testing.T, resp *http.Response, label string, wantStatus int, wantBody string) {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: read body: %v", label, err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf(expectStatusFmt, label, wantStatus, resp.StatusCode, body)
	}
	if wantBody != "" && !strings.Contains(string(body), wantBody) {
		t.Fatalf("%s: expected the body to carry %q, got %s", label, wantBody, body)
	}
}

// completeFirstSignIn walks a freshly created account through its first
// sign-in: temporary password, one-time-code setup, password rotation. It
// returns the session cookies the account ends up holding and its TOTP secret.
func completeFirstSignIn(t *testing.T, h *TestHarness, username, tempPassword string) (access, refresh *http.Cookie, totpSecret string) {
	t.Helper()

	loginResp := h.HTTPPost(t, loginPath, model.LoginRequest{
		Username: username,
		Password: tempPassword,
	}, "")
	defer loginResp.Body.Close()
	requireStatusOK(t, loginResp, "first sign-in password stage")

	var login model.LoginResponse
	decodeJSON(t, loginResp, &login, "first sign-in")
	if login.SetupToken == "" {
		t.Fatal("expected a setup token for an account signing in for the first time")
	}

	setupResp := h.HTTPPost(t, "/api/auth/totp/setup", nil, login.SetupToken)
	defer setupResp.Body.Close()
	requireStatusOK(t, setupResp, "totp setup")

	var setup model.TOTPSetupResponse
	decodeJSON(t, setupResp, &setup, "totp setup")
	totpSecret = setup.Secret

	code, err := auth.GenerateValidCode(totpSecret)
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	enableResp := h.HTTPPost(t, "/api/auth/totp/enable", model.TOTPEnableRequest{
		Code:        code,
		NewPassword: viewerNewPassword,
	}, login.SetupToken)
	defer enableResp.Body.Close()
	requireStatusOK(t, enableResp, "totp enable")

	access = findCookie(enableResp, cookieAccess)
	refresh = findCookie(enableResp, cookieRefresh)
	if access == nil || refresh == nil {
		t.Fatal("expected access and refresh cookies after the first sign-in")
	}
	return access, refresh, totpSecret
}

// mintAPIToken issues an API token for a user and returns the raw secret. It
// goes through the store because the hub mints tokens from the admin CLI, not
// over HTTP.
func mintAPIToken(t *testing.T, h *TestHarness, userID, name string) string {
	t.Helper()
	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if err := h.Store.CreateAPIToken(&model.APIToken{
		ID:          uuid.NewString(),
		UserID:      userID,
		Name:        name,
		TokenHash:   hash,
		TokenPrefix: prefix,
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}
	return raw
}

// setDormantDays writes just the dormancy window through the settings API.
func setDormantDays(t *testing.T, h *TestHarness, adminToken string, days int) {
	t.Helper()
	resp := h.HTTPPut(t, hubSettingsPath, map[string]interface{}{"dormant_days": days}, adminToken)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "put dormant_days")
}

// setAccountDisabled drives the admin status endpoint.
func setAccountDisabled(t *testing.T, h *TestHarness, adminToken, userID string, disabled bool) {
	t.Helper()
	resp := h.HTTPPut(t, fmt.Sprintf(statusPathFormat, userID),
		model.UpdateUserStatusRequest{Disabled: disabled}, adminToken)
	label := "enable account"
	if disabled {
		label = "disable account"
	}
	assertResponse(t, resp, label, http.StatusOK, "")
}

// backDateActivity ages an account by rewriting the three timestamps the
// dormancy clock reads. Nothing in the product can do this, which is the point:
// the only way to observe dormancy in a test is to move the data, never to add
// a switch that shortens the window.
func backDateActivity(t *testing.T, h *TestHarness, userID string, age time.Duration) {
	t.Helper()
	stamp := time.Now().UTC().Add(-age).Format(sqliteStampFormat)
	if _, err := h.Store.DB().Exec(
		`UPDATE users
		 SET last_activity_at = ?, reactivated_at = ?, created_at = ?
		 WHERE id = ?`,
		stamp, stamp, stamp, userID,
	); err != nil {
		t.Fatalf("back-date activity for %s: %v", userID, err)
	}
}

// TestAccountLifecycle_DisableCutsEveryPathThenEnableRestoresIt is the US1
// acceptance walk: an account signed in and holding an API token loses every
// form of access the instant an administrator disables it, and regains them all
// on enable — except the API tokens, which stay revoked (spec FR-002, FR-003,
// FR-004, FR-009).
func TestAccountLifecycle_DisableCutsEveryPathThenEnableRestoresIt(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)

	viewerID, tempPassword := createViewer(t, h, adminToken, "lifecycleviewer")
	accessCookie, refreshCookie, totpSecret := completeFirstSignIn(t, h, "lifecycleviewer", tempPassword)

	apiToken := mintAPIToken(t, h, viewerID, "pre-disable token")
	assertResponse(t, h.HTTPGet(t, serversPath, apiToken), "api token before disable", http.StatusOK, "")
	assertResponse(t, requestWithCookies(t, h, "GET", mePath, accessCookie),
		"session before disable", http.StatusOK, "")

	setAccountDisabled(t, h, adminToken, viewerID, true)

	// Every credential the account already held is refused, each with the
	// canonical message and the status its path uses.
	// The session dies on the token-generation bump the disable performs, which
	// is what makes the revocation instant; that check runs before the account
	// check, so this path answers with the generic revoked-token message rather
	// than the account one. The status is what the web client acts on.
	assertResponse(t, requestWithCookies(t, h, "GET", mePath, accessCookie),
		"session after disable", http.StatusUnauthorized, "")
	assertResponse(t, requestWithCookies(t, h, "POST", refreshPath, refreshCookie),
		"refresh after disable", http.StatusUnauthorized, account.MsgDisabled)
	// Likewise the API token: the disable revoked it outright, so it is no
	// longer a live token to attach an account message to. That it is revoked
	// rather than merely inert is the point — enabling must not resurrect it.
	assertResponse(t, h.HTTPGet(t, serversPath, apiToken),
		"api token after disable", http.StatusUnauthorized, "")

	// And a fresh sign-in is refused before the password is even considered.
	status, body := loginAttempt(t, h, "lifecycleviewer", viewerNewPassword)
	if status != http.StatusForbidden {
		t.Fatalf("login while disabled: expected 403, got %d: %s", status, body)
	}
	if !strings.Contains(body, account.MsgDisabled) {
		t.Fatalf("login while disabled: expected %q, got %s", account.MsgDisabled, body)
	}

	if listed := findListedUser(t, h, adminToken, viewerID); listed.Status != string(account.StatusDisabled) {
		t.Fatalf("expected the admin list to show status %q, got %q", account.StatusDisabled, listed.Status)
	}

	setAccountDisabled(t, h, adminToken, viewerID, false)

	if listed := findListedUser(t, h, adminToken, viewerID); listed.Status != string(account.StatusActive) {
		t.Fatalf("expected the admin list to show status %q after enable, got %q",
			account.StatusActive, listed.Status)
	}

	// Sign-in works again, right through the one-time-code stage.
	h.HTTPServer.ClearTOTPCache()
	loginResp := h.HTTPPost(t, loginPath, model.LoginRequest{
		Username: "lifecycleviewer",
		Password: viewerNewPassword,
	}, "")
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("login after enable: expected 202, got %d: %s", loginResp.StatusCode, respBody)
	}
	var login model.LoginResponse
	decodeJSON(t, loginResp, &login, "login after enable")

	code, err := auth.GenerateValidCode(totpSecret)
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	assertResponse(t, h.HTTPPost(t, loginTOTPPath, model.LoginTOTPRequest{
		TOTPToken: login.TOTPToken,
		Code:      code,
	}, ""), "code stage after enable", http.StatusOK, "")

	// The revoked API token stays revoked; a newly minted one works. Enabling
	// restores access, it does not resurrect credentials.
	assertResponse(t, h.HTTPGet(t, serversPath, apiToken),
		"old api token after enable", http.StatusUnauthorized, "")
	freshToken := mintAPIToken(t, h, viewerID, "post-enable token")
	assertResponse(t, h.HTTPGet(t, serversPath, freshToken),
		"new api token after enable", http.StatusOK, "")
}

// TestAccountLifecycle_FirstAdminIsDormancyExempt pins the recovery path: the
// account created by the register flow carries the exemption, so a hub whose
// only administrator goes quiet cannot lock itself out (FR-017).
func TestAccountLifecycle_FirstAdminIsDormancyExempt(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)

	resp := h.HTTPGet(t, mePath, adminToken)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "admin me")

	var me model.User
	decodeJSON(t, resp, &me, "admin me")
	if !me.DormancyExempt {
		t.Fatal("expected the first registered administrator to carry the dormancy exemption")
	}
	if me.Status != string(account.StatusActive) {
		t.Fatalf("expected status %q, got %q", account.StatusActive, me.Status)
	}
}

// TestAccountLifecycle_AdminUnlockRestoresSignIn is the US2 acceptance walk: a
// locked account is freed by an administrator rather than by waiting out the
// expiry (FR-005).
func TestAccountLifecycle_AdminUnlockRestoresSignIn(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)
	setLockoutPolicy(t, h, adminToken, 3, 60)

	viewerID, tempPassword := createViewer(t, h, adminToken, "unlockviewer")

	for i := 1; i <= 3; i++ {
		if status, body := loginAttempt(t, h, "unlockviewer", wrongPasswordText); status != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: expected 401, got %d: %s", i, status, body)
		}
	}
	if listed := findListedUser(t, h, adminToken, viewerID); listed.Status != string(account.StatusLocked) {
		t.Fatalf("expected status %q after the threshold, got %q", account.StatusLocked, listed.Status)
	}
	if status, body := loginAttempt(t, h, "unlockviewer", tempPassword); status != http.StatusLocked {
		t.Fatalf("expected 423 with the correct password while locked, got %d: %s", status, body)
	}

	assertResponse(t, h.HTTPPost(t, fmt.Sprintf(unlockPathFormat, viewerID), nil, adminToken),
		"admin unlock", http.StatusOK, "")

	listed := findListedUser(t, h, adminToken, viewerID)
	if listed.Status != string(account.StatusActive) {
		t.Fatalf("expected status %q after the unlock, got %q", account.StatusActive, listed.Status)
	}
	if listed.FailedLoginCount != 0 {
		t.Fatalf("expected failed_login_count 0 after the unlock, got %d", listed.FailedLoginCount)
	}

	if status, body := loginAttempt(t, h, "unlockviewer", tempPassword); status != http.StatusOK {
		t.Fatalf("expected the sign-in to proceed after the unlock, got %d: %s", status, body)
	}
}

// TestAccountLifecycle_DormancyRefusesStaleAccounts is the US3 acceptance walk:
// an account past the dormancy window is refused at sign-in and on its API
// token, an exempt administrator in the same state is not, and turning the
// policy off restores everyone (FR-006, FR-007, FR-017).
func TestAccountLifecycle_DormancyRefusesStaleAccounts(t *testing.T) {
	h := StartHarness(t)
	adminToken, totpSecret := h.SetupAdminWithTOTP(t)

	admin, err := h.Store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}

	setDormantDays(t, h, adminToken, 1)

	viewerID, tempPassword := createViewer(t, h, adminToken, "dormantviewer")
	apiToken := mintAPIToken(t, h, viewerID, "pre-dormancy token")
	assertResponse(t, h.HTTPGet(t, serversPath, apiToken), "api token before dormancy", http.StatusOK, "")

	backDateActivity(t, h, viewerID, 48*time.Hour)

	if listed := findListedUser(t, h, adminToken, viewerID); listed.Status != string(account.StatusDormant) {
		t.Fatalf("expected status %q, got %q", account.StatusDormant, listed.Status)
	}
	status, body := loginAttempt(t, h, "dormantviewer", tempPassword)
	if status != http.StatusForbidden {
		t.Fatalf("dormant login: expected 403, got %d: %s", status, body)
	}
	if !strings.Contains(body, account.MsgDormant) {
		t.Fatalf("dormant login: expected %q, got %s", account.MsgDormant, body)
	}
	assertResponse(t, h.HTTPGet(t, serversPath, apiToken),
		"api token while dormant", http.StatusUnauthorized, account.MsgDormant)

	// The administrator keeps their own recovery path: exempt first, then aged
	// past the window, and still able to sign in.
	assertResponse(t, h.HTTPPut(t, fmt.Sprintf(exemptPathFormat, admin.ID),
		model.SetDormancyExemptRequest{Exempt: true}, adminToken),
		"self exemption", http.StatusOK, "")
	backDateActivity(t, h, admin.ID, 48*time.Hour)

	h.HTTPServer.ClearTOTPCache()
	if cookie := completeAdminLogin(t, h, totpSecret); cookie == nil {
		t.Fatal("expected the exempt administrator to complete sign-in")
	}

	// Turning the policy off makes the stale account usable again with no
	// change to the account itself.
	setDormantDays(t, h, adminToken, 0)
	if listed := findListedUser(t, h, adminToken, viewerID); listed.Status != string(account.StatusActive) {
		t.Fatalf("expected status %q with dormancy disabled, got %q", account.StatusActive, listed.Status)
	}
	if status, body := loginAttempt(t, h, "dormantviewer", tempPassword); status != http.StatusOK {
		t.Fatalf("expected the sign-in to proceed with dormancy disabled, got %d: %s", status, body)
	}
}
