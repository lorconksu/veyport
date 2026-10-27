package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

const managementMFASecret = "JBSWY3DPEHPK3PXP"

func managementUser(t *testing.T, f *lifecycleFixture) *model.User {
	t.Helper()
	u, err := f.s.store.GetUserByID(f.viewerID)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func managementJSON(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}
func managementReset(t *testing.T, f *lifecycleFixture) map[string]any {
	t.Helper()
	rec := lifecycleRequest(t, f.s, "POST", "/api/users/"+f.viewerID+"/password-reset", f.adminToken, map[string]int{"expected_revision": managementUser(t, f).TokenGeneration})
	if rec.Code != 200 {
		t.Fatalf("reset status %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("reset response may be cached")
	}
	return managementJSON(t, rec)
}
func managementEnableExistingMFA(t *testing.T, f *lifecycleFixture) {
	t.Helper()
	secret := managementMFASecret
	if err := f.s.store.SetTemporaryPasswordState(f.viewerID, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.s.store.UpdateUserTOTP(f.viewerID, &secret, true); err != nil {
		t.Fatal(err)
	}
}
func managementChallenge(t *testing.T, f *lifecycleFixture, password string) string {
	t.Helper()
	login := lifecycleRequest(t, f.s, "POST", "/api/auth/login", "", model.LoginRequest{Username: lifecycleViewerName, Password: password})
	if login.Code != 202 {
		t.Fatalf("password login status %d", login.Code)
	}
	challenge, _ := managementJSON(t, login)["totp_token"].(string)
	return challenge
}
func managementRecovery(t *testing.T, f *lifecycleFixture, password string) string {
	t.Helper()
	challenge := managementChallenge(t, f, password)
	code := validTOTPCode(t, managementMFASecret, f.s.now())
	mfa := lifecycleRequest(t, f.s, "POST", "/api/auth/login/totp", "", model.LoginTOTPRequest{TOTPToken: challenge, Code: code})
	if mfa.Code != 200 {
		t.Fatalf("MFA status %d", mfa.Code)
	}
	body := managementJSON(t, mfa)
	token, _ := body["recovery_token"].(string)
	if token == "" || body["must_change_password"] != true || body["access_token"] != nil || body["refresh_token"] != nil || findCookie(mfa.Result().Cookies(), cookieAccess) != nil {
		t.Fatal("MFA issued normal authority during recovery")
	}
	claims, err := auth.ValidateToken(f.s.jwtSecret, token)
	if err != nil || claims.TokenType != auth.TokenTypePasswordRecovery {
		t.Fatal("invalid recovery purpose")
	}
	return token
}

func TestAccountManagementExistingMFAPasswordRecovery(t *testing.T) {
	f := newLifecycleFixture(t)
	managementEnableExistingMFA(t, f)
	oldAccess, oldRefresh, oldSession := sessionTokenPair(t, f.s, f.viewerID)
	reset := managementReset(t, f)
	password, _ := reset["temporary_password"].(string)
	if password == "" {
		t.Fatal("missing once-only temporary password")
	}
	live := managementUser(t, f)
	if !live.TOTPEnabled || live.TOTPSecret == nil || *live.TOTPSecret != managementMFASecret || !live.MustChangePassword {
		t.Fatal("reset changed existing MFA")
	}
	assertManagementOldAuthorityRevoked(t, f, oldAccess, oldRefresh, oldSession)
	recovery := managementRecovery(t, f, password)
	assertManagementRecoveryHasNoNormalAuthority(t, f, recovery)
	if rec := lifecycleRequest(t, f.s, "POST", "/api/auth/password/recovery", recovery, map[string]string{"new_password": password}); rec.Code != 400 {
		t.Fatal("temporary password reuse accepted")
	}
	permanent := "ChosenPermanent!Password123"
	done := lifecycleRequest(t, f.s, "POST", "/api/auth/password/recovery", recovery, map[string]string{"new_password": permanent})
	if done.Code != 200 || managementJSON(t, done)["requires_login"] != true {
		t.Fatalf("complete status %d", done.Code)
	}
	if rec := lifecycleRequest(t, f.s, "POST", "/api/auth/password/recovery", recovery, map[string]string{"new_password": "Replay!Password123"}); rec.Code != 401 {
		t.Fatal("recovery authority replay accepted")
	}
	live = managementUser(t, f)
	if live.MustChangePassword || live.TempPasswordExpiresAt != nil || !live.TOTPEnabled || *live.TOTPSecret != managementMFASecret {
		t.Fatal("completion changed MFA or left temporary authority")
	}
	// A fresh MFA timestep proves normal login is required after completion.
	now := f.s.now().Add(31 * time.Second)
	f.s.SetClock(func() time.Time { return now })
	challenge := managementChallenge(t, f, permanent)
	code := validTOTPCode(t, managementMFASecret, now)
	login := lifecycleRequest(t, f.s, "POST", "/api/auth/login/totp", "", model.LoginTOTPRequest{TOTPToken: challenge, Code: code})
	if login.Code != 200 || managementJSON(t, login)["access_token"] == nil {
		t.Fatalf("fresh normal sign-in status %d", login.Code)
	}
}

func TestAccountManagementRefusesOrdinaryResetBypasses(t *testing.T) {
	f := newLifecycleFixture(t)
	for _, test := range []struct {
		name, token string
		body        any
		want        int
	}{
		{"unauthenticated", "", map[string]int{"expected_revision": 0}, 401},
		{"missing revision", f.adminToken, map[string]string{}, 400},
		{"stale revision", f.adminToken, map[string]int{"expected_revision": 99}, 409},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := lifecycleRequest(t, f.s, "POST", "/api/users/"+f.viewerID+"/password-reset", test.token, test.body)
			if rec.Code != test.want {
				t.Fatalf("status %d wanted %d", rec.Code, test.want)
			}
		})
	}
	for _, provider := range []string{"ldap", "unknown"} {
		if _, err := f.s.store.DB().Exec("UPDATE users SET auth_provider=? WHERE id=?", provider, f.viewerID); err != nil {
			t.Fatal(err)
		}
		rec := lifecycleRequest(t, f.s, "POST", "/api/users/"+f.viewerID+"/password-reset", f.adminToken, map[string]int{"expected_revision": 0})
		if rec.Code != 400 {
			t.Fatalf("source %s status %d", provider, rec.Code)
		}
	}
	rec := lifecycleRequest(t, f.s, "POST", "/api/users/"+f.adminID+"/password-reset", f.adminToken, map[string]int{"expected_revision": 0})
	if rec.Code != 400 {
		t.Fatalf("self-reset status %d", rec.Code)
	}
}

func TestAccountManagementInteractiveAndCSRF(t *testing.T) {
	f := newLifecycleFixture(t)
	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.store.CreateAPIToken(&model.APIToken{ID: "admin-api", UserID: f.adminID, Name: "admin-api", TokenHash: hash, TokenPrefix: prefix}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"reactivate", "password-reset"} {
		path := "/api/users/" + f.viewerID + "/" + action
		rec := lifecycleRequest(t, f.s, "POST", path, raw, map[string]int{"expected_revision": 0})
		if rec.Code != 403 {
			t.Fatalf("API-only %s status %d", action, rec.Code)
		}
		req := httptest.NewRequest("POST", path, strings.NewReader(`{"expected_revision":0}`))
		req.AddCookie(&http.Cookie{Name: cookieAccess, Value: f.adminToken})
		req.AddCookie(&http.Cookie{Name: cookieCSRF, Value: "csrf-value"})
		response := httptest.NewRecorder()
		f.s.routes().ServeHTTP(response, req)
		if response.Code != 403 {
			t.Fatalf("missing CSRF %s status %d", action, response.Code)
		}
	}
}

func TestAccountManagementRecoveryInvalidationStages(t *testing.T) {
	for _, stage := range []string{"between password and MFA", "after MFA", "expiry"} {
		t.Run(stage, func(t *testing.T) {
			assertManagementInvalidationStage(t, stage)
		})
	}
}

func TestAccountManagementForcedChangeBlocksNormalAuthority(t *testing.T) {
	f := newLifecycleFixture(t)
	managementEnableExistingMFA(t, f)
	access, refresh, _ := sessionTokenPair(t, f.s, f.viewerID)
	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.store.CreateAPIToken(&model.APIToken{ID: "viewer-api", UserID: f.viewerID, Name: "viewer-api", TokenHash: hash, TokenPrefix: prefix}); err != nil {
		t.Fatal(err)
	}
	expires := f.s.now().Add(time.Hour)
	if err := f.s.store.SetTemporaryPasswordState(f.viewerID, true, &expires); err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{access, raw} {
		rec := lifecycleRequest(t, f.s, "GET", "/api/servers", credential, nil)
		if rec.Code != 403 || managementJSON(t, rec)["code"] != "password_change_required" {
			t.Fatalf("forced change access status %d", rec.Code)
		}
	}
	rec := lifecycleRequest(t, f.s, "POST", "/api/auth/refresh", "", model.RefreshRequest{RefreshToken: refresh})
	if rec.Code != 403 || managementJSON(t, rec)["code"] != "password_change_required" {
		t.Fatal("forced change refreshed normal credentials")
	}
}

func TestAccountManagementReactivatePreservesLock(t *testing.T) {
	f := newLifecycleFixture(t)
	now := f.s.now().UTC().Truncate(time.Second)
	locked := now.Add(time.Hour)
	if _, err := f.s.store.DB().Exec("UPDATE users SET created_at=?,locked_until=?,failed_login_count=7 WHERE id=?", now.Add(-60*24*time.Hour).Format("2006-01-02 15:04:05"), locked.Format("2006-01-02 15:04:05"), f.viewerID); err != nil {
		t.Fatal(err)
	}
	rec := lifecycleRequest(t, f.s, "POST", "/api/users/"+f.viewerID+"/reactivate", f.adminToken, nil)
	if rec.Code != 200 {
		t.Fatalf("reactivate status %d", rec.Code)
	}
	body := managementJSON(t, rec)
	user := body["user"].(map[string]any)
	if body["changed"] != true || user["status"] != "locked" || user["failed_login_count"] != float64(7) {
		t.Fatal("reactivation silently cleared lock")
	}
	rec = lifecycleRequest(t, f.s, "POST", "/api/users/"+f.viewerID+"/reactivate", f.adminToken, nil)
	if rec.Code != 200 || managementJSON(t, rec)["changed"] != false {
		t.Fatal("active reactivation was not idempotent")
	}
}

func TestAccountManagementErrorExpiryIsUnauthorized(t *testing.T) {
	s := testServer(t)
	rec := httptest.NewRecorder()
	s.accountManagementError(rec, store.ErrTemporaryPasswordExpired)
	if rec.Code != 401 {
		t.Fatalf("expiry status %d", rec.Code)
	}
}

func TestAccountManagementProtectedTargetsAndNonAdminsRefused(t *testing.T) {
	f := newLifecycleFixture(t)
	managementEnableExistingMFA(t, f)
	viewer, _, _ := sessionTokenPair(t, f.s, f.viewerID)
	for _, action := range []string{"reactivate", "password-reset"} {
		rec := lifecycleRequest(t, f.s, "POST", "/api/users/"+f.adminID+"/"+action, viewer, map[string]int{"expected_revision": 0})
		if rec.Code != 403 {
			t.Fatalf("non-admin %s status %d", action, rec.Code)
		}
	}
	before := managementUser(t, f)
	if _, err := f.s.store.DB().Exec("INSERT INTO user_roles(user_id,role) VALUES(?,'original-reader')", f.viewerID); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"reactivate", "password-reset"} {
		rec := lifecycleRequest(t, f.s, "POST", "/api/users/"+f.viewerID+"/"+action, f.adminToken, map[string]int{"expected_revision": managementUser(t, f).TokenGeneration})
		if rec.Code != 403 {
			t.Fatalf("protected %s status %d", action, rec.Code)
		}
	}
	after := managementUser(t, f)
	if before.PasswordHash != after.PasswordHash || after.TOTPSecret == nil || *after.TOTPSecret != managementMFASecret {
		t.Fatal("ordinary refusal modified protected credentials")
	}
	listed := lifecycleRequest(t, f.s, "GET", "/api/users", f.adminToken, nil)
	if listed.Code != 200 {
		t.Fatalf("list status %d", listed.Code)
	}
	var body struct {
		Users []model.User `json:"users"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, user := range body.Users {
		if user.ID == f.viewerID {
			found = user.Protected
		}
	}
	if !found {
		t.Fatal("user list did not expose protected action guidance")
	}
}

func TestAccountManagementRejectsActorMFAChangesBeforePrivilegedCommit(t *testing.T) {
	for _, reenable := range []bool{false, true} {
		t.Run(map[bool]string{false: "MFA removed", true: "MFA replaced"}[reenable], func(t *testing.T) {
			f := newLifecycleFixture(t)
			req := httptest.NewRequest("POST", "/api/users/"+f.viewerID+"/password-reset", nil)
			req.Header.Set("Authorization", "Bearer "+f.adminToken)
			authority := f.s.accountManagementActor(req)
			secret := "JBSWY3DPEHPK3PXP"
			if err := f.s.store.UpdateUserTOTP(f.adminID, &secret, false); err != nil {
				t.Fatal(err)
			}
			if reenable {
				if err := f.s.store.UpdateUserTOTP(f.adminID, &secret, true); err != nil {
					t.Fatal(err)
				}
			} else {
				// Even a resnapshot after removal cannot reuse a still-not-yet-bumped access
				// generation: live MFA is an independent commit requirement.
				authority = f.s.accountManagementActor(req)
			}
			before := managementUser(t, f)
			now := f.s.now()
			_, err := f.s.store.ResetLocalPassword(store.PasswordResetTarget{UserID: f.viewerID, ExpectedGeneration: before.TokenGeneration}, store.TemporaryPasswordCredential{Hash: "forbidden-hash", ExpiresAt: now.Add(time.Hour)}, now, 5, f.s.accountManagementAudit(req, f.adminID, f.viewerID, model.AuditUserPasswordReset), authority)
			if err != store.ErrAccountManagementActor {
				t.Fatalf("changed administrator MFA accepted: %v", err)
			}
			if after := managementUser(t, f); after.PasswordHash != before.PasswordHash || after.TokenGeneration != before.TokenGeneration {
				t.Fatal("MFA change race changed target credentials")
			}
		})
	}
}

func TestPasswordRecoveryUsesOnlyExplicitBearerDespiteBrowserCookies(t *testing.T) {
	for _, mode := range []string{"stale cookie and valid bearer", "cookie-only recovery refused", "blacklisted recovery bearer refused", "password-stage bearer refused", "expired recovery bearer refused"} {
		t.Run(mode, func(t *testing.T) {
			runManagementBearerScenario(t, mode)
		})
	}
}

func assertManagementOldAuthorityRevoked(t *testing.T, f *lifecycleFixture, oldAccess, oldRefresh, oldSession string) {
	t.Helper()
	if rec := lifecycleRequest(t, f.s, "GET", "/api/auth/me", oldAccess, nil); rec.Code != 401 {
		t.Fatalf("old access status %d", rec.Code)
	}
	if rec := lifecycleRequest(t, f.s, "POST", "/api/auth/refresh", "", model.RefreshRequest{RefreshToken: oldRefresh}); rec.Code != 403 && rec.Code != 401 {
		t.Fatalf("old refresh status %d", rec.Code)
	}
	sess, err := f.s.store.GetSession(oldSession)
	if err != nil || sess.EndedAt == nil {
		t.Fatal("reset did not end durable session")
	}
	if rec := lifecycleRequest(t, f.s, "POST", "/api/auth/login", "", model.LoginRequest{Username: lifecycleViewerName, Password: f.viewerPass}); rec.Code != 401 {
		t.Fatal("old password still accepted")
	}
}

func assertManagementRecoveryHasNoNormalAuthority(t *testing.T, f *lifecycleFixture, recovery string) {
	t.Helper()
	for _, path := range []string{"/api/auth/me", "/api/servers", "/api/users", "/api/auth/sessions"} {
		if rec := lifecycleRequest(t, f.s, "GET", path, recovery, nil); rec.Code != 403 {
			t.Fatalf("recovery reached %s: %d", path, rec.Code)
		}
	}
	if rec := lifecycleRequest(t, f.s, "POST", "/api/auth/totp/setup", recovery, nil); rec.Code != 403 {
		t.Fatal("recovery allowed MFA replacement")
	}
	if rec := lifecycleRequest(t, f.s, "POST", "/api/auth/refresh", "", model.RefreshRequest{RefreshToken: recovery}); rec.Code != 401 {
		t.Fatal("recovery token refreshed")
	}
}

func assertManagementInvalidationStage(t *testing.T, stage string) {
	t.Helper()
	f := newLifecycleFixture(t)
	managementEnableExistingMFA(t, f)
	first := managementReset(t, f)
	password := first["temporary_password"].(string)
	var credential string
	if stage == "between password and MFA" {
		credential = managementChallenge(t, f, password)
	} else {
		credential = managementRecovery(t, f, password)
	}
	if stage == "expiry" {
		if _, err := f.s.store.DB().Exec("UPDATE users SET temp_password_expires_at=datetime('now','-1 second') WHERE id=?", f.viewerID); err != nil {
			t.Fatal(err)
		}
	} else {
		managementReset(t, f)
	}
	var rec *httptest.ResponseRecorder
	if stage == "between password and MFA" {
		rec = lifecycleRequest(t, f.s, "POST", "/api/auth/login/totp", "", model.LoginTOTPRequest{TOTPToken: credential, Code: validTOTPCode(t, managementMFASecret, f.s.now())})
	} else {
		rec = lifecycleRequest(t, f.s, "POST", "/api/auth/password/recovery", credential, map[string]string{"new_password": "ChosenPermanent!Password123"})
	}
	if rec.Code != 401 {
		t.Fatalf("invalid recovery stage status %d", rec.Code)
	}
}

func managementRecoveryBearerRequest(t *testing.T, f *lifecycleFixture, mode, staleAccess, recovery string) *http.Request {
	t.Helper()
	request := httptest.NewRequest("POST", "/api/auth/password/recovery", mustJSON(t, map[string]string{"new_password": "ChosenPermanent!Password123"}))
	switch mode {
	case "stale cookie and valid bearer":
		request.AddCookie(&http.Cookie{Name: cookieAccess, Value: staleAccess})
		request.Header.Set("Authorization", testBearerPrefix+recovery)
	case "password-stage bearer refused":
		token, err := auth.GenerateTOTPToken(f.s.jwtSecret, f.viewerID, string(model.RoleViewer), managementUser(t, f).TokenGeneration)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", testBearerPrefix+token)
	case "expired recovery bearer refused":
		token, err := auth.GenerateTokenWithExpiry(f.s.jwtSecret, f.viewerID, string(model.RoleViewer), auth.TokenTypePasswordRecovery, -time.Minute, managementUser(t, f).TokenGeneration)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", testBearerPrefix+token)
	case "blacklisted recovery bearer refused":
		claims, err := auth.ValidateToken(f.s.jwtSecret, recovery)
		if err != nil {
			t.Fatal(err)
		}
		f.s.tokenBlacklist.Add(claims.ID, claims.ExpiresAt.Time)
		request.Header.Set("Authorization", testBearerPrefix+recovery)
	case "cookie-only recovery refused":
		request.AddCookie(&http.Cookie{Name: cookieAccess, Value: recovery})
		request.AddCookie(&http.Cookie{Name: cookieCSRF, Value: "valid-csrf"})
		request.Header.Set("X-CSRF-Token", "valid-csrf")
	default:
		t.Fatalf("unknown recovery credential case %q", mode)
	}
	return request
}

func runManagementBearerScenario(t *testing.T, mode string) {
	t.Helper()
	f := newLifecycleFixture(t)
	managementEnableExistingMFA(t, f)
	staleAccess, _, _ := sessionTokenPair(t, f.s, f.viewerID)
	reset := managementReset(t, f)
	recovery := managementRecovery(t, f, reset["temporary_password"].(string))
	request := managementRecoveryBearerRequest(t, f, mode, staleAccess, recovery)
	response := httptest.NewRecorder()
	f.s.routes().ServeHTTP(response, request)

	assertManagementBearerOutcome(t, f, mode, response)
}

func assertManagementBearerOutcome(t *testing.T, f *lifecycleFixture, mode string, response *httptest.ResponseRecorder) {
	t.Helper()
	want := http.StatusOK
	if mode != "stale cookie and valid bearer" {
		want = http.StatusUnauthorized
	}
	if response.Code != want {
		t.Fatalf("%s status %d wanted %d", mode, response.Code, want)
	}
	live := managementUser(t, f)
	if mode == "stale cookie and valid bearer" {
		if live.MustChangePassword || managementJSON(t, response)["requires_login"] != true {
			t.Fatal("explicit recovery bearer did not complete replacement")
		}
	} else if !live.MustChangePassword {
		t.Fatal("cookie-only request consumed recovery authority")
	}
}
