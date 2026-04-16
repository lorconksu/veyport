package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
)

// registerAndLoginWithCookies performs the full register -> TOTP setup -> TOTP enable
// flow and returns the response recorder from TOTP enable, which contains Set-Cookie
// headers. It also returns the TOTP secret for later login flows.
func registerAndLoginWithCookies(t *testing.T, s *Server) (cookies []*http.Cookie, totpSecret string) {
	t.Helper()
	router := s.routes()

	// Step 1: Register
	body, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var regResp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	// Step 2: TOTP setup
	req2 := httptest.NewRequest("POST", testTOTPSetupPath, nil)
	req2.Header.Set("Authorization", testBearerPrefix+setupToken)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("totp setup: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	var totpResp model.TOTPSetupResponse
	json.NewDecoder(rec2.Body).Decode(&totpResp)

	// Step 3: TOTP enable (this sets auth cookies)
	code, _ := auth.GenerateValidCode(totpResp.Secret)
	enableBody, _ := json.Marshal(model.TOTPEnableRequest{Code: code})
	req3 := httptest.NewRequest("POST", testTOTPEnablePath, bytes.NewReader(enableBody))
	req3.Header.Set("Authorization", testBearerPrefix+setupToken)
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("totp enable: expected 200, got %d: %s", rec3.Code, rec3.Body.String())
	}

	return rec3.Result().Cookies(), totpResp.Secret
}

// loginWithCookies performs login -> TOTP verify flow and returns response cookies.
// The user must already be registered with TOTP enabled.
func loginWithCookies(t *testing.T, s *Server, totpSecret string) []*http.Cookie {
	t.Helper()
	router := s.routes()

	// Step 1: Login (returns TOTP token)
	body, _ := json.Marshal(model.LoginRequest{
		Username: "admin", Password: testPassword,
	})
	req := httptest.NewRequest("POST", testLoginPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("login: expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	var loginResp model.LoginResponse
	json.NewDecoder(rec.Body).Decode(&loginResp)

	// Step 2: TOTP verify (sets cookies)
	code, _ := auth.GenerateValidCode(totpSecret)
	totpBody, _ := json.Marshal(model.LoginTOTPRequest{
		TOTPToken: loginResp.TOTPToken,
		Code:      code,
	})
	req2 := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader(totpBody))
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("login totp: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	return rec2.Result().Cookies()
}

// addCookies adds cookies to a request.
func addCookies(r *http.Request, cookies []*http.Cookie) {
	for _, c := range cookies {
		r.AddCookie(c)
	}
}

func TestCookieAuth_LoginSetsCookies(t *testing.T) {
	s := testServer(t)
	cookies, _ := registerAndLoginWithCookies(t, s)

	access := findCookie(cookies, cookieAccess)
	refresh := findCookie(cookies, cookieRefresh)
	csrf := findCookie(cookies, cookieCSRF)

	if access == nil {
		t.Fatal("missing aerodocs_access cookie")
	}
	if !access.HttpOnly {
		t.Error("aerodocs_access should be httpOnly")
	}

	if refresh == nil {
		t.Fatal("missing aerodocs_refresh cookie")
	}
	if !refresh.HttpOnly {
		t.Error("aerodocs_refresh should be httpOnly")
	}
	if refresh.Path != testRefreshPath {
		t.Errorf("aerodocs_refresh path = %q, want /api/auth/refresh", refresh.Path)
	}

	if csrf == nil {
		t.Fatal("missing aerodocs_csrf cookie")
	}
	if csrf.HttpOnly {
		t.Error("aerodocs_csrf should NOT be httpOnly (JS needs to read it)")
	}
}

func TestCookieAuth_LoginResponseStillContainsTokens(t *testing.T) {
	s := testServer(t)
	router := s.routes()

	// Register and get TOTP secret
	_, totpSecret := registerAndLoginWithCookies(t, s)

	// Clear TOTP replay cache so we can reuse the code within the same 30s window
	s.totpCache.Clear()

	// Login again via the normal login flow
	body, _ := json.Marshal(model.LoginRequest{
		Username: "admin", Password: testPassword,
	})
	req := httptest.NewRequest("POST", testLoginPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	var loginResp model.LoginResponse
	json.NewDecoder(rec.Body).Decode(&loginResp)

	code, _ := auth.GenerateValidCode(totpSecret)
	totpBody, _ := json.Marshal(model.LoginTOTPRequest{
		TOTPToken: loginResp.TOTPToken,
		Code:      code,
	})
	req2 := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader(totpBody))
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("login totp: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	var authResp model.AuthResponse
	json.NewDecoder(rec2.Body).Decode(&authResp)

	if authResp.AccessToken == "" {
		t.Error("expected access_token in response body")
	}
	if authResp.RefreshToken == "" {
		t.Error("expected refresh_token in response body")
	}
}

func TestCookieAuth_RequestWithCookieOnly(t *testing.T) {
	s := testServer(t)
	cookies, _ := registerAndLoginWithCookies(t, s)

	// GET /api/auth/me using only cookies (no Bearer header)
	req := httptest.NewRequest("GET", testMePath, nil)
	addCookies(req, cookies)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var user model.User
	json.NewDecoder(rec.Body).Decode(&user)
	if user.Username != "admin" {
		t.Errorf("expected username 'admin', got %q", user.Username)
	}
}

func TestCookieAuth_PostWithoutCSRF(t *testing.T) {
	s := testServer(t)
	cookies, _ := registerAndLoginWithCookies(t, s)

	// POST /api/auth/logout with cookies but NO X-CSRF-Token header.
	// Since logout route has no auth requirement but CSRF middleware is global,
	// and request has cookies, it should be rejected.
	//
	// Use a POST endpoint that requires auth and uses cookie auth.
	// Try changing password — it requires access token auth.
	body, _ := json.Marshal(map[string]string{
		"current_password": testPassword,
		"new_password":     "NewP@ssw0rd!567",
	})
	req := httptest.NewRequest("PUT", testPasswordPath, bytes.NewReader(body))
	addCookies(req, cookies)
	// Deliberately omit X-CSRF-Token
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (CSRF validation failed), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuth_PostWithCSRF(t *testing.T) {
	s := testServer(t)
	cookies, _ := registerAndLoginWithCookies(t, s)

	csrfCookie := findCookie(cookies, cookieCSRF)
	if csrfCookie == nil {
		t.Fatal("missing CSRF cookie")
	}

	// PUT /api/auth/password with cookies AND matching X-CSRF-Token header
	body, _ := json.Marshal(map[string]string{
		"current_password": testPassword,
		"new_password":     "NewP@ssw0rd!567",
	})
	req := httptest.NewRequest("PUT", testPasswordPath, bytes.NewReader(body))
	addCookies(req, cookies)
	req.Header.Set(testCSRFTokenHdr, csrfCookie.Value)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid CSRF, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCookieAuth_RefreshViaCookie(t *testing.T) {
	s := testServer(t)
	cookies, _ := registerAndLoginWithCookies(t, s)

	refreshCookie := findCookie(cookies, cookieRefresh)
	if refreshCookie == nil {
		t.Fatal("missing refresh cookie")
	}

	// POST /api/auth/refresh with only the refresh cookie (no body).
	// The refresh endpoint is public (no auth middleware) and CSRF middleware
	// exempts requests without access/CSRF cookies. But we send the refresh
	// cookie which is scoped to /api/auth/refresh path, so only that cookie
	// is present. Since there's no aerodocs_access or aerodocs_csrf cookie
	// in the request, CSRF middleware will pass through.
	req := httptest.NewRequest("POST", testRefreshPath, nil)
	req.AddCookie(refreshCookie)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for cookie-based refresh, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify new cookies are set
	newCookies := rec.Result().Cookies()
	newAccess := findCookie(newCookies, cookieAccess)
	newRefresh := findCookie(newCookies, cookieRefresh)
	newCSRF := findCookie(newCookies, cookieCSRF)

	if newAccess == nil {
		t.Error("refresh response should set new access cookie")
	}
	if newRefresh == nil {
		t.Error("refresh response should set new refresh cookie")
	}
	if newCSRF == nil {
		t.Error("refresh response should set new CSRF cookie")
	}

	// Verify response body still contains tokens
	var tokenPair model.TokenPair
	json.NewDecoder(rec.Body).Decode(&tokenPair)
	if tokenPair.AccessToken == "" {
		t.Error("expected access_token in refresh response body")
	}
	if tokenPair.RefreshToken == "" {
		t.Error("expected refresh_token in refresh response body")
	}
}

func TestCookieAuth_Logout(t *testing.T) {
	s := testServer(t)
	cookies, _ := registerAndLoginWithCookies(t, s)

	csrfCookie := findCookie(cookies, cookieCSRF)
	if csrfCookie == nil {
		t.Fatal("missing CSRF cookie")
	}

	// POST /api/auth/logout with cookies and CSRF token
	req := httptest.NewRequest("POST", testLogoutPath, nil)
	addCookies(req, cookies)
	req.Header.Set(testCSRFTokenHdr, csrfCookie.Value)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify cookies are cleared (MaxAge=-1)
	clearCookies := rec.Result().Cookies()
	for _, name := range []string{cookieAccess, cookieRefresh, cookieCSRF} {
		c := findCookie(clearCookies, name)
		if c == nil {
			t.Errorf("expected cleared cookie %q in response", name)
			continue
		}
		if c.MaxAge != -1 {
			t.Errorf("cookie %q MaxAge = %d, want -1", name, c.MaxAge)
		}
	}
}
