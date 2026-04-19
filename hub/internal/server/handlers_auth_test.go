package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
	"github.com/wyiu/aerodocs/hub/internal/notify"
	"github.com/wyiu/aerodocs/hub/internal/store"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	t.Cleanup(func() { st.Close() })

	jwtSecret, err := InitJWTSecret(st)
	if err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}

	notifier := notify.New(st)
	t.Cleanup(func() { notifier.Close() })

	return New(Config{
		Addr:      ":0",
		Store:     st,
		JWTSecret: jwtSecret,
		IsDev:     true,
		Notifier:  notifier,
	})
}

func TestAuthStatus_NotInitialized(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/api/auth/status", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200, rec.Code)
	}

	var resp model.AuthStatusResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Initialized {
		t.Fatal("expected initialized=false")
	}
}

func TestRegisterFirstUser(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(model.RegisterRequest{
		Username: "admin",
		Email:    testAdminEmail,
		Password: testPassword,
	})

	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["setup_token"] == nil {
		t.Fatal("expected setup_token in response")
	}
}

func TestRegisterBlocked_AfterFirstUser(t *testing.T) {
	s := testServer(t)

	// Register first user and complete full setup (including TOTP)
	_ = registerAndGetAdminToken(t, s)

	// Try to register again — should be blocked
	body2, _ := json.Marshal(model.RegisterRequest{
		Username: "hacker", Email: "hacker@test.com", Password: testPassword,
	})
	req2 := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(body2))
	rec2 := httptest.NewRecorder()
	s.routes().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec2.Code)
	}
}

func TestAuthStatus_RemainsInitializedAfterTOTPReset(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)

	user, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get admin user: %v", err)
	}
	if err := s.store.UpdateUserTOTP(user.ID, nil, false); err != nil {
		t.Fatalf("reset totp in store: %v", err)
	}

	statusReq := httptest.NewRequest("GET", "/api/auth/status", nil)
	statusRec := httptest.NewRecorder()
	s.routes().ServeHTTP(statusRec, statusReq)

	if statusRec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, statusRec.Code, statusRec.Body.String())
	}

	var statusResp model.AuthStatusResponse
	if err := json.NewDecoder(statusRec.Body).Decode(&statusResp); err != nil {
		t.Fatalf("decode auth status: %v", err)
	}
	if !statusResp.Initialized {
		t.Fatal("expected initialized=true after TOTP reset on a completed system")
	}

	body, _ := json.Marshal(model.RegisterRequest{
		Username: "newadmin",
		Email:    "newadmin@test.com",
		Password: testPassword,
	})
	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 after TOTP reset, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestChangePassword_Success(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.ChangePasswordRequest{
		CurrentPassword: testPassword,
		NewPassword:     "NewP@ssw0rd!567",
	})
	req := httptest.NewRequest("PUT", testPasswordPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "password updated" {
		t.Fatalf("expected status 'password updated', got '%s'", resp["status"])
	}
}

func TestChangePassword_WrongCurrent(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.ChangePasswordRequest{
		CurrentPassword: "WrongP@ssword!1",
		NewPassword:     "NewP@ssw0rd!567",
	})
	req := httptest.NewRequest("PUT", testPasswordPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401Body, rec.Code, rec.Body.String())
	}
}

func TestChangePassword_PolicyViolation(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.ChangePasswordRequest{
		CurrentPassword: testPassword,
		NewPassword:     "short",
	})
	req := httptest.NewRequest("PUT", testPasswordPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(model.LoginRequest{
		Username: "nobody", Password: "wrong",
	})
	req := httptest.NewRequest("POST", testLoginPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}

func TestLogin_Success_NeedsTOTPSetup(t *testing.T) {
	s := testServer(t)

	// Register first user — get setup token
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	// Login with correct credentials (TOTP not yet set up)
	body, _ := json.Marshal(model.LoginRequest{
		Username: "admin", Password: testPassword,
	})
	req := httptest.NewRequest("POST", testLoginPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp model.LoginResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.RequiresTOTPSetup {
		t.Fatal("expected requires_totp_setup=true")
	}
	if resp.SetupToken == "" {
		t.Fatal("expected setup_token in response")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	s := testServer(t)

	// Register user first
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	body, _ := json.Marshal(model.LoginRequest{
		Username: "admin", Password: "WrongPassword!999",
	})
	req := httptest.NewRequest("POST", testLoginPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}

func TestLogin_WithTOTPEnabled(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)

	// Now try logging in again — should return TOTP token
	body, _ := json.Marshal(model.LoginRequest{
		Username: "admin", Password: testPassword,
	})
	req := httptest.NewRequest("POST", testLoginPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp model.LoginResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TOTPToken == "" {
		t.Fatal("expected totp_token in response")
	}
}

func TestLogin_InvalidJSON(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("POST", testLoginPath, bytes.NewReader([]byte(testNotJSON)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestLoginTOTP_Success(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)

	// Login to get TOTP token
	loginBody, _ := json.Marshal(model.LoginRequest{
		Username: "admin", Password: testPassword,
	})
	loginReq := httptest.NewRequest("POST", testLoginPath, bytes.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	s.routes().ServeHTTP(loginRec, loginReq)

	var loginResp model.LoginResponse
	json.NewDecoder(loginRec.Body).Decode(&loginResp)

	// Get user's TOTP secret from store
	user, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	// Clear replay cache so the code (already used during enable) can be reused in this test
	s.totpCache.Clear()
	rawTOTP, _ := s.DecryptTOTPSecret(*user.TOTPSecret)
	code, _ := auth.GenerateValidCode(rawTOTP)

	// Login with TOTP
	totpBody, _ := json.Marshal(model.LoginTOTPRequest{
		TOTPToken: loginResp.TOTPToken,
		Code:      code,
	})
	totpReq := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader(totpBody))
	totpRec := httptest.NewRecorder()
	s.routes().ServeHTTP(totpRec, totpReq)

	if totpRec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, totpRec.Code, totpRec.Body.String())
	}

	var authResp model.AuthResponse
	json.NewDecoder(totpRec.Body).Decode(&authResp)
	if authResp.AccessToken == "" {
		t.Fatal("expected access_token in login/totp response body")
	}
	if authResp.RefreshToken == "" {
		t.Fatal("expected refresh_token in login/totp response body")
	}
}

func TestLoginTOTP_InvalidCode(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)

	// Login to get TOTP token
	loginBody, _ := json.Marshal(model.LoginRequest{
		Username: "admin", Password: testPassword,
	})
	loginReq := httptest.NewRequest("POST", testLoginPath, bytes.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	s.routes().ServeHTTP(loginRec, loginReq)

	var loginResp model.LoginResponse
	json.NewDecoder(loginRec.Body).Decode(&loginResp)

	// Use wrong code
	totpBody, _ := json.Marshal(model.LoginTOTPRequest{
		TOTPToken: loginResp.TOTPToken,
		Code:      "000000",
	})
	totpReq := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader(totpBody))
	totpRec := httptest.NewRecorder()
	s.routes().ServeHTTP(totpRec, totpReq)

	if totpRec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401Body, totpRec.Code, totpRec.Body.String())
	}
}

func TestLoginTOTP_InvalidTOTPToken(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(model.LoginTOTPRequest{
		TOTPToken: "invalid-token",
		Code:      "123456",
	})
	req := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}

func TestLoginTOTP_InvalidJSON(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader([]byte(testNotJSON)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestRefresh_ValidToken(t *testing.T) {
	s := testServer(t)

	// We need a refresh token — use registerAndGetAdminToken and call login
	_ = registerAndGetAdminToken(t, s)

	// Get refresh token via TOTP login flow
	loginBody, _ := json.Marshal(model.LoginRequest{
		Username: "admin", Password: testPassword,
	})
	loginReq := httptest.NewRequest("POST", testLoginPath, bytes.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	s.routes().ServeHTTP(loginRec, loginReq)

	var loginResp model.LoginResponse
	json.NewDecoder(loginRec.Body).Decode(&loginResp)

	user, _ := s.store.GetUserByUsername("admin")

	// Clear replay cache so the code (already used during enable) can be reused in this test
	s.totpCache.Clear()
	rawTOTP, _ := s.DecryptTOTPSecret(*user.TOTPSecret)
	code, _ := auth.GenerateValidCode(rawTOTP)

	totpBody, _ := json.Marshal(model.LoginTOTPRequest{
		TOTPToken: loginResp.TOTPToken,
		Code:      code,
	})
	totpReq := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader(totpBody))
	totpRec := httptest.NewRecorder()
	s.routes().ServeHTTP(totpRec, totpReq)

	// Now refresh
	refreshCookie := findCookie(totpRec.Result().Cookies(), cookieRefresh)
	if refreshCookie == nil {
		t.Fatal("expected refresh cookie after login/totp")
	}
	refreshReq := httptest.NewRequest("POST", testRefreshPath, nil)
	refreshReq.AddCookie(refreshCookie)
	refreshRec := httptest.NewRecorder()
	s.routes().ServeHTTP(refreshRec, refreshReq)

	if refreshRec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, refreshRec.Code, refreshRec.Body.String())
	}

	var tokenPair model.TokenPair
	json.NewDecoder(refreshRec.Body).Decode(&tokenPair)
	if tokenPair.AccessToken == "" {
		t.Fatal("expected access_token in refresh response body")
	}
	if tokenPair.RefreshToken == "" {
		t.Fatal("expected refresh_token in refresh response body")
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(model.RefreshRequest{
		RefreshToken: "invalid-token",
	})
	req := httptest.NewRequest("POST", testRefreshPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}

func TestRefresh_AccessTokenAsRefresh(t *testing.T) {
	s := testServer(t)
	accessToken := registerAndGetAdminToken(t, s)

	// Use access token where refresh token is expected
	body, _ := json.Marshal(model.RefreshRequest{
		RefreshToken: accessToken,
	})
	req := httptest.NewRequest("POST", testRefreshPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}

func TestRefresh_InvalidJSON(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("POST", testRefreshPath, bytes.NewReader([]byte(testNotJSON)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestTOTPSetup_Success(t *testing.T) {
	s := testServer(t)

	// Register to get setup token
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	var regResp map[string]interface{}
	json.NewDecoder(regRec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	req := httptest.NewRequest("POST", testTOTPSetupPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+setupToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp model.TOTPSetupResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Secret == "" {
		t.Fatal("expected secret in response")
	}
	if resp.QRURL == "" {
		t.Fatal("expected qr_url in response")
	}
}

func TestTOTPEnable_Success(t *testing.T) {
	s := testServer(t)

	// Register and setup TOTP, then enable
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	var regResp map[string]interface{}
	json.NewDecoder(regRec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	// Setup TOTP
	setupReq := httptest.NewRequest("POST", testTOTPSetupPath, nil)
	setupReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	setupRec := httptest.NewRecorder()
	s.routes().ServeHTTP(setupRec, setupReq)

	var totpResp model.TOTPSetupResponse
	json.NewDecoder(setupRec.Body).Decode(&totpResp)

	// Enable TOTP with valid code
	code, _ := auth.GenerateValidCode(totpResp.Secret)
	enableBody, _ := json.Marshal(model.TOTPEnableRequest{Code: code})
	enableReq := httptest.NewRequest("POST", testTOTPEnablePath, bytes.NewReader(enableBody))
	enableReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	enableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(enableRec, enableReq)

	if enableRec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, enableRec.Code, enableRec.Body.String())
	}

	var authResp model.AuthResponse
	json.NewDecoder(enableRec.Body).Decode(&authResp)
	if authResp.AccessToken == "" {
		t.Fatal("expected access_token in TOTP enable response body")
	}
	if authResp.RefreshToken == "" {
		t.Fatal("expected refresh_token in TOTP enable response body")
	}
	if !authResp.User.TOTPEnabled {
		t.Fatal("expected totp_enabled=true")
	}
}

func TestTOTPEnable_InvalidCode(t *testing.T) {
	s := testServer(t)

	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	var regResp map[string]interface{}
	json.NewDecoder(regRec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	setupReq := httptest.NewRequest("POST", testTOTPSetupPath, nil)
	setupReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	setupRec := httptest.NewRecorder()
	s.routes().ServeHTTP(setupRec, setupReq)

	enableBody, _ := json.Marshal(model.TOTPEnableRequest{Code: "000000"})
	enableReq := httptest.NewRequest("POST", testTOTPEnablePath, bytes.NewReader(enableBody))
	enableReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	enableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(enableRec, enableReq)

	if enableRec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401Body, enableRec.Code, enableRec.Body.String())
	}
}

func TestTOTPEnable_NotSetUp(t *testing.T) {
	s := testServer(t)

	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	var regResp map[string]interface{}
	json.NewDecoder(regRec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	// Try to enable without calling setup first
	enableBody, _ := json.Marshal(model.TOTPEnableRequest{Code: "123456"})
	enableReq := httptest.NewRequest("POST", testTOTPEnablePath, bytes.NewReader(enableBody))
	enableReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	enableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(enableRec, enableReq)

	if enableRec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, enableRec.Code, enableRec.Body.String())
	}
}

func TestTOTPEnable_InvalidJSON(t *testing.T) {
	s := testServer(t)

	// Get a setup token (TOTP enable requires setup token)
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	var regResp map[string]interface{}
	json.NewDecoder(regRec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	req := httptest.NewRequest("POST", testTOTPEnablePath, bytes.NewReader([]byte(testNotJSON)))
	req.Header.Set("Authorization", testBearerPrefix+setupToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestTOTPDisable_Success(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Create viewer user
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	// Get viewer's user id
	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+viewerToken)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)

	var viewerUser model.User
	json.NewDecoder(meRec.Body).Decode(&viewerUser)

	// Get admin's TOTP secret
	adminUser, _ := s.store.GetUserByUsername("admin")

	// Clear replay cache so the code (already used during enable) can be reused in this test
	s.totpCache.Clear()
	rawAdminTOTP, _ := s.DecryptTOTPSecret(*adminUser.TOTPSecret)
	adminCode, _ := auth.GenerateValidCode(rawAdminTOTP)

	// Disable viewer's TOTP
	disableBody, _ := json.Marshal(model.TOTPDisableRequest{
		UserID:        viewerUser.ID,
		AdminTOTPCode: adminCode,
	})
	disableReq := httptest.NewRequest("POST", testTOTPDisablePath, bytes.NewReader(disableBody))
	disableReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	disableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(disableRec, disableReq)

	if disableRec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, disableRec.Code, disableRec.Body.String())
	}
}

func TestTOTPDisable_WrongAdminCode(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	viewerToken := createViewerAndGetToken(t, s, adminToken)

	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+viewerToken)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)

	var viewerUser model.User
	json.NewDecoder(meRec.Body).Decode(&viewerUser)

	disableBody, _ := json.Marshal(model.TOTPDisableRequest{
		UserID:        viewerUser.ID,
		AdminTOTPCode: "000000",
	})
	disableReq := httptest.NewRequest("POST", testTOTPDisablePath, bytes.NewReader(disableBody))
	disableReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	disableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(disableRec, disableReq)

	if disableRec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401Body, disableRec.Code, disableRec.Body.String())
	}
}

func TestTOTPDisable_InvalidJSON(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("POST", testTOTPDisablePath, bytes.NewReader([]byte(testNotJSON)))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestTOTPSetup_AlreadyEnabled(t *testing.T) {
	s := testServer(t)

	// Register to get setup token
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	var regResp map[string]interface{}
	json.NewDecoder(regRec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	// Setup TOTP
	setupReq := httptest.NewRequest("POST", testTOTPSetupPath, nil)
	setupReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	setupRec := httptest.NewRecorder()
	s.routes().ServeHTTP(setupRec, setupReq)

	var totpResp model.TOTPSetupResponse
	json.NewDecoder(setupRec.Body).Decode(&totpResp)

	// Enable TOTP
	code, _ := auth.GenerateValidCode(totpResp.Secret)
	enableBody, _ := json.Marshal(model.TOTPEnableRequest{Code: code})
	enableReq := httptest.NewRequest("POST", testTOTPEnablePath, bytes.NewReader(enableBody))
	enableReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	enableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(enableRec, enableReq)

	if enableRec.Code != http.StatusOK {
		t.Fatalf("enable failed: %d: %s", enableRec.Code, enableRec.Body.String())
	}

	// Try to setup TOTP again — should get 409
	setupReq2 := httptest.NewRequest("POST", testTOTPSetupPath, nil)
	setupReq2.Header.Set("Authorization", testBearerPrefix+setupToken)
	setupRec2 := httptest.NewRecorder()
	s.routes().ServeHTTP(setupRec2, setupReq2)

	if setupRec2.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict, got %d: %s", setupRec2.Code, setupRec2.Body.String())
	}
}

func TestTOTPDisable_AdminSelfDisable(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Get admin user ID
	adminUser, _ := s.store.GetUserByUsername("admin")

	s.totpCache.Clear()
	rawAdminTOTP, _ := s.DecryptTOTPSecret(*adminUser.TOTPSecret)
	adminCode, _ := auth.GenerateValidCode(rawAdminTOTP)

	body, _ := json.Marshal(model.TOTPDisableRequest{
		UserID:        adminUser.ID,
		AdminTOTPCode: adminCode,
	})
	req := httptest.NewRequest("POST", testTOTPDisablePath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMe(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", testMePath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var user model.User
	json.NewDecoder(rec.Body).Decode(&user)
	if user.Username != "admin" {
		t.Fatalf("expected username 'admin', got '%s'", user.Username)
	}
}

func TestUpdateAvatar_Success(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.UpdateAvatarRequest{
		Avatar: "data:image/png;base64,abc123",
	})
	req := httptest.NewRequest("PUT", testAvatarPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

func TestUpdateAvatar_TooLarge(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Generate a large avatar string (>700KB)
	largeAvatar := make([]byte, 700001)
	for i := range largeAvatar {
		largeAvatar[i] = 'a'
	}

	body, _ := json.Marshal(model.UpdateAvatarRequest{
		Avatar: string(largeAvatar),
	})
	req := httptest.NewRequest("PUT", testAvatarPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
}

func TestUpdateAvatar_InvalidJSON(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("PUT", testAvatarPath, bytes.NewReader([]byte(testNotJSON)))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestRegister_InvalidJSON(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader([]byte(testNotJSON)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestRegister_InvalidUsername(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(model.RegisterRequest{
		Username: "ab", // too short
		Email:    "test@test.com",
		Password: testPassword,
	})
	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(model.RegisterRequest{
		Username: "admin",
		Email:    "test@test.com",
		Password: "weak",
	})
	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestAuthStatus_Initialized(t *testing.T) {
	s := testServer(t)

	// Complete full setup (register + TOTP)
	_ = registerAndGetAdminToken(t, s)

	// Check status
	statusReq := httptest.NewRequest("GET", "/api/auth/status", nil)
	statusRec := httptest.NewRecorder()
	s.routes().ServeHTTP(statusRec, statusReq)

	if statusRec.Code != http.StatusOK {
		t.Fatalf(testExpected200, statusRec.Code)
	}

	var resp model.AuthStatusResponse
	json.NewDecoder(statusRec.Body).Decode(&resp)
	if !resp.Initialized {
		t.Fatal("expected initialized=true after full setup")
	}
}

func TestLoginTOTP_WrongTokenType(t *testing.T) {
	s := testServer(t)
	accessToken := registerAndGetAdminToken(t, s)

	// Use access token as totp_token (wrong type)
	body, _ := json.Marshal(model.LoginTOTPRequest{
		TOTPToken: accessToken,
		Code:      "123456",
	})
	req := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}
