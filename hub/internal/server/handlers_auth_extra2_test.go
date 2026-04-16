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

// TestHandleTOTPSetup_WithSetupToken verifies that TOTP setup works via setup token.
func TestHandleTOTPSetup_WithSetupToken(t *testing.T) {
	s := testServer(t)

	// Register to get setup_token
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	var regResp map[string]interface{}
	json.NewDecoder(regRec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	// Call /api/auth/totp/setup using setup token
	setupReq := httptest.NewRequest("POST", testTOTPSetupPath, nil)
	setupReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	setupRec := httptest.NewRecorder()
	s.routes().ServeHTTP(setupRec, setupReq)

	if setupRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for TOTP setup, got %d: %s", setupRec.Code, setupRec.Body.String())
	}

	var totpResp model.TOTPSetupResponse
	json.NewDecoder(setupRec.Body).Decode(&totpResp)
	if totpResp.Secret == "" {
		t.Fatal("expected non-empty TOTP secret")
	}
	if totpResp.QRURL == "" {
		t.Fatal("expected non-empty QR URL")
	}
}

// TestHandleTOTPEnable_InvalidCode verifies that wrong TOTP code returns 401.
func TestHandleTOTPEnable_InvalidCode(t *testing.T) {
	s := testServer(t)

	// Register to get setup_token
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	var regResp map[string]interface{}
	json.NewDecoder(regRec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	// Call /api/auth/totp/setup
	setupReq := httptest.NewRequest("POST", testTOTPSetupPath, nil)
	setupReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	setupRec := httptest.NewRecorder()
	s.routes().ServeHTTP(setupRec, setupReq)

	// Now try to enable with wrong code
	enableBody, _ := json.Marshal(model.TOTPEnableRequest{Code: "000000"})
	enableReq := httptest.NewRequest("POST", testTOTPEnablePath, bytes.NewReader(enableBody))
	enableReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	enableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(enableRec, enableReq)

	if enableRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid TOTP code, got %d: %s", enableRec.Code, enableRec.Body.String())
	}
}

// TestHandleTOTPEnable_NoSetup verifies that enabling TOTP without setup first returns 400.
func TestHandleTOTPEnable_NoSetup(t *testing.T) {
	s := testServer(t)

	// Register to get setup_token
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	var regResp map[string]interface{}
	json.NewDecoder(regRec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	// Try to enable TOTP without calling setup first
	enableBody, _ := json.Marshal(model.TOTPEnableRequest{Code: "123456"})
	enableReq := httptest.NewRequest("POST", testTOTPEnablePath, bytes.NewReader(enableBody))
	enableReq.Header.Set("Authorization", testBearerPrefix+setupToken)
	enableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(enableRec, enableReq)

	if enableRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when TOTP not set up, got %d: %s", enableRec.Code, enableRec.Body.String())
	}
}

// TestHandleLoginTOTP_InvalidToken verifies that invalid TOTP token returns 401.
func TestHandleLoginTOTP_InvalidToken(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(model.LoginTOTPRequest{
		TOTPToken: "invalid-token",
		Code:      "123456",
	})
	req := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid TOTP token, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleLoginTOTP_InvalidCode verifies that wrong TOTP code at login returns 401.
func TestHandleLoginTOTP_InvalidCode(t *testing.T) {
	s := testServer(t)

	// Create a user with TOTP fully set up
	adminToken := registerAndGetAdminToken(t, s)
	_ = adminToken

	// Now try to log in with the TOTP flow but wrong code
	// First, we need a valid totp_token from login
	user, _ := s.store.GetUserByUsername("admin")
	totpToken, _ := auth.GenerateTOTPToken(s.jwtSecret, user.ID, string(user.Role))

	body, _ := json.Marshal(model.LoginTOTPRequest{
		TOTPToken: totpToken,
		Code:      "000000", // wrong code
	})
	req := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid TOTP code, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleRefresh_ValidToken verifies successful token refresh.
func TestHandleRefresh_ValidToken(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)

	user, _ := s.store.GetUserByUsername("admin")
	_, refreshToken, _ := auth.GenerateTokenPair(s.jwtSecret, user.ID, string(user.Role), user.TokenGeneration)

	body, _ := json.Marshal(model.RefreshRequest{RefreshToken: refreshToken})
	req := httptest.NewRequest("POST", testRefreshPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp model.TokenPair
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.AccessToken == "" {
		t.Fatal("expected access token in refresh response body")
	}
	if resp.RefreshToken == "" {
		t.Fatal("expected refresh token in refresh response body")
	}
}

// TestHandleRefresh_UseAccessTokenReturns401 verifies access token cannot be used for refresh.
func TestHandleRefresh_UseAccessToken(t *testing.T) {
	s := testServer(t)
	accessToken := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.RefreshRequest{RefreshToken: accessToken})
	req := httptest.NewRequest("POST", testRefreshPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when using access token for refresh, got %d", rec.Code)
	}
}

// TestHandleTOTPDisable_WrongAdminCode verifies wrong admin TOTP code returns 401.
func TestHandleTOTPDisable_WrongAdminCode(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	disableBody, _ := json.Marshal(model.TOTPDisableRequest{
		UserID:        "some-user-id",
		AdminTOTPCode: "000000", // wrong code
	})
	disableReq := httptest.NewRequest("POST", testTOTPDisablePath, bytes.NewReader(disableBody))
	disableReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	disableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(disableRec, disableReq)

	if disableRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong admin TOTP code, got %d: %s", disableRec.Code, disableRec.Body.String())
	}
}

// TestHandleTOTPDisable_Success verifies successfully disabling another user's TOTP.
func TestHandleTOTPDisable_Success(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	adminUser, _ := s.store.GetUserByUsername("admin")

	// Create a second user to disable TOTP on (admin cannot self-disable)
	targetUser := &model.User{
		ID:           "target-user-id",
		Username:     "targetuser",
		Email:        "target@example.com",
		PasswordHash: "$2a$12$fakehashfakehashfakehashfakehashfakehashfakehashfake",
		Role:         "viewer",
	}
	if err := s.store.CreateUser(targetUser); err != nil {
		t.Fatalf("create target user: %v", err)
	}
	secret := "JBSWY3DPEHPK3PXP"
	s.store.UpdateUserTOTP(targetUser.ID, &secret, true)

	// Clear replay cache
	s.totpCache.Clear()

	// Generate a valid TOTP code for the admin (proving admin identity)
	rawAdminTOTP, _ := s.DecryptTOTPSecret(*adminUser.TOTPSecret)
	adminCode, err := auth.GenerateValidCode(rawAdminTOTP)
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}

	// Disable TOTP for the target user (not self)
	disableBody, _ := json.Marshal(model.TOTPDisableRequest{
		UserID:        targetUser.ID,
		AdminTOTPCode: adminCode,
	})
	disableReq := httptest.NewRequest("POST", testTOTPDisablePath, bytes.NewReader(disableBody))
	disableReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	disableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(disableRec, disableReq)

	if disableRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for TOTP disable, got %d: %s", disableRec.Code, disableRec.Body.String())
	}
}

// TestHandleRegister_InvalidBody verifies invalid JSON body returns 400.
func TestHandleRegister_InvalidBody(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader([]byte(testNotJSON)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

// TestHandleRegister_WeakPassword verifies weak password returns 400.
func TestHandleRegister_WeakPassword(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: "weak",
	})
	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

// TestHandleUpdateAvatar_TooLarge verifies large avatar returns 400.
func TestHandleUpdateAvatar_TooLarge(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Create a large avatar (over 700KB)
	largeAvatar := make([]byte, 750000)
	for i := range largeAvatar {
		largeAvatar[i] = 'a'
	}

	body, _ := json.Marshal(model.UpdateAvatarRequest{Avatar: string(largeAvatar)})
	req := httptest.NewRequest("PUT", testAvatarPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized avatar, got %d", rec.Code)
	}
}

// TestHandleLogin_InvalidBody verifies invalid JSON body returns 400.
func TestHandleLogin_InvalidBody(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("POST", testLoginPath, bytes.NewReader([]byte(testNotJSON)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

// TestHandleLoginTOTP_InvalidBody verifies invalid JSON body returns 400.
func TestHandleLoginTOTP_InvalidBody(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("POST", testLoginTOTPPath, bytes.NewReader([]byte(testNotJSON)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

// TestHandleTOTPDisable_InvalidBody verifies invalid JSON body returns 400.
func TestHandleTOTPDisable_InvalidBody(t *testing.T) {
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

// TestHandleTOTPEnable_InvalidBody verifies invalid JSON body returns 400.
func TestHandleTOTPEnable_InvalidBody(t *testing.T) {
	s := testServer(t)

	// Register to get setup_token
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

// TestHandleRegister_InvalidUsername verifies invalid username returns 400.
func TestHandleRegister_InvalidUsername(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(model.RegisterRequest{
		Username: "ab", // too short
		Email:    testAdminEmail,
		Password: testPassword,
	})
	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}
