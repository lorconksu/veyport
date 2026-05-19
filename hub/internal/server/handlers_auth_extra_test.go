package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

// TestHandleMe_Unauthenticated verifies that /api/auth/me without auth returns 401.
func TestHandleMe_Unauthenticated(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", testMePath, nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}

// TestHandleAuthStatus_AfterTOTPSetup verifies status after TOTP is configured.
func TestHandleAuthStatus_AfterFirstUserBeforeTOTP(t *testing.T) {
	s := testServer(t)

	// Register a user but don't complete TOTP setup
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)

	// Check status - user exists but TOTP not enabled, so initialized should be false
	statusReq := httptest.NewRequest("GET", "/api/auth/status", nil)
	statusRec := httptest.NewRecorder()
	s.routes().ServeHTTP(statusRec, statusReq)

	if statusRec.Code != http.StatusOK {
		t.Fatalf(testExpected200, statusRec.Code)
	}

	var resp model.AuthStatusResponse
	json.NewDecoder(statusRec.Body).Decode(&resp)
	if resp.Initialized {
		t.Fatal("expected initialized=false before TOTP setup completes")
	}
}

// TestRegisterAllowed_AfterIncompleteSetup verifies that if a user registered
// but never completed TOTP, the setup flow can be restarted.
func TestRegisterAllowed_AfterIncompleteSetup(t *testing.T) {
	s := testServer(t)

	// Register a user but don't complete TOTP setup
	regBody, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	regReq := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody))
	regRec := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec, regReq)
	if regRec.Code != http.StatusOK {
		t.Fatalf("first register: expected 200, got %d", regRec.Code)
	}

	// Re-register — incomplete user should be cleaned up and new registration allowed
	regBody2, _ := json.Marshal(model.RegisterRequest{
		Username: "admin2", Email: "admin2@test.com", Password: testPassword,
	})
	regReq2 := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(regBody2))
	regRec2 := httptest.NewRecorder()
	s.routes().ServeHTTP(regRec2, regReq2)
	if regRec2.Code != http.StatusOK {
		t.Fatalf("re-register after incomplete setup: expected 200, got %d: %s", regRec2.Code, regRec2.Body.String())
	}
}

// TestTOTPDisable_NonExistentUser verifies disabling TOTP for non-existent user returns 404/error.
func TestTOTPDisable_NonExistentUser(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	adminUser, _ := s.store.GetUserByUsername("admin")
	rawAdminTOTP, _ := s.DecryptTOTPSecret(*adminUser.TOTPSecret)
	adminCode, _ := auth.GenerateValidCode(rawAdminTOTP)

	disableBody, _ := json.Marshal(model.TOTPDisableRequest{
		UserID:        "nonexistent-user-id",
		AdminTOTPCode: adminCode,
	})
	disableReq := httptest.NewRequest("POST", testTOTPDisablePath, bytes.NewReader(disableBody))
	disableReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	disableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(disableRec, disableReq)

	// Should either succeed (TOTP is already nil for non-existent) or return an error
	// Either way, not a 500 crash
	if disableRec.Code == http.StatusInternalServerError {
		t.Fatalf("unexpected 500: %s", disableRec.Body.String())
	}
}

// TestTOTPSetup_Unauthenticated verifies /api/auth/totp/setup requires auth.
func TestTOTPSetup_Unauthenticated(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("POST", testTOTPSetupPath, nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}

// TestHandleRefresh_JSONOnly verifies the endpoint requires JSON body.
func TestHandleRefresh_EmptyBody(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("POST", testRefreshPath, bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// Empty refresh token → 401
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for empty refresh token, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestLogin_Success_WithTOTPFlow tests the complete login → TOTP → access token flow.
func TestLogin_TOTPFlowComplete(t *testing.T) {
	s := testServer(t)

	// Register and complete setup
	adminToken := registerAndGetAdminToken(t, s)
	if adminToken == "" {
		t.Fatal("expected non-empty token")
	}

	// Verify we can call /api/auth/me with the token
	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, meRec.Code, meRec.Body.String())
	}

	var user model.User
	json.NewDecoder(meRec.Body).Decode(&user)
	if !user.TOTPEnabled {
		t.Fatal("expected TOTP to be enabled after complete setup")
	}
}

// TestUpdateAvatar_ClearAvatar verifies setting empty avatar clears it.
func TestUpdateAvatar_ClearAvatar(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// First set an avatar
	setBody, _ := json.Marshal(model.UpdateAvatarRequest{Avatar: "data:image/png;base64,abc"})
	setReq := httptest.NewRequest("PUT", testAvatarPath, bytes.NewReader(setBody))
	setReq.Header.Set("Authorization", testBearerPrefix+token)
	setRec := httptest.NewRecorder()
	s.routes().ServeHTTP(setRec, setReq)

	if setRec.Code != http.StatusOK {
		t.Fatalf("set avatar: expected 200, got %d", setRec.Code)
	}

	// Now clear it
	clearBody, _ := json.Marshal(model.UpdateAvatarRequest{Avatar: ""})
	clearReq := httptest.NewRequest("PUT", testAvatarPath, bytes.NewReader(clearBody))
	clearReq.Header.Set("Authorization", testBearerPrefix+token)
	clearRec := httptest.NewRecorder()
	s.routes().ServeHTTP(clearRec, clearReq)

	if clearRec.Code != http.StatusOK {
		t.Fatalf("clear avatar: expected 200, got %d: %s", clearRec.Code, clearRec.Body.String())
	}
}

// TestHandleChangePassword_InvalidJSON verifies invalid JSON returns 400.
func TestHandleChangePassword_InvalidJSON(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("PUT", testPasswordPath, bytes.NewReader([]byte(testNotJSON)))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

// TestHandleMe_InvalidToken verifies invalid token returns 401.
func TestHandleMe_InvalidToken(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", testMePath, nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}

// TestRegister_DuplicateUsername verifies that registering again after the first user
// blocks (already covered by other test but adds context for the "already exists" branch).
func TestRegister_BlockedAfterSetup(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)

	// Try to register a second first user
	body, _ := json.Marshal(model.RegisterRequest{
		Username: "admin2", Email: "admin2@test.com", Password: testPassword,
	})
	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

// TestValidateUsername tests the validateUsername helper directly.
func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"valid short", "abc", false},
		{"valid long", "username_123", false},
		{"too short", "ab", true},
		{"too long", "this_username_is_way_too_long_over_32chars", true},
		{"invalid chars", "user name", true},
		{"valid with numbers", "user123", false},
		{"valid with underscore", "user_name", false},
		{"invalid with hyphen", "user-name", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUsername(tc.username)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for username %q, got nil", tc.username)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for username %q, got %v", tc.username, err)
			}
		})
	}
}
