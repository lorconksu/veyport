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

// Shared test constants used across multiple test files in the server package.
const (
	testBearerPrefix    = "Bearer "
	testPassword        = "MyP@ssw0rd!234"
	testNewPassword     = "NewP@ssw0rd!567"
	testAdminEmail      = "admin@test.com"
	testRegisterPath    = "/api/auth/register"
	testMePath          = "/api/auth/me"
	testLoginPath       = "/api/auth/login"
	testLoginTOTPPath   = "/api/auth/login/totp"
	testRefreshPath     = "/api/auth/refresh"
	testLogoutPath      = "/api/auth/logout"
	testPasswordPath    = "/api/auth/password"
	testAvatarPath      = "/api/auth/avatar"
	testTOTPSetupPath   = "/api/auth/totp/setup"
	testTOTPEnablePath  = "/api/auth/totp/enable"
	testTOTPDisablePath = "/api/auth/totp/disable"
	testServersPrefix   = "/api/servers/"
	testServersPath     = "/api/servers"
	testUsersPath       = "/api/users"
	testUsersPrefix     = "/api/users/"
	testSMTPPath        = "/api/settings/smtp"
	testSMTPTestPath    = "/api/settings/smtp/test"
	testPrefsPath       = "/api/notifications/preferences"
	testNotifLogPath    = "/api/notifications/log"
	testAuditLogsPath   = "/api/audit-logs"
	testHubSettingsPath = "/api/settings/hub"
	testContentType     = "Content-Type"
	testUploadSuffix    = "/upload"
	testDropzoneSuffix  = "/dropzone"
	testPathsSuffix     = "/paths"
	testUnregSuffix     = "/unregister"
	testSelfUnregSuffix = "/self-unregister"
	testFilesSuffix     = "/files"
	testLogsTailSuffix  = "/logs/tail"
	testNotJSON         = "not-json"
	testJWTSecret       = "test-secret-key-256-bits-long!!!"
	testUserID1         = "user-1"
	testFromCookie      = "from-cookie"
	testMemoryDB        = ":memory:"
	testCreateStoreErr  = "create store: %v"
	testVarLog          = "/var/log"
	testExpected200     = "expected 200, got %d"
	testExpected200Body = "expected 200, got %d: %s"
	testExpected400     = "expected 400, got %d"
	testExpected400Body = "expected 400, got %d: %s"
	testExpected401     = "expected 401, got %d"
	testExpected401Body = "expected 401, got %d: %s"
	testUnregTokenHdr   = "X-Unregister-Token"
	testCSRFTokenHdr    = "X-CSRF-Token"
	testXForwardedFor   = "X-Forwarded-For"
	testCSPHeader       = "Content-Security-Policy"
	testIP1234          = "1.2.3.4"
	testIP1111          = "1.1.1.1"
	testIP10001         = "10.0.0.1"
	testIP19216811      = "192.168.1.1"
	testLoginRoute      = "/login"
	testAPITest         = "/api/test"
	testAPISomething    = "/api/something"
	testHandlerNotCall  = "handler should not be called"
	testIP10054321      = "10.0.0.1:54321"
	testViewerEmail     = "viewer@test.com"
	testSMTPHost        = "smtp.example.com"
	testNoReplyEmail    = "noreply@example.com"
	testLogNotifErr     = "log notification: %v"
	testLogsTailQuery   = "/logs/tail?path=/var/log/syslog"
	testFilesQuery      = "/files?path=/var/log"
	testIndexHTML       = "index.html"
	testExpected502Body = "expected 502 for no agent, got %d: %s"
	testDecodeRespErr   = "decode response: %v"
	testS1Upload        = "/api/servers/s1/upload"
	testServerS1Path    = "/api/servers/s1"
	testSMTP250OK       = "250 OK\r\n"
	testLocalhost       = "127.0.0.1"
)

// mustJSON encodes v as JSON and returns a *bytes.Reader. Fails the test on error.
func mustJSON(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustJSON: %v", err)
	}
	return bytes.NewReader(b)
}

// createViewerAndGetToken creates a viewer user and returns a valid access token for them.
func createViewerAndGetToken(t *testing.T, s *Server, adminToken string) string {
	t.Helper()

	// Create viewer user
	body, _ := json.Marshal(model.CreateUserRequest{
		Username: "viewertest", Email: "viewertest@test.com", Role: model.RoleViewer,
	})
	createReq := httptest.NewRequest("POST", "/api/users", bytes.NewReader(body))
	createReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("createViewerAndGetToken: create user failed with %d: %s", createRec.Code, createRec.Body.String())
	}

	var createResp model.CreateUserResponse
	json.NewDecoder(createRec.Body).Decode(&createResp)
	tempPassword := createResp.TemporaryPassword

	// Login with temp password — first need to set up TOTP
	loginBody, _ := json.Marshal(model.LoginRequest{
		Username: "viewertest",
		Password: tempPassword,
	})
	loginReq := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	s.routes().ServeHTTP(loginRec, loginReq)

	var loginResp model.LoginResponse
	json.NewDecoder(loginRec.Body).Decode(&loginResp)

	// Setup TOTP
	setupReq := httptest.NewRequest("POST", "/api/auth/totp/setup", nil)
	setupReq.Header.Set("Authorization", testBearerPrefix+loginResp.SetupToken)
	setupRec := httptest.NewRecorder()
	s.routes().ServeHTTP(setupRec, setupReq)

	var totpResp model.TOTPSetupResponse
	json.NewDecoder(setupRec.Body).Decode(&totpResp)

	// Enable TOTP and rotate the temporary password on first setup.
	code, _ := auth.GenerateValidCode(totpResp.Secret)
	enableBody, _ := json.Marshal(model.TOTPEnableRequest{
		Code:        code,
		NewPassword: testNewPassword,
	})
	enableReq := httptest.NewRequest("POST", "/api/auth/totp/enable", bytes.NewReader(enableBody))
	enableReq.Header.Set("Authorization", testBearerPrefix+loginResp.SetupToken)
	enableRec := httptest.NewRecorder()
	s.routes().ServeHTTP(enableRec, enableReq)

	accessCookie := findCookie(enableRec.Result().Cookies(), cookieAccess)
	if accessCookie == nil {
		t.Fatal("createViewerAndGetToken: missing access cookie after TOTP enable")
	}

	return accessCookie.Value
}
