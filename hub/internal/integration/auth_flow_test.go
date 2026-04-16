package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
)

// requireStatusOK reads a response and fatals if status is not 200.
func requireStatusOK(t *testing.T, resp *http.Response, label string) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s: status=%d body=%s", label, resp.StatusCode, body)
	}
}

// decodeJSON decodes a JSON response body into dst and fatals on error.
func decodeJSON(t *testing.T, resp *http.Response, dst interface{}, label string) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode %s response: %v", label, err)
	}
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// assertAuthStatus checks the /api/auth/status endpoint for the expected initialized value.
func assertAuthStatus(t *testing.T, h *TestHarness, wantInitialized bool) {
	t.Helper()
	resp := h.HTTPGet(t, "/api/auth/status", "")
	defer resp.Body.Close()
	requireStatusOK(t, resp, "auth status")

	var result model.AuthStatusResponse
	decodeJSON(t, resp, &result, "auth status")
	if result.Initialized != wantInitialized {
		t.Fatalf("expected initialized=%v, got %v", wantInitialized, result.Initialized)
	}
}

// registerUser registers a user and returns the setup token.
func registerUser(t *testing.T, h *TestHarness, username, email, password string) string {
	t.Helper()
	resp := h.HTTPPost(t, "/api/auth/register", model.RegisterRequest{
		Username: username, Email: email, Password: password,
	}, "")
	defer resp.Body.Close()
	requireStatusOK(t, resp, "register")

	var result struct {
		SetupToken string `json:"setup_token"`
	}
	decodeJSON(t, resp, &result, "register")
	if result.SetupToken == "" {
		t.Fatal("expected non-empty setup_token after register")
	}
	return result.SetupToken
}

// setupTOTP calls /api/auth/totp/setup and returns the secret.
func setupTOTP(t *testing.T, h *TestHarness, setupToken string) string {
	t.Helper()
	resp := h.HTTPPost(t, "/api/auth/totp/setup", nil, setupToken)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "totp setup")

	var result model.TOTPSetupResponse
	decodeJSON(t, resp, &result, "totp setup")
	if result.Secret == "" {
		t.Fatal("expected non-empty TOTP secret")
	}
	if result.QRURL == "" {
		t.Fatal("expected non-empty TOTP QR URL")
	}
	return result.Secret
}

// enableTOTP generates a code and enables TOTP, returning access and refresh cookies.
func enableTOTP(t *testing.T, h *TestHarness, secret, setupToken string) (accessToken, refreshToken string) {
	t.Helper()
	code, err := auth.GenerateValidCode(secret)
	if err != nil {
		t.Fatalf("generate TOTP enable code: %v", err)
	}
	resp := h.HTTPPost(t, "/api/auth/totp/enable", model.TOTPEnableRequest{Code: code}, setupToken)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "totp enable")

	var result model.AuthResponse
	decodeJSON(t, resp, &result, "totp enable")
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("expected token fields in totp enable response body")
	}

	access := findCookie(resp, cookieAccess)
	refresh := findCookie(resp, cookieRefresh)
	if access == nil || access.Value == "" || refresh == nil || refresh.Value == "" {
		t.Fatal("expected access and refresh cookies after totp enable")
	}
	return access.Value, refresh.Value
}

// loginAndGetTOTPToken logs in with credentials and returns the TOTP token.
func loginAndGetTOTPToken(t *testing.T, h *TestHarness, username, password string) string {
	t.Helper()
	resp := h.HTTPPost(t, "/api/auth/login", model.LoginRequest{
		Username: username, Password: password,
	}, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login: status=%d body=%s (expected 202)", resp.StatusCode, body)
	}
	var result model.LoginResponse
	decodeJSON(t, resp, &result, "login")
	if result.TOTPToken == "" {
		t.Fatal("expected totp_token after login (TOTP enabled)")
	}
	return result.TOTPToken
}

// completeTOTPLogin completes the TOTP login step and returns access and refresh cookies.
func completeTOTPLogin(t *testing.T, h *TestHarness, totpToken, secret string) (accessToken, refreshToken string) {
	t.Helper()
	h.HTTPServer.ClearTOTPCache()
	code, err := auth.GenerateValidCode(secret)
	if err != nil {
		t.Fatalf("generate TOTP login code: %v", err)
	}
	resp := h.HTTPPost(t, "/api/auth/login/totp", model.LoginTOTPRequest{
		TOTPToken: totpToken, Code: code,
	}, "")
	defer resp.Body.Close()
	requireStatusOK(t, resp, "login/totp")

	var result model.AuthResponse
	decodeJSON(t, resp, &result, "login/totp")
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("expected token fields in login/totp response body")
	}

	access := findCookie(resp, cookieAccess)
	refresh := findCookie(resp, cookieRefresh)
	if access == nil || access.Value == "" || refresh == nil || refresh.Value == "" {
		t.Fatal("expected access and refresh cookies after login/totp")
	}
	return access.Value, refresh.Value
}

func TestFullAuthFlow(t *testing.T) {
	h := StartHarness(t)

	const (
		username = "testadmin"
		email    = "testadmin@example.com"
		password = "SecurePass123!"
	)

	t.Run("initial_status_uninitialized", func(t *testing.T) {
		assertAuthStatus(t, h, false)
	})

	setupToken := registerUser(t, h, username, email, password)
	t.Log("register: got setup_token")

	totpSecret := setupTOTP(t, h, setupToken)
	t.Log("totp setup: got secret and qr_url")

	accessToken, refreshToken := enableTOTP(t, h, totpSecret, setupToken)
	t.Log("totp enable: got access_token and refresh_token")

	t.Run("status_initialized", func(t *testing.T) {
		assertAuthStatus(t, h, true)
	})

	totpToken := loginAndGetTOTPToken(t, h, username, password)
	t.Log("login: got totp_token")

	accessToken, refreshToken = completeTOTPLogin(t, h, totpToken, totpSecret)
	t.Log("login/totp: got access_token and refresh_token")

	t.Run("verify_me_endpoint", func(t *testing.T) {
		resp := h.HTTPGet(t, "/api/auth/me", accessToken)
		defer resp.Body.Close()
		requireStatusOK(t, resp, "me")

		var meResult model.User
		decodeJSON(t, resp, &meResult, "me")
		if meResult.Username != username {
			t.Fatalf("username mismatch: got %q, want %q", meResult.Username, username)
		}
		if meResult.Role != model.RoleAdmin {
			t.Fatalf("role mismatch: got %q, want %q", meResult.Role, model.RoleAdmin)
		}
		t.Logf("me: username=%s role=%s", meResult.Username, meResult.Role)
	})

	t.Run("change_password_and_relogin", func(t *testing.T) {
		const newPassword = "NewSecurePass456!" // NOSONAR -- test fixture
		pwResp := h.HTTPPut(t, "/api/auth/password", model.ChangePasswordRequest{
			CurrentPassword: password, NewPassword: newPassword,
		}, accessToken)
		defer pwResp.Body.Close()
		requireStatusOK(t, pwResp, "change password")

		// Password change invalidates existing sessions (increments token_generation),
		// so the old refresh token should no longer work.
		loginNewResp := h.HTTPPost(t, "/api/auth/login", model.LoginRequest{
			Username: username, Password: newPassword,
		}, "")
		defer loginNewResp.Body.Close()
		if loginNewResp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(loginNewResp.Body)
			t.Fatalf("login with new password: status=%d body=%s (expected 202)", loginNewResp.StatusCode, body)
		}

		// Complete TOTP login to get fresh tokens for the refresh test
		var loginResult model.LoginResponse
		decodeJSON(t, loginNewResp, &loginResult, "login-new-password")
		_, refreshToken = completeTOTPLogin(t, h, loginResult.TOTPToken, totpSecret)
	})

	t.Run("refresh_token", func(t *testing.T) {
		resp := h.HTTPPost(t, "/api/auth/refresh", model.RefreshRequest{
			RefreshToken: refreshToken,
		}, "")
		defer resp.Body.Close()
		requireStatusOK(t, resp, "refresh")

		var result model.TokenPair
		decodeJSON(t, resp, &result, "refresh")
		if result.AccessToken == "" || result.RefreshToken == "" {
			t.Fatal("expected token fields in refresh response body")
		}

		access := findCookie(resp, cookieAccess)
		refresh := findCookie(resp, cookieRefresh)
		if access == nil || access.Value == "" || refresh == nil || refresh.Value == "" {
			t.Fatal("expected new access and refresh cookies after refresh")
		}
	})

	t.Log("full auth flow completed successfully")
}
