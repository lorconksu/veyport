package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
)

const (
	testSecretKey = "test-secret-key-256-bits-long!!!"
	testUserID    = "user-1"
)

func TestGenerateAndValidateAccessToken(t *testing.T) {
	secret := testSecretKey

	access, _, err := auth.GenerateTokenPair(secret, testUserID, "admin", 0)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	claims, err := auth.ValidateToken(secret, access)
	if err != nil {
		t.Fatalf("validate access: %v", err)
	}

	if claims.Subject != testUserID {
		t.Fatalf("expected sub 'user-1', got '%s'", claims.Subject)
	}
	if claims.Role != "admin" {
		t.Fatalf("expected role 'admin', got '%s'", claims.Role)
	}
	if claims.TokenType != auth.TokenTypeAccess {
		t.Fatalf("expected type 'access', got '%s'", claims.TokenType)
	}
}

func TestValidateRefreshToken(t *testing.T) {
	secret := testSecretKey

	_, refresh, _ := auth.GenerateTokenPair(secret, testUserID, "admin", 0)

	claims, err := auth.ValidateToken(secret, refresh)
	if err != nil {
		t.Fatalf("validate refresh: %v", err)
	}
	if claims.TokenType != auth.TokenTypeRefresh {
		t.Fatalf("expected type 'refresh', got '%s'", claims.TokenType)
	}
}

func TestGenerateSetupToken(t *testing.T) {
	secret := testSecretKey

	token, err := auth.GenerateSetupToken(secret, testUserID, "admin")
	if err != nil {
		t.Fatalf("generate setup: %v", err)
	}

	claims, err := auth.ValidateToken(secret, token)
	if err != nil {
		t.Fatalf("validate setup: %v", err)
	}
	if claims.TokenType != auth.TokenTypeSetup {
		t.Fatalf("expected type 'setup', got '%s'", claims.TokenType)
	}
}

func TestGenerateTOTPToken(t *testing.T) {
	secret := testSecretKey

	token, err := auth.GenerateTOTPToken(secret, testUserID, "admin")
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}

	claims, err := auth.ValidateToken(secret, token)
	if err != nil {
		t.Fatalf("validate totp: %v", err)
	}
	if claims.TokenType != auth.TokenTypeTOTP {
		t.Fatalf("expected type 'totp', got '%s'", claims.TokenType)
	}
}

func TestExpiredToken(t *testing.T) {
	secret := testSecretKey

	// Create a token that's already expired
	token, _ := auth.GenerateTokenWithExpiry(secret, testUserID, "admin", auth.TokenTypeAccess, -1*time.Minute)

	_, err := auth.ValidateToken(secret, token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestWrongSecret(t *testing.T) {
	access, _, _ := auth.GenerateTokenPair("correct-secret-key-256-bits!!!!", testUserID, "admin", 0)

	_, err := auth.ValidateToken("wrong-secret-key-256-bits-long!", access)
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

// --- Feature 009: session-bound tokens (sid claim) ---

const testSessionID = "11111111-2222-3333-4444-555555555555"

// decodeClaimsJSON returns the raw decoded payload of a JWT so tests can assert
// on the wire representation (for example that "sid" is omitted entirely).
func decodeClaimsJSON(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

func TestGenerateSessionTokenPair_BothTokensCarrySameSID(t *testing.T) {
	secret := testSecretKey

	access, refresh, err := auth.GenerateSessionTokenPair(secret, testUserID, "admin", 3, testSessionID)
	if err != nil {
		t.Fatalf("generate session pair: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected both tokens to be non-empty")
	}
	if access == refresh {
		t.Fatal("expected access and refresh tokens to differ")
	}

	accessClaims, err := auth.ValidateToken(secret, access)
	if err != nil {
		t.Fatalf("validate access: %v", err)
	}
	refreshClaims, err := auth.ValidateToken(secret, refresh)
	if err != nil {
		t.Fatalf("validate refresh: %v", err)
	}

	if accessClaims.SessionID != testSessionID {
		t.Fatalf("expected access sid %q, got %q", testSessionID, accessClaims.SessionID)
	}
	if refreshClaims.SessionID != testSessionID {
		t.Fatalf("expected refresh sid %q, got %q", testSessionID, refreshClaims.SessionID)
	}
	if accessClaims.TokenType != auth.TokenTypeAccess {
		t.Fatalf("expected access type, got %q", accessClaims.TokenType)
	}
	if refreshClaims.TokenType != auth.TokenTypeRefresh {
		t.Fatalf("expected refresh type, got %q", refreshClaims.TokenType)
	}
	if accessClaims.Subject != testUserID || refreshClaims.Subject != testUserID {
		t.Fatalf("expected sub %q on both tokens", testUserID)
	}
	if accessClaims.Role != "admin" || refreshClaims.Role != "admin" {
		t.Fatal("expected role admin on both tokens")
	}
	if accessClaims.TokenGeneration != 3 || refreshClaims.TokenGeneration != 3 {
		t.Fatalf("expected token generation 3, got %d/%d",
			accessClaims.TokenGeneration, refreshClaims.TokenGeneration)
	}
	if accessClaims.ID == refreshClaims.ID {
		t.Fatal("expected distinct jti per token")
	}

	// Expiries stay the standard access/refresh windows.
	accessTTL := time.Until(accessClaims.ExpiresAt.Time)
	if accessTTL > auth.AccessTokenExpiry || accessTTL < auth.AccessTokenExpiry-time.Minute {
		t.Fatalf("unexpected access expiry: %v", accessTTL)
	}
	refreshTTL := time.Until(refreshClaims.ExpiresAt.Time)
	if refreshTTL > auth.RefreshTokenExpiry || refreshTTL < auth.RefreshTokenExpiry-time.Minute {
		t.Fatalf("unexpected refresh expiry: %v", refreshTTL)
	}

	if got := decodeClaimsJSON(t, access)["sid"]; got != testSessionID {
		t.Fatalf("expected sid %q in the access payload, got %v", testSessionID, got)
	}
}

func TestGenerateTokenPair_LegacyTokensHaveNoSID(t *testing.T) {
	secret := testSecretKey

	access, refresh, err := auth.GenerateTokenPair(secret, testUserID, "admin", 0)
	if err != nil {
		t.Fatalf("generate pair: %v", err)
	}

	for name, token := range map[string]string{"access": access, "refresh": refresh} {
		claims, err := auth.ValidateToken(secret, token)
		if err != nil {
			t.Fatalf("validate %s: %v", name, err)
		}
		if claims.SessionID != "" {
			t.Fatalf("expected empty SessionID on legacy %s token, got %q", name, claims.SessionID)
		}
		if _, present := decodeClaimsJSON(t, token)["sid"]; present {
			t.Fatalf("expected the sid claim to be omitted from the legacy %s payload", name)
		}
	}
}

func TestSetupAndTOTPTokens_CarryNoSID(t *testing.T) {
	secret := testSecretKey

	setup, err := auth.GenerateSetupToken(secret, testUserID, "admin")
	if err != nil {
		t.Fatalf("generate setup: %v", err)
	}
	totp, err := auth.GenerateTOTPToken(secret, testUserID, "admin")
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}

	for name, token := range map[string]string{"setup": setup, "totp": totp} {
		claims, err := auth.ValidateToken(secret, token)
		if err != nil {
			t.Fatalf("validate %s: %v", name, err)
		}
		if claims.SessionID != "" {
			t.Fatalf("expected no sid on the %s token, got %q", name, claims.SessionID)
		}
		if _, present := decodeClaimsJSON(t, token)["sid"]; present {
			t.Fatalf("expected the sid claim to be omitted from the %s payload", name)
		}
	}
}

func TestSessionToken_TamperedSIDFailsValidation(t *testing.T) {
	secret := testSecretKey

	access, _, err := auth.GenerateSessionTokenPair(secret, testUserID, "admin", 0, testSessionID)
	if err != nil {
		t.Fatalf("generate session pair: %v", err)
	}

	parts := strings.Split(access, ".")
	claims := decodeClaimsJSON(t, access)
	claims["sid"] = "99999999-9999-9999-9999-999999999999"
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal tampered payload: %v", err)
	}
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]

	if _, err := auth.ValidateToken(secret, tampered); err == nil {
		t.Fatal("expected a token with a rewritten sid to fail signature validation")
	}
}

func TestGenerateSessionTokenPair_EmptySIDOmitsClaim(t *testing.T) {
	secret := testSecretKey

	access, _, err := auth.GenerateSessionTokenPair(secret, testUserID, "user", 0, "")
	if err != nil {
		t.Fatalf("generate session pair: %v", err)
	}
	claims, err := auth.ValidateToken(secret, access)
	if err != nil {
		t.Fatalf("validate access: %v", err)
	}
	if claims.SessionID != "" {
		t.Fatalf("expected empty SessionID, got %q", claims.SessionID)
	}
	if _, present := decodeClaimsJSON(t, access)["sid"]; present {
		t.Fatal("expected the sid claim to be omitted when the session id is empty")
	}
}
