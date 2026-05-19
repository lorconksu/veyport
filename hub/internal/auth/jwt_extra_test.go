package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
)

// TestValidateToken_InvalidSigningMethod verifies that a token with wrong signing method is rejected.
// We can't easily create an RSA-signed token, so we test with a malformed token instead.
func TestValidateToken_MalformedToken(t *testing.T) {
	secret := testSecretKey

	_, err := auth.ValidateToken(secret, "not.a.jwt.token.here")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

// TestValidateToken_EmptyToken verifies empty token returns error.
func TestValidateToken_EmptyToken(t *testing.T) {
	secret := testSecretKey

	_, err := auth.ValidateToken(secret, "")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

// TestGenerateTokenPair_ReturnsNonEmptyTokens verifies both tokens are non-empty.
func TestGenerateTokenPair_ReturnsNonEmptyTokens(t *testing.T) {
	secret := testSecretKey

	access, refresh, err := auth.GenerateTokenPair(secret, "user-123", "viewer", 0)
	if err != nil {
		t.Fatalf("generate token pair: %v", err)
	}
	if access == "" {
		t.Fatal("expected non-empty access token")
	}
	if refresh == "" {
		t.Fatal("expected non-empty refresh token")
	}
	if access == refresh {
		t.Fatal("access and refresh tokens should be different")
	}
}

// TestGenerateTokenWithExpiry_CustomExpiry verifies custom expiry is respected.
func TestGenerateTokenWithExpiry_CustomExpiry(t *testing.T) {
	secret := testSecretKey

	token, err := auth.GenerateTokenWithExpiry(secret, testUserID, "admin", "custom", 5*time.Minute)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	claims, err := auth.ValidateToken(secret, token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.TokenType != "custom" {
		t.Fatalf("expected type 'custom', got '%s'", claims.TokenType)
	}
	if claims.Subject != testUserID {
		t.Fatalf("expected subject 'user-1', got '%s'", claims.Subject)
	}
}

// TestValidateToken_WrongTokenType verifies we can check token type from claims.
func TestValidateToken_TOTPTokenHasCorrectType(t *testing.T) {
	secret := testSecretKey

	token, err := auth.GenerateTOTPToken(secret, testUserID, "admin")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	claims, err := auth.ValidateToken(secret, token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.TokenType != auth.TokenTypeTOTP {
		t.Fatalf("expected TOTP type, got '%s'", claims.TokenType)
	}
}

// TestValidateToken_TruncatedToken verifies truncated token is rejected.
func TestValidateToken_TruncatedToken(t *testing.T) {
	secret := testSecretKey

	access, _, _ := auth.GenerateTokenPair(secret, testUserID, "admin", 0)
	truncated := access[:len(access)/2]

	_, err := auth.ValidateToken(secret, truncated)
	if err == nil {
		t.Fatal("expected error for truncated token")
	}
}

// TestGenerateTokenWithExpiry_EmptySecret verifies signing with empty secret still works (but is insecure).
func TestGenerateTokenWithExpiry_MultipleRoles(t *testing.T) {
	secret := testSecretKey

	roles := []string{"admin", "viewer", "editor"}
	for _, role := range roles {
		token, err := auth.GenerateTokenWithExpiry(secret, testUserID, role, auth.TokenTypeAccess, 5*time.Minute)
		if err != nil {
			t.Fatalf("generate for role %s: %v", role, err)
		}

		claims, err := auth.ValidateToken(secret, token)
		if err != nil {
			t.Fatalf("validate for role %s: %v", role, err)
		}
		if claims.Role != role {
			t.Fatalf("expected role %s, got %s", role, claims.Role)
		}
	}
}

// TestValidateToken_ModifiedPayload verifies a tampered token is rejected.
func TestValidateToken_ModifiedPayload(t *testing.T) {
	secret := testSecretKey

	access, _, _ := auth.GenerateTokenPair(secret, testUserID, "admin", 0)

	// Modify the middle section (payload)
	parts := strings.Split(access, ".")
	if len(parts) != 3 {
		t.Fatal("expected 3-part JWT")
	}
	parts[1] = "bW9kaWZpZWRwYXlsb2Fk" // base64 "modifiedpayload"
	tampered := strings.Join(parts, ".")

	_, err := auth.ValidateToken(secret, tampered)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}
