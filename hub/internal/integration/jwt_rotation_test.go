package integration

// TestJWTRotationEndToEnd — T010
//
// Verifies the full JWT secret rotation lifecycle end-to-end:
//   - encrypted secrets (LDAP bind password, SMTP password) survive rotation decryptable.
//   - API tokens are revoked inside the rotation transaction.
//   - Old JWT access tokens are rejected after rotation.
//   - jwt_secret_rotated_at is set to a recent RFC 3339 timestamp.
//   - Exactly one audit entry with action auth.jwt_secret_rotated.
//   - CA still loads from the store after rotation.
//
// Never prints key material.

import (
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/ca"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
)

// smtpConfigBody builds a PUT /api/settings/smtp request body with a password.
func smtpConfigBody(password string) model.SMTPConfig {
	return model.SMTPConfig{
		Enabled:  true,
		Host:     "smtp.test.local",
		Port:     587,
		Username: "smtp-user",
		Password: password,
		From:     "noreply@test.local",
		TLS:      false,
	}
}

// putSMTPConfig sends a PUT /api/settings/smtp with the given body and asserts 200.
func putSMTPConfig(t *testing.T, h *TestHarness, token string, body model.SMTPConfig) {
	t.Helper()
	resp := h.HTTPPut(t, "/api/settings/smtp", body, token)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "put smtp config")
}

// decryptConfigSecret replicates the "enc:<hex>" decryption used by the server
// (auth.DeriveKey → auth.Decrypt).
func decryptConfigSecretForTest(t *testing.T, storageKey, stored string) string {
	t.Helper()
	if !strings.HasPrefix(stored, "enc:") {
		t.Fatalf("decryptConfigSecretForTest: value lacks enc: prefix: %q", stored)
	}
	data, err := hex.DecodeString(stored[4:])
	if err != nil {
		t.Fatalf("decryptConfigSecretForTest: hex decode: %v", err)
	}
	derived := auth.DeriveKey(storageKey)
	pt, err := auth.Decrypt(data, derived)
	if err != nil {
		t.Fatalf("decryptConfigSecretForTest: decrypt: %v", err)
	}
	return string(pt)
}

func TestJWTRotationEndToEnd(t *testing.T) {
	// Step 1 — start harness and set up admin.
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)

	// Step 2a — seed LDAP bind password through the API.
	const ldapBindPassword = "ldap-bind-secret-rotation-test"
	putLDAPConfig(t, h, adminToken, ldapConfigBody(
		[]string{"ldap-admins"},
		[]string{"ldap-auditors"},
		[]string{"ldap-viewers"},
		[]string{},
	))
	// PUT again with a bind password so it is stored encrypted.
	ldapBody := ldapConfigBody(
		[]string{"ldap-admins"},
		[]string{"ldap-auditors"},
		[]string{"ldap-viewers"},
		[]string{},
	)
	ldapBody["bind_password"] = ldapBindPassword
	putLDAPConfig(t, h, adminToken, ldapBody)

	// Step 2b — seed SMTP password through the API.
	const smtpPassword = "smtp-pass-rotation-test" // NOSONAR — test fixture
	putSMTPConfig(t, h, adminToken, smtpConfigBody(smtpPassword))

	// Step 3 — create an API token directly via the store and verify it authenticates.
	rawToken, tokenHash, displayPrefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}

	// Get the admin user's ID from the store.
	adminUser, err := h.Store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername(admin): %v", err)
	}

	apiToken := &model.APIToken{
		ID:          uuid.NewString(),
		UserID:      adminUser.ID,
		Name:        "rotation-test-token",
		TokenHash:   tokenHash,
		TokenPrefix: displayPrefix,
	}
	if err := h.Store.CreateAPIToken(apiToken); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	// Verify the API token works before rotation: GET /api/auth/me → 200.
	meResp := h.HTTPGet(t, "/api/auth/me", rawToken)
	defer meResp.Body.Close()
	if meResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(meResp.Body)
		t.Fatalf("pre-rotation API token should authenticate: status=%d body=%s", meResp.StatusCode, body)
	}

	// Step 4 — rotate the JWT secret.
	result, err := server.RotateJWTSecret(h.Store)
	if err != nil {
		t.Fatalf("RotateJWTSecret: %v", err)
	}
	if result.RevokedAPITokens < 1 {
		t.Errorf("expected RevokedAPITokens >= 1, got %d", result.RevokedAPITokens)
	}

	// Step 5 — post-rotation assertions.

	// 5a. Old adminToken still works against the running harness (the in-memory
	// jwtSecret has not changed — this is pre-restart state).  This is expected
	// behavior: old sessions remain valid until the hub process restarts.
	// NOTE: we do not assert on it here to avoid depending on that incidental
	// behavior; the key claims are below.

	// Simulate restart: read the new JWT secret and storage key from the store.
	newJWTSecret, err := server.InitJWTSecret(h.Store)
	if err != nil {
		t.Fatalf("InitJWTSecret (post-rotation read): %v", err)
	}
	storageKey, err := server.InitStorageKey(h.Store)
	if err != nil {
		t.Fatalf("InitStorageKey (post-rotation read): %v", err)
	}

	// 5b. Old adminToken must fail validation against the new secret.
	if _, err := auth.ValidateToken(newJWTSecret, adminToken); err == nil {
		t.Error("old adminToken must be rejected by the new JWT secret after rotation")
	}

	// 5c. API token is rejected even by the RUNNING harness (DB-backed credential,
	// revoked inside the transaction): GET /api/auth/me with adt_ token → 401.
	apiResp := h.HTTPGet(t, "/api/auth/me", rawToken)
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(apiResp.Body)
		t.Errorf("revoked API token should be rejected (401), got status=%d body=%s", apiResp.StatusCode, body)
	}

	// 5d. LDAP bind password decrypts with the storage key and equals the seeded value.
	storedLDAP, ldapOK, ldapErr := h.Store.LookupConfig("ldap.bind_password")
	if ldapErr != nil || !ldapOK {
		t.Fatalf("LookupConfig ldap.bind_password: ok=%v err=%v", ldapOK, ldapErr)
	}
	if !strings.HasPrefix(storedLDAP, "enc:") {
		t.Fatalf("ldap.bind_password not encrypted at rest: %q", storedLDAP)
	}
	decryptedLDAP := decryptConfigSecretForTest(t, storageKey, storedLDAP)
	if decryptedLDAP != ldapBindPassword {
		t.Errorf("LDAP bind password mismatch after rotation: got %q, want %q", decryptedLDAP, ldapBindPassword)
	}

	// 5e. SMTP password decrypts with the storage key and equals the seeded value.
	storedSMTP, smtpOK, smtpErr := h.Store.LookupConfig("smtp_password")
	if smtpErr != nil || !smtpOK {
		t.Fatalf("LookupConfig smtp_password: ok=%v err=%v", smtpOK, smtpErr)
	}
	if !strings.HasPrefix(storedSMTP, "enc:") {
		t.Fatalf("smtp_password not encrypted at rest: %q", storedSMTP)
	}
	decryptedSMTP := decryptConfigSecretForTest(t, storageKey, storedSMTP)
	if decryptedSMTP != smtpPassword {
		t.Errorf("SMTP password mismatch after rotation: got %q, want %q", decryptedSMTP, smtpPassword)
	}

	// 5f. jwt_secret_rotated_at is set and parses as RFC 3339 with a recent timestamp.
	rotatedAt, err := h.Store.GetConfig("jwt_secret_rotated_at")
	if err != nil {
		t.Fatalf("GetConfig jwt_secret_rotated_at: %v", err)
	}
	ts, err := time.Parse(time.RFC3339, rotatedAt)
	if err != nil {
		t.Fatalf("jwt_secret_rotated_at is not valid RFC 3339: %q — %v", rotatedAt, err)
	}
	if time.Since(ts) > 30*time.Second {
		t.Errorf("jwt_secret_rotated_at is stale: %v", rotatedAt)
	}

	// 5g. Exactly one auth.jwt_secret_rotated audit entry.
	action := model.AuditJWTSecretRotated
	entries, _, err := h.Store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 10})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 %q audit entry, got %d", model.AuditJWTSecretRotated, len(entries))
	}

	// 5h. CA still loads: ca.InitCA succeeds and returns existing CA (no new key generated).
	_, _, caErr := ca.InitCA(h.Store, storageKey)
	if caErr != nil {
		t.Errorf("ca.InitCA failed after rotation: %v", caErr)
	}
}
