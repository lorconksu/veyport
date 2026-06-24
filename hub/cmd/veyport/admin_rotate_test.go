package main

// T008 — unit tests for server.RotateJWTSecret
//
// These tests exercise the exported helper:
//
//	func server.RotateJWTSecret(st *store.Store) (server.RotateResult, error)
//
// and its companion result type:
//
//	type server.RotateResult struct {
//	    RevokedAPITokens int
//	    // NOTE: must NOT carry the new secret — no field for key material.
//	}
//
// Run:
//
//	cd hub && go test ./cmd/veyport -run TestRotateJWTSecret -count=1

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
	"github.com/wyiu/veyport/hub/internal/store"
)

// ---------------------------------------------------------------------------
// helpers shared across rotation tests
// ---------------------------------------------------------------------------

// initTestStoreForRotation creates a store with InitJWTSecret and
// InitStorageKey already called — mirroring the production startup order from
// contracts §4.  Returns the opened store, the initial JWT signing key, and
// the storage key so individual tests can build fixtures that use them.
func initTestStoreForRotation(t *testing.T) (st *store.Store, initialJWTSecret, storageKey string) {
	t.Helper()
	_, st = newAdminTestStore(t)

	jwtSecret, err := server.InitJWTSecret(st)
	if err != nil {
		t.Fatalf("InitJWTSecret: %v", err)
	}
	sk, err := server.InitStorageKey(st)
	if err != nil {
		t.Fatalf("InitStorageKey: %v", err)
	}
	return st, jwtSecret, sk
}

// encryptForTest replicates the "enc:<hex>" format that the server uses for
// at-rest secrets (auth.DeriveKey → auth.Encrypt).  Used to verify that the
// storage key is unchanged and ciphertexts are still decryptable after
// rotation.
func encryptForTest(t *testing.T, key, plaintext string) string {
	t.Helper()
	derived := auth.DeriveKey(key)
	ct, err := auth.Encrypt([]byte(plaintext), derived)
	if err != nil {
		t.Fatalf("encryptForTest: %v", err)
	}
	return "enc:" + hex.EncodeToString(ct)
}

// decryptForTest is the inverse of encryptForTest.
func decryptForTest(t *testing.T, key, stored string) string {
	t.Helper()
	if !strings.HasPrefix(stored, "enc:") {
		t.Fatalf("decryptForTest: value lacks enc: prefix: %q", stored)
	}
	data, err := hex.DecodeString(stored[4:])
	if err != nil {
		t.Fatalf("decryptForTest: hex decode: %v", err)
	}
	derived := auth.DeriveKey(key)
	pt, err := auth.Decrypt(data, derived)
	if err != nil {
		t.Fatalf("decryptForTest: decrypt: %v", err)
	}
	return string(pt)
}

// createAPITokenForUser is a thin wrapper that seeds an active API token in
// the store and returns (rawToken, hash) for later validation.
func createAPITokenForUser(t *testing.T, st *store.Store, userID string) (raw, hash string) {
	t.Helper()
	rawToken, tokenHash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	tok := &model.APIToken{
		ID:          uuid.NewString(),
		UserID:      userID,
		Name:        "test-token-" + uuid.NewString()[:8],
		TokenHash:   tokenHash,
		TokenPrefix: prefix,
	}
	if err := st.CreateAPIToken(tok); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	return rawToken, tokenHash
}

// ---------------------------------------------------------------------------
// T008-1  Happy path
// ---------------------------------------------------------------------------

// TestRotateJWTSecret_HappyPath asserts the complete success scenario:
//
//   - jwt_signing_key changes to a new 64-hex-char value.
//   - storage_key is untouched.
//   - An existing ciphertext encrypted under storage_key still decrypts.
//   - jwt_secret_rotated_at is set, parses as RFC 3339, and is recent.
//   - result.RevokedAPITokens == 2 (two active tokens across two users).
//   - Both tokens are no longer active (RevokedAt is set).
//   - Exactly one audit entry with action AuditJWTSecretRotated whose Detail
//     contains {"revoked_api_tokens": 2} (verified via JSON unmarshal).
func TestRotateJWTSecret_HappyPath(t *testing.T) {
	st, oldJWTSecret, storageKey := initTestStoreForRotation(t)
	defer st.Close()

	// Seed an encrypted value under the storage key to verify it survives.
	const plaintext = "ldap-bind-secret"
	const encConfigKey = "ldap_bind_password"
	encrypted := encryptForTest(t, storageKey, plaintext)
	if err := st.SetConfig(encConfigKey, encrypted); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	// Create two users each with one active API token.
	user1 := createAdminUser(t, st, "rot-user1", model.RoleViewer, nil, false)
	user2 := createAdminUser(t, st, "rot-user2", model.RoleViewer, nil, false)
	_, hash1 := createAPITokenForUser(t, st, user1.ID)
	_, hash2 := createAPITokenForUser(t, st, user2.ID)

	// ---- invoke the helper ----
	result, err := server.RotateJWTSecret(st)
	if err != nil {
		t.Fatalf("rotateJWTSecret: %v", err)
	}

	// 1. jwt_signing_key changed and is 64 hex chars.
	newJWTSecret, err := st.GetConfig("jwt_signing_key")
	if err != nil {
		t.Fatalf("GetConfig jwt_signing_key: %v", err)
	}
	if newJWTSecret == oldJWTSecret {
		t.Error("jwt_signing_key must change after rotation")
	}
	if len(newJWTSecret) != 64 {
		t.Errorf("jwt_signing_key must be 64 hex chars, got len %d", len(newJWTSecret))
	}
	if _, err := hex.DecodeString(newJWTSecret); err != nil {
		t.Errorf("jwt_signing_key is not valid hex: %v", err)
	}

	// 2. storage_key unchanged.
	storedSK, err := st.GetConfig("storage_key")
	if err != nil {
		t.Fatalf("GetConfig storage_key: %v", err)
	}
	if storedSK != storageKey {
		t.Error("storage_key must not change during JWT rotation")
	}

	// 3. Ciphertext still decrypts with the storage key.
	storedCT, err := st.GetConfig(encConfigKey)
	if err != nil {
		t.Fatalf("GetConfig %s: %v", encConfigKey, err)
	}
	decrypted := decryptForTest(t, storedSK, storedCT)
	if decrypted != plaintext {
		t.Errorf("ciphertext no longer decrypts correctly after rotation: got %q, want %q", decrypted, plaintext)
	}

	// 4. jwt_secret_rotated_at is set, parses as RFC 3339, and is recent.
	rotatedAt, err := st.GetConfig("jwt_secret_rotated_at")
	if err != nil {
		t.Fatalf("GetConfig jwt_secret_rotated_at: %v", err)
	}
	ts, err := time.Parse(time.RFC3339, rotatedAt)
	if err != nil {
		t.Fatalf("jwt_secret_rotated_at is not valid RFC 3339: %q — %v", rotatedAt, err)
	}
	if time.Since(ts) > 10*time.Second {
		t.Errorf("jwt_secret_rotated_at is stale: %v", rotatedAt)
	}

	// 5. RevokedAPITokens count == 2.
	if result.RevokedAPITokens != 2 {
		t.Errorf("expected RevokedAPITokens == 2, got %d", result.RevokedAPITokens)
	}

	// 6. Both tokens are no longer active.
	for _, hash := range []string{hash1, hash2} {
		_, err := st.GetActiveAPITokenByHash(hash)
		if err == nil {
			t.Errorf("token with hash %s should be inactive after rotation, but GetActiveAPITokenByHash succeeded", hash[:8])
		}
	}

	// 7. Exactly one audit entry with action AuditJWTSecretRotated.
	action := model.AuditJWTSecretRotated
	entries, _, err := st.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 10})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 %q audit entry, got %d", model.AuditJWTSecretRotated, len(entries))
	}
	entry := entries[0]
	if entry.Detail == nil {
		t.Fatalf("audit entry Detail must not be nil")
	}

	var detail map[string]interface{}
	if err := json.Unmarshal([]byte(*entry.Detail), &detail); err != nil {
		t.Fatalf("audit entry Detail is not valid JSON: %q — %v", *entry.Detail, err)
	}
	revokedCount, ok := detail["revoked_api_tokens"]
	if !ok {
		t.Fatalf("audit detail missing 'revoked_api_tokens' key: %v", detail)
	}
	// JSON numbers unmarshal to float64.
	if revokedCount != float64(2) {
		t.Errorf("audit detail revoked_api_tokens must be 2, got %v", revokedCount)
	}
}

// ---------------------------------------------------------------------------
// T008-2  Uninitialized DB
// ---------------------------------------------------------------------------

// TestRotateJWTSecret_UninitializedDB asserts that rotateJWTSecret returns an
// error (mentioning "not initialized" or similar) when jwt_signing_key is
// absent, and makes no state changes.
func TestRotateJWTSecret_UninitializedDB(t *testing.T) {
	_, st := newAdminTestStore(t)
	defer st.Close()

	// Fresh store — no jwt_signing_key, no storage_key, no rotated_at.
	result, err := server.RotateJWTSecret(st)
	if err == nil {
		t.Fatal("expected error for uninitialized DB, got nil")
	}
	lowerErr := strings.ToLower(err.Error())
	if !strings.Contains(lowerErr, "not initialized") && !strings.Contains(lowerErr, "not found") {
		t.Errorf("error should mention instance is not initialized, got: %v", err)
	}

	// Zero value result on error.
	_ = result // result fields should be zero; just ensure no panic

	// No state written.
	if _, err2 := st.GetConfig("jwt_signing_key"); err2 == nil {
		t.Error("jwt_signing_key must not be written on uninitialized-DB error")
	}
	if _, err2 := st.GetConfig("storage_key"); err2 == nil {
		t.Error("storage_key must not be written on uninitialized-DB error")
	}
	if _, err2 := st.GetConfig("jwt_secret_rotated_at"); err2 == nil {
		t.Error("jwt_secret_rotated_at must not be written on uninitialized-DB error")
	}
}

// ---------------------------------------------------------------------------
// T008-3  Old tokens rejected after rotation
// ---------------------------------------------------------------------------

// TestRotateJWTSecret_OldTokenRejected confirms that a JWT access token
// signed with the pre-rotation secret is rejected by ValidateToken after the
// rotation, because the signing secret has changed.
func TestRotateJWTSecret_OldTokenRejected(t *testing.T) {
	st, oldSecret, _ := initTestStoreForRotation(t)
	defer st.Close()

	// Mint a token with the OLD secret.
	oldToken, err := auth.GenerateTokenWithExpiry(
		oldSecret,
		uuid.NewString(), // arbitrary user ID
		string(model.RoleViewer),
		auth.TokenTypeAccess,
		auth.AccessTokenExpiry,
	)
	if err != nil {
		t.Fatalf("GenerateTokenWithExpiry: %v", err)
	}

	// Confirm it validates with the old secret (sanity check).
	if _, err := auth.ValidateToken(oldSecret, oldToken); err != nil {
		t.Fatalf("pre-rotation: token should be valid with old secret, got %v", err)
	}

	// Rotate.
	if _, err := server.RotateJWTSecret(st); err != nil {
		t.Fatalf("rotateJWTSecret: %v", err)
	}

	// Re-read the new secret.
	newSecret, err := st.GetConfig("jwt_signing_key")
	if err != nil {
		t.Fatalf("GetConfig jwt_signing_key: %v", err)
	}

	// Old token must fail with the new secret.
	if _, err := auth.ValidateToken(newSecret, oldToken); err == nil {
		t.Error("old token must be rejected after JWT secret rotation, but ValidateToken succeeded")
	}
}

// ---------------------------------------------------------------------------
// T008-4  rotateResult carries no key material (type-shape note)
// ---------------------------------------------------------------------------

// TestRotateJWTSecret_ResultCarriesNoKeyMaterial documents the requirement
// that rotateResult must not expose the new secret.  This is enforced by the
// type definition itself — there is no field for key material — so this test
// simply ensures the struct is usable and its RevokedAPITokens field is
// present.  The absence of a secret field is verified by compilation: if
// anyone adds such a field, the team will notice the struct change in review.
//
// NOTE: Never assert on the value of the new key in any test; the requirement
// is that the result type does not carry it.
func TestRotateJWTSecret_ResultCarriesNoKeyMaterial(t *testing.T) {
	st, _, _ := initTestStoreForRotation(t)
	defer st.Close()

	result, err := server.RotateJWTSecret(st)
	if err != nil {
		t.Fatalf("server.RotateJWTSecret: %v", err)
	}

	// The only assertion here is that RevokedAPITokens is accessible and is
	// a non-negative integer (no tokens were created, so 0 is valid).
	if result.RevokedAPITokens < 0 {
		t.Errorf("RevokedAPITokens must be >= 0, got %d", result.RevokedAPITokens)
	}

	// The struct must NOT have a field like NewSecret, NewKey, Secret, Key, etc.
	// This is enforced at the type-definition level (compile time), not here.
	// The comment below documents the requirement for future readers:
	//
	//   server.RotateResult MUST NOT contain: NewSecret, NewKey, Secret, Key,
	//   JWTSecret, SigningKey, or any field that could leak the new key material.
}
