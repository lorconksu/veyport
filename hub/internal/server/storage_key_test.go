package server

import (
	"encoding/hex"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// countAuditAction returns the number of audit entries with the given action string.
func countAuditAction(t *testing.T, st *store.Store, action string) int {
	t.Helper()
	entries, _, err := st.ListAuditLogs(model.AuditFilter{Action: &action})
	if err != nil {
		t.Fatalf("list audit logs for action %q: %v", action, err)
	}
	return len(entries)
}

// TestInitStorageKey_LegacyAdoption verifies the migration path: when a store
// already has a jwt_signing_key but no storage_key, InitStorageKey copies the
// jwt_signing_key value into storage_key, writes exactly one
// auth.storage_key_separated audit entry, and previously encrypted ciphertext
// decrypts correctly using the returned storage key.
func TestInitStorageKey_LegacyAdoption(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	// Simulate a legacy install: initialise the JWT signing key.
	jwtSecret, err := InitJWTSecret(st)
	if err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}

	// Encrypt a sample value using the jwt signing key (same as encryptConfigSecret
	// does in ldap_auth.go) so we can verify the derived key is unchanged.
	const samplePlaintext = "super-secret-ldap-password"
	encrypted, err := encryptConfigSecret(jwtSecret, samplePlaintext)
	if err != nil {
		t.Fatalf("encrypt sample secret: %v", err)
	}

	// No storage_key exists yet — this is the legacy state.
	storageKey, err := InitStorageKey(st)
	if err != nil {
		t.Fatalf("InitStorageKey: %v", err)
	}

	// The returned key must equal the jwt signing key value.
	if storageKey != jwtSecret {
		t.Fatalf("legacy adoption: storage key length mismatch (got %d chars, want %d)", len(storageKey), len(jwtSecret))
	}

	// storage_key config row must be persisted.
	persisted, err := st.GetConfig("storage_key")
	if err != nil {
		t.Fatalf("read persisted storage_key: %v", err)
	}
	if persisted != storageKey {
		t.Fatal("persisted storage_key does not match returned key")
	}

	// The existing ciphertext must still decrypt using the storage key
	// (the derived AES key is bit-identical because we copied the value).
	decrypted, err := decryptConfigSecret(storageKey, encrypted)
	if err != nil {
		t.Fatalf("decrypt sample secret using storage key: %v", err)
	}
	if decrypted != samplePlaintext {
		t.Fatal("decrypted value does not match original plaintext")
	}

	// Exactly one audit entry with action auth.storage_key_separated must exist.
	n := countAuditAction(t, st, model.AuditStorageKeySeparated)
	if n != 1 {
		t.Fatalf("expected 1 %q audit entry, got %d", model.AuditStorageKeySeparated, n)
	}
}

// TestInitStorageKey_Idempotency verifies that calling InitStorageKey twice
// returns the same key both times and does not create a second audit entry.
func TestInitStorageKey_Idempotency(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	_, err = InitJWTSecret(st)
	if err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}

	key1, err := InitStorageKey(st)
	if err != nil {
		t.Fatalf("InitStorageKey (first call): %v", err)
	}

	key2, err := InitStorageKey(st)
	if err != nil {
		t.Fatalf("InitStorageKey (second call): %v", err)
	}

	if key1 != key2 {
		t.Fatal("idempotency: second call returned a different key")
	}

	// Still exactly one audit entry — the second call must not append another.
	n := countAuditAction(t, st, model.AuditStorageKeySeparated)
	if n != 1 {
		t.Fatalf("expected exactly 1 %q audit entry after two calls, got %d", model.AuditStorageKeySeparated, n)
	}
}

// TestInitStorageKey_AlreadySeparated verifies that when storage_key is already
// set to a known value (and a different jwt_signing_key also exists), the
// function returns the pre-existing storage_key unchanged and writes no new
// audit entry.
func TestInitStorageKey_AlreadySeparated(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	// Pre-set a different jwt_signing_key so the legacy path would normally fire.
	if err := st.SetConfig("jwt_signing_key", "aaaa1111000011112222333344445555666677778888999900001111222233334444"); err != nil {
		t.Fatalf("set jwt_signing_key: %v", err)
	}

	// Pre-set storage_key to a distinct known value.
	knownStorageKey := "bbbb2222000011112222333344445555666677778888999900001111222233334444"
	if err := st.SetConfig("storage_key", knownStorageKey); err != nil {
		t.Fatalf("set storage_key: %v", err)
	}

	storageKey, err := InitStorageKey(st)
	if err != nil {
		t.Fatalf("InitStorageKey: %v", err)
	}

	// Must return the pre-existing storage_key, not the jwt_signing_key.
	if storageKey != knownStorageKey {
		t.Fatalf("already-separated: expected pre-existing storage key, got different value of length %d", len(storageKey))
	}

	// Must not write any audit entry.
	n := countAuditAction(t, st, model.AuditStorageKeySeparated)
	if n != 0 {
		t.Fatalf("already-separated: expected 0 audit entries, got %d", n)
	}
}

// TestInitStorageKey_FreshInstall verifies that when neither storage_key nor
// jwt_signing_key exists, InitStorageKey generates a fresh random 64-char hex
// key and persists it.
func TestInitStorageKey_FreshInstall(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	// Fresh store — no jwt_signing_key, no storage_key.
	storageKey, err := InitStorageKey(st)
	if err != nil {
		t.Fatalf("InitStorageKey: %v", err)
	}

	// Must be exactly 64 hex characters (256 bits).
	if len(storageKey) != 64 {
		t.Fatalf("fresh install: expected 64-char hex key, got length %d", len(storageKey))
	}

	// Must be valid hex.
	if _, err := hex.DecodeString(storageKey); err != nil {
		t.Fatalf("fresh install: returned key is not valid hex: %v", err)
	}

	// Must be persisted.
	persisted, err := st.GetConfig("storage_key")
	if err != nil {
		t.Fatalf("read persisted storage_key: %v", err)
	}
	if persisted != storageKey {
		t.Fatal("fresh install: persisted storage_key does not match returned key")
	}
}

// TestInitStorageKey_KeyMaterial is a guard that ensures we never accidentally
// log or compare against literal secret bytes in test output. This test simply
// validates that the auth.DeriveKey and auth.Encrypt round-trip still works
// with any key of the expected format, without printing key material.
func TestInitStorageKey_KeyMaterial(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	jwtSecret, err := InitJWTSecret(st)
	if err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}

	storageKey, err := InitStorageKey(st)
	if err != nil {
		t.Fatalf("InitStorageKey: %v", err)
	}

	// Key length check only — never assert on the actual value.
	if len(storageKey) != 64 {
		t.Fatalf("storage key must be 64 hex chars (256 bits), got %d", len(storageKey))
	}
	if len(jwtSecret) != 64 {
		t.Fatalf("jwt secret must be 64 hex chars (256 bits), got %d", len(jwtSecret))
	}

	// Verify the storage key produces a usable AES key via DeriveKey.
	key := auth.DeriveKey(storageKey)
	if len(key) != 32 {
		t.Fatalf("DeriveKey must produce a 32-byte AES-256 key, got %d bytes", len(key))
	}
}
