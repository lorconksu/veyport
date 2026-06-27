package server

import (
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/store"
)

// TestRotateJWTSecret_RefusesBeforeStorageKeySeparation is a regression test for
// the rotate-before-migration ordering hazard.
//
// On a legacy install (jwt_signing_key present, storage_key absent) all at-rest
// secrets (TOTP, SMTP, LDAP, CA) are encrypted under a key derived from
// jwt_signing_key.  If an operator upgrades the binary and runs
// `veyport admin rotate-jwt-secret` BEFORE the first start of the new server
// (i.e. before InitStorageKey's legacy-adopt migration has run), rotating
// jwt_signing_key would orphan every existing ciphertext: the later startup
// would adopt the *rotated* value as storage_key, and nothing would decrypt.
//
// RotateJWTSecret must refuse to run until storage_key exists, forcing the
// operator to start the server once (which performs the one-time separation)
// before rotating.
func TestRotateJWTSecret_RefusesBeforeStorageKeySeparation(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	// Legacy state: jwt_signing_key exists, storage_key does NOT.
	if _, err := InitJWTSecret(st); err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}
	jwtBefore, err := st.GetConfig("jwt_signing_key")
	if err != nil {
		t.Fatalf("read jwt_signing_key: %v", err)
	}

	_, err = RotateJWTSecret(st)
	if err == nil {
		t.Fatal("expected RotateJWTSecret to refuse when storage_key is absent, got nil")
	}
	if !strings.Contains(err.Error(), "storage_key") {
		t.Errorf("expected error to mention storage_key, got: %v", err)
	}

	// And it must NOT have mutated jwt_signing_key (fail-closed, no partial write).
	jwtAfter, err := st.GetConfig("jwt_signing_key")
	if err != nil {
		t.Fatalf("read jwt_signing_key after refusal: %v", err)
	}
	if jwtAfter != jwtBefore {
		t.Error("jwt_signing_key must be unchanged after a refused rotation")
	}
}

// TestRotateJWTSecret_SucceedsAfterStorageKeySeparation confirms the guard does
// not break the normal post-migration steady state: once storage_key exists
// (server has started at least once), rotation proceeds and changes only
// jwt_signing_key, leaving storage_key — and therefore every at-rest
// ciphertext — intact.
func TestRotateJWTSecret_SucceedsAfterStorageKeySeparation(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	if _, err := InitJWTSecret(st); err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}
	if _, err := InitStorageKey(st); err != nil {
		t.Fatalf("init storage key: %v", err)
	}
	storageBefore, err := st.GetConfig("storage_key")
	if err != nil {
		t.Fatalf("read storage_key: %v", err)
	}
	jwtBefore, err := st.GetConfig("jwt_signing_key")
	if err != nil {
		t.Fatalf("read jwt_signing_key: %v", err)
	}

	if _, err := RotateJWTSecret(st); err != nil {
		t.Fatalf("expected rotation to succeed after storage key separation, got: %v", err)
	}

	jwtAfter, err := st.GetConfig("jwt_signing_key")
	if err != nil {
		t.Fatalf("read jwt_signing_key after rotation: %v", err)
	}
	storageAfter, err := st.GetConfig("storage_key")
	if err != nil {
		t.Fatalf("read storage_key after rotation: %v", err)
	}
	if jwtAfter == jwtBefore {
		t.Error("jwt_signing_key must change after rotation")
	}
	if storageAfter != storageBefore {
		t.Error("storage_key must NOT change after rotation (at-rest secrets must stay decryptable)")
	}
}
