package main

// T009 — CLI wrapper tests for runRotateJWTSecret
//
// These tests exercise the full CLI path:
//
//	func runRotateJWTSecret(args []string) error
//
// Each sub-test seeds a SQLite store, closes it (to avoid SQLite lock), then
// drives runRotateJWTSecret.  Pattern mirrors admin_test.go helpers.
//
// Run:
//
//	cd hub && go test ./cmd/veyport -run TestRunRotateJWTSecret -count=1

import (
	"os"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
	"github.com/wyiu/veyport/hub/internal/store"
)

// ---------------------------------------------------------------------------
// T009-1  Happy path with -yes flag
// ---------------------------------------------------------------------------

// TestRunRotateJWTSecret_YesFlag exercises the "-yes" bypass path:
// seeds the DB with two users (two active API tokens), closes the store, runs
// runRotateJWTSecret with -yes, and verifies no error.  It then reopens the
// store to assert that jwt_signing_key is present (changed from nothing→something).
func TestRunRotateJWTSecret_YesFlag(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	// Capture the initial JWT secret before seeding.
	if _, err := server.InitJWTSecret(st); err != nil {
		st.Close()
		t.Fatalf("InitJWTSecret: %v", err)
	}
	if _, err := server.InitStorageKey(st); err != nil {
		st.Close()
		t.Fatalf("InitStorageKey: %v", err)
	}
	initialKey, err := st.GetConfig("jwt_signing_key")
	if err != nil {
		st.Close()
		t.Fatalf("GetConfig jwt_signing_key before rotation: %v", err)
	}
	user1 := createAdminUser(t, st, "happy-u1", model.RoleViewer, nil, false)
	user2 := createAdminUser(t, st, "happy-u2", model.RoleViewer, nil, false)
	createAPITokenForUser(t, st, user1.ID)
	createAPITokenForUser(t, st, user2.ID)
	st.Close()

	var runErr error
	captureStdout(t, func() {
		runErr = runRotateJWTSecret([]string{"-db", dbPath, "-yes"})
	})
	if runErr != nil {
		t.Fatalf("runRotateJWTSecret(-yes): %v", runErr)
	}

	// Reopen to verify state.
	verifyStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer verifyStore.Close()

	newKey, err := verifyStore.GetConfig("jwt_signing_key")
	if err != nil {
		t.Fatalf("GetConfig jwt_signing_key after rotation: %v", err)
	}
	if newKey == initialKey {
		t.Error("jwt_signing_key must change after rotation")
	}
	if len(newKey) != 64 {
		t.Errorf("expected 64-char hex key, got len %d", len(newKey))
	}

	rotatedAt, err := verifyStore.GetConfig("jwt_secret_rotated_at")
	if err != nil {
		t.Fatalf("GetConfig jwt_secret_rotated_at: %v", err)
	}
	if rotatedAt == "" {
		t.Error("jwt_secret_rotated_at must be set after rotation")
	}
}

// ---------------------------------------------------------------------------
// T009-2  Interactive confirmation — user types "yes"
// ---------------------------------------------------------------------------

// TestRunRotateJWTSecret_InteractiveYes injects "yes\n" into os.Stdin so that
// the interactive prompt in runRotateJWTSecret proceeds.
func TestRunRotateJWTSecret_InteractiveYes(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	if _, err := server.InitJWTSecret(st); err != nil {
		st.Close()
		t.Fatalf("InitJWTSecret: %v", err)
	}
	if _, err := server.InitStorageKey(st); err != nil {
		st.Close()
		t.Fatalf("InitStorageKey: %v", err)
	}
	st.Close()

	// Inject stdin.
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	if _, err := w.WriteString("yes\n"); err != nil {
		t.Fatalf("write to stdin pipe: %v", err)
	}
	w.Close()

	var runErr error
	captureStdout(t, func() {
		runErr = runRotateJWTSecret([]string{"-db", dbPath})
	})
	if runErr != nil {
		t.Fatalf("expected success when user types 'yes', got: %v", runErr)
	}
}

// ---------------------------------------------------------------------------
// T009-3  Interactive confirmation — user types "no"
// ---------------------------------------------------------------------------

// TestRunRotateJWTSecret_InteractiveAbort injects "no\n" and verifies the
// command returns an error containing "aborted".
func TestRunRotateJWTSecret_InteractiveAbort(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	if _, err := server.InitJWTSecret(st); err != nil {
		st.Close()
		t.Fatalf("InitJWTSecret: %v", err)
	}
	if _, err := server.InitStorageKey(st); err != nil {
		st.Close()
		t.Fatalf("InitStorageKey: %v", err)
	}
	st.Close()

	// Inject stdin with "no".
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	if _, err := w.WriteString("no\n"); err != nil {
		t.Fatalf("write to stdin pipe: %v", err)
	}
	w.Close()

	var runErr error
	captureStdout(t, func() {
		runErr = runRotateJWTSecret([]string{"-db", dbPath})
	})
	if runErr == nil {
		t.Fatal("expected error when user types 'no', got nil")
	}
	if !strings.Contains(runErr.Error(), "aborted") {
		t.Errorf("expected 'aborted' in error, got: %v", runErr)
	}
}

// ---------------------------------------------------------------------------
// T009-4  Flag parse error
// ---------------------------------------------------------------------------

// TestRunRotateJWTSecret_FlagParseError passes an unknown flag; flag.ContinueOnError
// causes Parse to return an error which runRotateJWTSecret propagates.
func TestRunRotateJWTSecret_FlagParseError(t *testing.T) {
	err := runRotateJWTSecret([]string{"-nonexistent-flag"})
	if err == nil {
		t.Fatal("expected flag parse error, got nil")
	}
}

// ---------------------------------------------------------------------------
// T009-5  openAdminStore error — bad db path
// ---------------------------------------------------------------------------

// TestRunRotateJWTSecret_BadDBPath passes a db path inside a non-existent
// directory, which should cause store.New to fail.
func TestRunRotateJWTSecret_BadDBPath(t *testing.T) {
	err := runRotateJWTSecret([]string{"-db", "/nonexistent-dir-xyz/no.db", "-yes"})
	if err == nil {
		t.Fatal("expected error for bad db path, got nil")
	}
	if !strings.Contains(err.Error(), "open database") {
		t.Errorf("expected 'open database' in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// T009-6  server.RotateJWTSecret error — uninitialized DB
// ---------------------------------------------------------------------------

// TestRunRotateJWTSecret_UninitializedDB creates a fresh empty store without
// calling InitJWTSecret, then runs runRotateJWTSecret.  RotateJWTSecret should
// return "instance not initialized" which propagates as the CLI error.
func TestRunRotateJWTSecret_UninitializedDB(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	// Deliberately do NOT call InitJWTSecret.
	st.Close()

	err := runRotateJWTSecret([]string{"-db", dbPath, "-yes"})
	if err == nil {
		t.Fatal("expected error for uninitialized DB, got nil")
	}
	lowerErr := strings.ToLower(err.Error())
	if !strings.Contains(lowerErr, "not initialized") && !strings.Contains(lowerErr, "not found") {
		t.Errorf("expected 'not initialized' or 'not found' in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// T009-7  runAdmin dispatches rotate-jwt-secret (covers admin.go case branch)
// ---------------------------------------------------------------------------

// TestRunAdmin_DispatchesRotateJWTSecret covers the "rotate-jwt-secret" case
// in runAdmin.  We seed an initialized DB, close it, and dispatch via
// runAdmin.  A successful rotation returns nil and the dispatch was exercised.
func TestRunAdmin_DispatchesRotateJWTSecret(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	if _, err := server.InitJWTSecret(st); err != nil {
		st.Close()
		t.Fatalf("InitJWTSecret: %v", err)
	}
	if _, err := server.InitStorageKey(st); err != nil {
		st.Close()
		t.Fatalf("InitStorageKey: %v", err)
	}
	st.Close()

	var runErr error
	captureStdout(t, func() {
		runErr = runAdmin([]string{"rotate-jwt-secret", "-db", dbPath, "-yes"})
	})
	if runErr != nil {
		t.Fatalf("runAdmin(rotate-jwt-secret): %v", runErr)
	}
}

// ---------------------------------------------------------------------------
// T009-8  Fault injection: DROP api_tokens table to cover error branch in rotate.go
// ---------------------------------------------------------------------------

// TestRotateJWTSecret_APITokensExecError covers the error return inside
// server.RotateJWTSecret when the UPDATE api_tokens statement fails.
// We seed an initialized store, drop the api_tokens table, and call
// RotateJWTSecret directly to trigger the Exec failure path.
func TestRotateJWTSecret_APITokensExecError(t *testing.T) {
	st, _, _ := initTestStoreForRotation(t)
	defer st.Close()

	// Drop api_tokens to force the UPDATE Exec inside the transaction to fail.
	if _, err := st.DB().Exec("DROP TABLE api_tokens"); err != nil {
		t.Fatalf("DROP TABLE api_tokens: %v", err)
	}

	_, err := server.RotateJWTSecret(st)
	if err == nil {
		t.Fatal("expected error after DROP TABLE api_tokens, got nil")
	}
	if !strings.Contains(err.Error(), "revoke all api tokens") {
		t.Errorf("expected 'revoke all api tokens' in error, got: %v", err)
	}
}
