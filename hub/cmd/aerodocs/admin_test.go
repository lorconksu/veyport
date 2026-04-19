package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
	"github.com/wyiu/aerodocs/hub/internal/store"
)

func TestRunAdmin_NoArgs(t *testing.T) {
	err := runAdmin(nil)
	if err == nil || !strings.Contains(err.Error(), "usage: aerodocs admin") {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestRunAdmin_UnknownCommand(t *testing.T) {
	err := runAdmin([]string{"unknown"})
	if err == nil || !strings.Contains(err.Error(), "unknown admin command") {
		t.Fatalf("expected unknown command error, got %v", err)
	}
}

func TestRunAdmin_DispatchesResetTOTP(t *testing.T) {
	err := runAdmin([]string{"reset-totp"})
	if err == nil || err.Error() != "--username is required" {
		t.Fatalf("expected reset-totp dispatch error, got %v", err)
	}
}

func TestRunAdmin_DispatchesCreateAPIToken(t *testing.T) {
	err := runAdmin([]string{"create-api-token"})
	if err == nil || err.Error() != "--username is required" {
		t.Fatalf("expected create-api-token dispatch error, got %v", err)
	}
}

func TestRunAdmin_DispatchesListAPITokens(t *testing.T) {
	err := runAdmin([]string{"list-api-tokens"})
	if err == nil || err.Error() != "--username is required" {
		t.Fatalf("expected list-api-tokens dispatch error, got %v", err)
	}
}

func TestRunAdmin_DispatchesRevokeAPIToken(t *testing.T) {
	err := runAdmin([]string{"revoke-api-token"})
	if err == nil || err.Error() != "--id is required" {
		t.Fatalf("expected revoke-api-token dispatch error, got %v", err)
	}
}

func TestRunResetTOTP_RequiresUsername(t *testing.T) {
	err := runResetTOTP(nil)
	if err == nil || err.Error() != "--username is required" {
		t.Fatalf("expected missing username error, got %v", err)
	}
}

func TestRunResetTOTP_BadDB(t *testing.T) {
	err := runResetTOTP([]string{"--username", "resetme", "--db", "/dev/null/admin.db"})
	if err == nil || !strings.Contains(err.Error(), "open database:") {
		t.Fatalf("expected db open error, got %v", err)
	}
}

func TestRunResetTOTP_UserNotFound(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	st.Close()

	err := runResetTOTP([]string{"--username", "missing", "--db", dbPath})
	if err == nil || !strings.Contains(err.Error(), `user "missing" not found`) {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func TestRunResetTOTP_Success(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	secret := "totp-secret"
	user := createAdminUser(t, st, "resetme", model.RoleAdmin, &secret, true)
	originalHash := user.PasswordHash
	st.Close()

	output := captureStdout(t, func() {
		if err := runResetTOTP([]string{"--username", "resetme", "--db", dbPath}); err != nil {
			t.Fatalf("run reset-totp: %v", err)
		}
	})

	verifyStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("re-open store: %v", err)
	}
	defer verifyStore.Close()

	got, err := verifyStore.GetUserByUsername("resetme")
	if err != nil {
		t.Fatalf("fetch user: %v", err)
	}
	if got.TOTPSecret != nil {
		t.Fatal("expected TOTP secret to be cleared")
	}
	if got.TOTPEnabled {
		t.Fatal("expected TOTP to be disabled")
	}
	if got.PasswordHash == originalHash {
		t.Fatal("expected temporary password hash to be updated")
	}
	if !strings.Contains(output, "Temporary password:") {
		t.Fatalf("expected temporary password in output, got %q", output)
	}
}

func TestRunCreateAPIToken_RequiresUsername(t *testing.T) {
	err := runCreateAPIToken([]string{"--name", "nightly"})
	if err == nil || err.Error() != "--username is required" {
		t.Fatalf("expected missing username error, got %v", err)
	}
}

func TestRunCreateAPIToken_RequiresName(t *testing.T) {
	err := runCreateAPIToken([]string{"--username", "scanner"})
	if err == nil || err.Error() != "--name is required" {
		t.Fatalf("expected missing name error, got %v", err)
	}
}

func TestRunCreateAPIToken_InvalidDuration(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	createAdminUser(t, st, "scanner", model.RoleViewer, nil, false)
	st.Close()

	err := runCreateAPIToken([]string{
		"--username", "scanner",
		"--name", "nightly",
		"--expires-in", "not-a-duration",
		"--db", dbPath,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid value") {
		t.Fatalf("expected duration parse error, got %v", err)
	}
}

func TestRunCreateAPIToken_Success(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	user := createAdminUser(t, st, "scanner", model.RoleViewer, nil, false)
	st.Close()

	output := captureStdout(t, func() {
		err := runCreateAPIToken([]string{
			"--username", "scanner",
			"--name", "nightly scan",
			"--expires-in", "0",
			"--db", dbPath,
		})
		if err != nil {
			t.Fatalf("run create-api-token: %v", err)
		}
	})

	verifyStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("re-open store: %v", err)
	}
	defer verifyStore.Close()

	tokens, err := verifyStore.ListAPITokensByUserID(user.ID)
	if err != nil {
		t.Fatalf("list api tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0].ExpiresAt != nil {
		t.Fatal("expected token with no expiry")
	}
	if tokens[0].Name != "nightly scan" {
		t.Fatalf("expected token name to be trimmed and stored, got %q", tokens[0].Name)
	}
	if !strings.Contains(output, "Expires At: never") || !strings.Contains(output, "Token: adt_") {
		t.Fatalf("expected token details in output, got %q", output)
	}
}

func TestRunListAPITokens_RequiresUsername(t *testing.T) {
	err := runListAPITokens(nil)
	if err == nil || err.Error() != "--username is required" {
		t.Fatalf("expected missing username error, got %v", err)
	}
}

func TestRunListAPITokens_NoTokens(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	createAdminUser(t, st, "scanner", model.RoleViewer, nil, false)
	st.Close()

	output := captureStdout(t, func() {
		if err := runListAPITokens([]string{"--username", "scanner", "--db", dbPath}); err != nil {
			t.Fatalf("run list-api-tokens: %v", err)
		}
	})

	if !strings.Contains(output, `No API tokens found for "scanner"`) {
		t.Fatalf("expected empty token message, got %q", output)
	}
}

func TestRunListAPITokens_ShowsStatuses(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	user := createAdminUser(t, st, "scanner", model.RoleViewer, nil, false)
	now := time.Now().UTC()
	lastUsedAt := now.Add(-time.Minute)
	expiredAt := now.Add(-time.Hour)
	revokedAt := now.Add(-30 * time.Minute)

	tokens := []*model.APIToken{
		{
			ID:          "active-token",
			UserID:      user.ID,
			Name:        "active",
			TokenHash:   "hash-active",
			TokenPrefix: "adt_active",
			LastUsedAt:  &lastUsedAt,
		},
		{
			ID:          "expired-token",
			UserID:      user.ID,
			Name:        "expired",
			TokenHash:   "hash-expired",
			TokenPrefix: "adt_expired",
			ExpiresAt:   &expiredAt,
		},
		{
			ID:          "revoked-token",
			UserID:      user.ID,
			Name:        "revoked",
			TokenHash:   "hash-revoked",
			TokenPrefix: "adt_revoked",
			RevokedAt:   &revokedAt,
		},
	}
	for _, token := range tokens {
		if err := st.CreateAPIToken(token); err != nil {
			t.Fatalf("create api token %s: %v", token.ID, err)
		}
	}
	st.Close()

	output := captureStdout(t, func() {
		if err := runListAPITokens([]string{"--username", "scanner", "--db", dbPath}); err != nil {
			t.Fatalf("run list-api-tokens: %v", err)
		}
	})

	for _, fragment := range []string{
		"ID\tNAME\tPREFIX\tEXPIRES_AT\tLAST_USED_AT\tSTATUS",
		"active-token\tactive\tadt_active\tnever\t",
		"\tactive\n",
		"expired-token\texpired\tadt_expired\t",
		"\texpired\n",
		"revoked-token\trevoked\tadt_revoked\tnever\tnever\trevoked",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected output to contain %q, got %q", fragment, output)
		}
	}
}

func TestRunRevokeAPIToken_RequiresID(t *testing.T) {
	err := runRevokeAPIToken(nil)
	if err == nil || err.Error() != "--id is required" {
		t.Fatalf("expected missing id error, got %v", err)
	}
}

func TestRunRevokeAPIToken_Success(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	user := createAdminUser(t, st, "scanner", model.RoleViewer, nil, false)
	token := &model.APIToken{
		ID:          "tok-1",
		UserID:      user.ID,
		Name:        "nightly",
		TokenHash:   "hash-1",
		TokenPrefix: "adt_123456789abc",
	}
	if err := st.CreateAPIToken(token); err != nil {
		t.Fatalf("create api token: %v", err)
	}
	st.Close()

	output := captureStdout(t, func() {
		if err := runRevokeAPIToken([]string{"--id", token.ID, "--db", dbPath}); err != nil {
			t.Fatalf("run revoke-api-token: %v", err)
		}
	})

	verifyStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("re-open store: %v", err)
	}
	defer verifyStore.Close()

	tokens, err := verifyStore.ListAPITokensByUserID(user.ID)
	if err != nil {
		t.Fatalf("list api tokens: %v", err)
	}
	if len(tokens) != 1 || tokens[0].RevokedAt == nil {
		t.Fatalf("expected revoked token, got %+v", tokens)
	}
	if !strings.Contains(output, "API token tok-1 revoked") {
		t.Fatalf("expected revoke output, got %q", output)
	}
}

func TestRunRevokeAPIToken_NotFound(t *testing.T) {
	dbPath, st := newAdminTestStore(t)
	st.Close()

	err := runRevokeAPIToken([]string{"--id", "missing", "--db", dbPath})
	if err == nil || err.Error() != "api token not found" {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func newAdminTestStore(t *testing.T) (string, *store.Store) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "admin-test.db")
	st, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	return dbPath, st
}

func createAdminUser(t *testing.T, st *store.Store, username string, role model.Role, secret *string, totpEnabled bool) *model.User {
	t.Helper()

	hash, err := auth.HashPassword("MyP@ssw0rd!234")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &model.User{
		ID:           uuid.NewString(),
		Username:     username,
		Email:        username + "@test.com",
		PasswordHash: hash,
		Role:         role,
		TOTPSecret:   secret,
		TOTPEnabled:  totpEnabled,
	}
	if err := st.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	defer reader.Close()
	defer func() {
		_ = writer.Close()
		os.Stdout = originalStdout
	}()

	os.Stdout = writer
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	os.Stdout = originalStdout

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(output)
}
