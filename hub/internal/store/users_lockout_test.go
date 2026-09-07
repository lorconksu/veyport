package store_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

// TestCreateUser_LockoutFieldsDefaultZero verifies that a freshly created
// user reads back a zero failure count and nil lifecycle timestamps via both
// GetUserByID and ListUsers.
func TestCreateUser_LockoutFieldsDefaultZero(t *testing.T) {
	s := testStore(t)

	if err := s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "h", Role: model.RoleAdmin,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	got, err := s.GetUserByID("u1")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.FailedLoginCount != 0 {
		t.Fatalf("expected failed_login_count = 0, got %d", got.FailedLoginCount)
	}
	if got.LastFailedLoginAt != nil {
		t.Fatalf("expected nil last_failed_login_at, got %v", got.LastFailedLoginAt)
	}
	if got.LastLoginAt != nil {
		t.Fatalf("expected nil last_login_at, got %v", got.LastLoginAt)
	}
	if got.LockedUntil != nil {
		t.Fatalf("expected nil locked_until, got %v", got.LockedUntil)
	}

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	listed := users[0]
	if listed.FailedLoginCount != 0 {
		t.Fatalf("expected failed_login_count = 0 via ListUsers, got %d", listed.FailedLoginCount)
	}
	if listed.LastFailedLoginAt != nil || listed.LastLoginAt != nil || listed.LockedUntil != nil {
		t.Fatalf("expected nil lifecycle timestamps via ListUsers, got %+v", listed)
	}
}

// TestUpsertLDAPUser_PreservesLockedUntil verifies that the LDAP update path
// does not clear a previously set locked_until on an existing LDAP user.
func TestUpsertLDAPUser_PreservesLockedUntil(t *testing.T) {
	s := testStore(t)

	if err := s.CreateUser(&model.User{
		ID:           "ldap-1",
		Username:     "alice",
		Email:        "alice@example.com",
		Role:         model.RoleViewer,
		AuthProvider: model.AuthProviderLDAP,
		ExternalID:   "entry-1",
	}); err != nil {
		t.Fatalf("create ldap user: %v", err)
	}

	if _, err := s.DB().Exec(
		"UPDATE users SET locked_until = ? WHERE id = ?", "2030-01-01 00:00:00", "ldap-1",
	); err != nil {
		t.Fatalf("set locked_until directly: %v", err)
	}

	if _, err := s.UpsertLDAPUser(&model.User{
		Username:   "alice",
		Email:      "alice-new@example.com",
		Role:       model.RoleViewer,
		ExternalID: "entry-1",
	}); err != nil {
		t.Fatalf("upsert ldap user: %v", err)
	}

	after, err := s.GetUserByID("ldap-1")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if after.LockedUntil == nil {
		t.Fatal("expected locked_until to remain set after LDAP upsert, got nil")
	}
	if after.LockedUntil.Format("2006-01-02 15:04:05") != "2030-01-01 00:00:00" {
		t.Fatalf("expected locked_until '2030-01-01 00:00:00', got %v", after.LockedUntil)
	}
}
