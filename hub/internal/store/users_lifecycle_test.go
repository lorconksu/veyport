package store_test

import (
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

// TestUserLifecycleColumns_RoundTrip verifies that the five account-lifecycle
// columns added by migration 022 round-trip through both read paths
// (GetUserByID and ListUsers) once set directly against the database, the
// same way an already-migrated hub would carry them.
func TestUserLifecycleColumns_RoundTrip(t *testing.T) {
	s := testStore(t)

	if err := s.CreateUser(&model.User{
		ID: "lifecycle-1", Username: "lifecycle1", Email: "lifecycle1@test.com",
		PasswordHash: "h", Role: model.RoleAdmin,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := s.DB().Exec(
		`UPDATE users
		 SET disabled_at = ?, disabled_by = ?, reactivated_at = ?,
		     dormancy_exempt = 1, last_activity_at = ?
		 WHERE id = ?`,
		"2026-01-01 00:00:00", "admin-2", "2026-01-02 00:00:00", "2026-01-03 00:00:00",
		"lifecycle-1",
	); err != nil {
		t.Fatalf("set lifecycle columns directly: %v", err)
	}

	assertLifecycleFields := func(t *testing.T, u *model.User) {
		t.Helper()
		if u.DisabledAt == nil || u.DisabledAt.Format("2006-01-02 15:04:05") != "2026-01-01 00:00:00" {
			t.Fatalf("expected disabled_at '2026-01-01 00:00:00', got %v", u.DisabledAt)
		}
		if u.DisabledBy == nil || *u.DisabledBy != "admin-2" {
			t.Fatalf("expected disabled_by 'admin-2', got %v", u.DisabledBy)
		}
		if u.ReactivatedAt == nil || u.ReactivatedAt.Format("2006-01-02 15:04:05") != "2026-01-02 00:00:00" {
			t.Fatalf("expected reactivated_at '2026-01-02 00:00:00', got %v", u.ReactivatedAt)
		}
		if !u.DormancyExempt {
			t.Fatal("expected dormancy_exempt true")
		}
		if u.LastActivityAt == nil || u.LastActivityAt.Format("2006-01-02 15:04:05") != "2026-01-03 00:00:00" {
			t.Fatalf("expected last_activity_at '2026-01-03 00:00:00', got %v", u.LastActivityAt)
		}
	}

	got, err := s.GetUserByID("lifecycle-1")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	assertLifecycleFields(t, got)

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	assertLifecycleFields(t, &users[0])
}

// TestUserLifecycleColumns_DefaultZero verifies a freshly created user (no
// lifecycle columns touched) reads back an unexempt, fully-enabled account
// with nil lifecycle timestamps.
func TestUserLifecycleColumns_DefaultZero(t *testing.T) {
	s := testStore(t)

	if err := s.CreateUser(&model.User{
		ID: "lifecycle-2", Username: "lifecycle2", Email: "lifecycle2@test.com",
		PasswordHash: "h", Role: model.RoleViewer,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	got, err := s.GetUserByID("lifecycle-2")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.DisabledAt != nil || got.DisabledBy != nil || got.ReactivatedAt != nil || got.LastActivityAt != nil {
		t.Fatalf("expected nil lifecycle timestamps, got %+v", got)
	}
	if got.DormancyExempt {
		t.Fatal("expected dormancy_exempt false by default")
	}
}

// TestCreateUser_DormancyExemptPersists verifies CreateUser accepts and
// persists DormancyExempt = true (used by the register handler to mark the
// first admin exempt on a fresh install).
func TestCreateUser_DormancyExemptPersists(t *testing.T) {
	s := testStore(t)

	if err := s.CreateUser(&model.User{
		ID: "lifecycle-3", Username: "lifecycle3", Email: "lifecycle3@test.com",
		PasswordHash: "h", Role: model.RoleAdmin, DormancyExempt: true,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	got, err := s.GetUserByID("lifecycle-3")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if !got.DormancyExempt {
		t.Fatal("expected dormancy_exempt true from CreateUser")
	}
}

// TestUpsertLDAPUser_PreservesLifecycleColumns verifies that the LDAP update
// path (updateLDAPUser) never touches disabled_at, dormancy_exempt or
// reactivated_at on an existing LDAP user — those are hub-local
// administrative state, not synced attributes.
func TestUpsertLDAPUser_PreservesLifecycleColumns(t *testing.T) {
	s := testStore(t)

	if err := s.CreateUser(&model.User{
		ID:           "ldap-lifecycle-1",
		Username:     "ldaplifecycle",
		Email:        "ldaplifecycle@example.com",
		Role:         model.RoleAdmin,
		AuthProvider: model.AuthProviderLDAP,
		ExternalID:   "entry-lifecycle-1",
	}); err != nil {
		t.Fatalf("create ldap user: %v", err)
	}

	if _, err := s.DB().Exec(
		`UPDATE users SET disabled_at = ?, dormancy_exempt = 1, reactivated_at = ? WHERE id = ?`,
		"2026-01-01 00:00:00", "2026-01-02 00:00:00", "ldap-lifecycle-1",
	); err != nil {
		t.Fatalf("set lifecycle columns directly: %v", err)
	}

	if _, err := s.UpsertLDAPUser(&model.User{
		Username:   "ldaplifecycle",
		Email:      "ldaplifecycle-new@example.com",
		Role:       model.RoleAdmin,
		ExternalID: "entry-lifecycle-1",
	}); err != nil {
		t.Fatalf("upsert ldap user: %v", err)
	}

	after, err := s.GetUserByID("ldap-lifecycle-1")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if after.DisabledAt == nil || after.DisabledAt.Format("2006-01-02 15:04:05") != "2026-01-01 00:00:00" {
		t.Fatalf("expected disabled_at to remain set after LDAP upsert, got %v", after.DisabledAt)
	}
	if !after.DormancyExempt {
		t.Fatal("expected dormancy_exempt to remain true after LDAP upsert")
	}
	if after.ReactivatedAt == nil || after.ReactivatedAt.Format("2006-01-02 15:04:05") != "2026-01-02 00:00:00" {
		t.Fatalf("expected reactivated_at to remain set after LDAP upsert, got %v", after.ReactivatedAt)
	}
}

// TestUpdateUserRole_ClearsDormancyExemptForNonAdmin verifies UpdateUserRole
// clears dormancy_exempt when the new role is not admin, and leaves it set
// when the new role is admin.
func TestUpdateUserRole_ClearsDormancyExemptForNonAdmin(t *testing.T) {
	s := testStore(t)

	if err := s.CreateUser(&model.User{
		ID: "role-1", Username: "roleuser1", Email: "roleuser1@test.com",
		PasswordHash: "h", Role: model.RoleAdmin, DormancyExempt: true,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := s.UpdateUserRole("role-1", model.RoleViewer); err != nil {
		t.Fatalf("update role to viewer: %v", err)
	}
	got, err := s.GetUserByID("role-1")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.DormancyExempt {
		t.Fatal("expected dormancy_exempt cleared after role change to viewer")
	}
	if got.Role != model.RoleViewer {
		t.Fatalf("expected role viewer, got %v", got.Role)
	}
}

func TestUpdateUserRole_KeepsDormancyExemptForAdmin(t *testing.T) {
	s := testStore(t)

	if err := s.CreateUser(&model.User{
		ID: "role-2", Username: "roleuser2", Email: "roleuser2@test.com",
		PasswordHash: "h", Role: model.RoleAdmin, DormancyExempt: true,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := s.UpdateUserRole("role-2", model.RoleAdmin); err != nil {
		t.Fatalf("update role to admin: %v", err)
	}
	got, err := s.GetUserByID("role-2")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if !got.DormancyExempt {
		t.Fatal("expected dormancy_exempt to remain true after re-affirming admin role")
	}
}

// TestRecordLoginSuccess_StampsLastActivity verifies RecordLoginSuccess sets
// last_activity_at to the same instant as last_login_at, so a completed
// sign-in counts as activity for the dormancy clock.
func TestRecordLoginSuccess_StampsLastActivity(t *testing.T) {
	s := testStore(t)

	if err := s.CreateUser(&model.User{
		ID: "login-1", Username: "loginuser1", Email: "loginuser1@test.com",
		PasswordHash: "h", Role: model.RoleViewer,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := s.RecordLoginSuccess("login-1", now); err != nil {
		t.Fatalf("record login success: %v", err)
	}

	got, err := s.GetUserByID("login-1")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.LastLoginAt == nil || !got.LastLoginAt.Equal(now) {
		t.Fatalf("expected last_login_at %v, got %v", now, got.LastLoginAt)
	}
	if got.LastActivityAt == nil || !got.LastActivityAt.Equal(now) {
		t.Fatalf("expected last_activity_at %v, got %v", now, got.LastActivityAt)
	}
}
