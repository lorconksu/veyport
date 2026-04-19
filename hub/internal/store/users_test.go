package store_test

import (
	"testing"

	"github.com/wyiu/aerodocs/hub/internal/model"
)

const (
	testAliceEmail = "alice@test.com"
	testGetUserFmt = "get user: %v"
	testEmailAAcom = "a@a.com"
)

func TestCreateAndGetUser(t *testing.T) {
	s := testStore(t)

	user := &model.User{
		ID:           "test-uuid-1",
		Username:     "admin",
		Email:        "admin@test.com",
		PasswordHash: "$2a$12$fakehash",
		Role:         model.RoleAdmin,
	}

	if err := s.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	got, err := s.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.ID != "test-uuid-1" {
		t.Fatalf("expected id 'test-uuid-1', got '%s'", got.ID)
	}
	if got.Role != model.RoleAdmin {
		t.Fatalf("expected role 'admin', got '%s'", got.Role)
	}
}

func TestCreateUser_DuplicateUsername(t *testing.T) {
	s := testStore(t)

	user := &model.User{
		ID: "u1", Username: "dup", Email: testEmailAAcom,
		PasswordHash: "hash", Role: model.RoleViewer,
	}
	if err := s.CreateUser(user); err != nil {
		t.Fatalf("first create: %v", err)
	}

	user2 := &model.User{
		ID: "u2", Username: "dup", Email: "b@b.com",
		PasswordHash: "hash", Role: model.RoleViewer,
	}
	if err := s.CreateUser(user2); err == nil {
		t.Fatal("expected error for duplicate username")
	}
}

func TestUserCount(t *testing.T) {
	s := testStore(t)

	count, err := s.UserCount()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 users, got %d", count)
	}

	s.CreateUser(&model.User{
		ID: "u1", Username: "a", Email: testEmailAAcom,
		PasswordHash: "h", Role: model.RoleAdmin,
	})

	count, _ = s.UserCount()
	if count != 1 {
		t.Fatalf("expected 1 user, got %d", count)
	}
}

func TestUpdateUserTOTP(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "a", Email: testEmailAAcom,
		PasswordHash: "h", Role: model.RoleAdmin,
	})

	secret := "JBSWY3DPEHPK3PXP"
	if err := s.UpdateUserTOTP("u1", &secret, true); err != nil {
		t.Fatalf("update totp: %v", err)
	}

	user, _ := s.GetUserByID("u1")
	if !user.TOTPEnabled {
		t.Fatal("expected totp_enabled = true")
	}
	if user.TOTPSecret == nil || *user.TOTPSecret != secret {
		t.Fatal("totp_secret not set correctly")
	}
}

func TestUpdateUserRole(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "h", Role: model.RoleViewer,
	})

	if err := s.UpdateUserRole("u1", model.RoleAdmin); err != nil {
		t.Fatalf("update role: %v", err)
	}

	user, err := s.GetUserByID("u1")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if user.Role != model.RoleAdmin {
		t.Fatalf("expected role 'admin', got '%s'", user.Role)
	}
}

func TestUpdateUserRole_NonexistentUser(t *testing.T) {
	s := testStore(t)

	err := s.UpdateUserRole("nonexistent", model.RoleAdmin)
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestListUsers(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "h", Role: model.RoleAdmin,
	})
	s.CreateUser(&model.User{
		ID: "u2", Username: "bob", Email: "bob@test.com",
		PasswordHash: "h", Role: model.RoleViewer,
	})

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

func TestDeleteUser(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "h", Role: model.RoleAdmin,
	})

	if err := s.DeleteUser("u1"); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	_, err := s.GetUserByID("u1")
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestDeleteUser_NotFound(t *testing.T) {
	s := testStore(t)

	err := s.DeleteUser("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestUpdateUserAvatar(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "h", Role: model.RoleAdmin,
	})

	avatar := "data:image/png;base64,abc123"
	if err := s.UpdateUserAvatar("u1", &avatar); err != nil {
		t.Fatalf("update avatar: %v", err)
	}

	user, err := s.GetUserByID("u1")
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if user.Avatar == nil || *user.Avatar != avatar {
		t.Fatalf("expected avatar '%s', got '%v'", avatar, user.Avatar)
	}
}

func TestUpdateUserAvatar_ClearAvatar(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "h", Role: model.RoleAdmin,
	})

	// Set avatar
	avatar := "data:image/png;base64,abc123"
	s.UpdateUserAvatar("u1", &avatar)

	// Clear avatar
	if err := s.UpdateUserAvatar("u1", nil); err != nil {
		t.Fatalf("clear avatar: %v", err)
	}

	user, _ := s.GetUserByID("u1")
	if user.Avatar != nil {
		t.Fatalf("expected nil avatar after clear, got '%v'", user.Avatar)
	}
}

func TestUpdateUserPassword(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "oldhash", Role: model.RoleAdmin,
	})

	if err := s.UpdateUserPassword("u1", "newhash"); err != nil {
		t.Fatalf("update password: %v", err)
	}

	user, _ := s.GetUserByID("u1")
	if user.PasswordHash != "newhash" {
		t.Fatalf("expected 'newhash', got '%s'", user.PasswordHash)
	}
}

func TestGetUserByID_NotFound(t *testing.T) {
	s := testStore(t)

	_, err := s.GetUserByID("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent user ID")
	}
}

func TestGetUserByUsername_NotFound(t *testing.T) {
	s := testStore(t)

	_, err := s.GetUserByUsername("nobody")
	if err == nil {
		t.Fatal("expected error for nonexistent username")
	}
}

func TestUpdateUserTOTP_Clear(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "h", Role: model.RoleAdmin,
	})

	secret := "JBSWY3DPEHPK3PXP"
	s.UpdateUserTOTP("u1", &secret, true)

	// Clear TOTP
	if err := s.UpdateUserTOTP("u1", nil, false); err != nil {
		t.Fatalf("clear totp: %v", err)
	}

	user, _ := s.GetUserByID("u1")
	if user.TOTPEnabled {
		t.Fatal("expected totp_enabled=false after clear")
	}
	if user.TOTPSecret != nil {
		t.Fatal("expected nil totp_secret after clear")
	}
}

func TestIncrementTokenGeneration(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "h", Role: model.RoleAdmin,
	})

	// Token generation starts at 0
	user, _ := s.GetUserByID("u1")
	if user.TokenGeneration != 0 {
		t.Fatalf("expected initial token_generation=0, got %d", user.TokenGeneration)
	}

	newGen, err := s.IncrementTokenGeneration("u1")
	if err != nil {
		t.Fatalf("increment token generation: %v", err)
	}
	if newGen != 1 {
		t.Fatalf("expected returned generation=1, got %d", newGen)
	}

	user, _ = s.GetUserByID("u1")
	if user.TokenGeneration != 1 {
		t.Fatalf("expected token_generation=1, got %d", user.TokenGeneration)
	}

	// Increment again
	newGen2, _ := s.IncrementTokenGeneration("u1")
	if newGen2 != 2 {
		t.Fatalf("expected returned generation=2, got %d", newGen2)
	}
	user, _ = s.GetUserByID("u1")
	if user.TokenGeneration != 2 {
		t.Fatalf("expected token_generation=2, got %d", user.TokenGeneration)
	}
}

func TestInitializedUserCount(t *testing.T) {
	s := testStore(t)

	// No users
	count, err := s.InitializedUserCount()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}

	// Add a user with TOTP disabled (not initialized)
	s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "h", Role: model.RoleAdmin, TOTPEnabled: false,
	})

	count, _ = s.InitializedUserCount()
	if count != 0 {
		t.Fatalf("expected 0 initialized users, got %d", count)
	}

	// Enable TOTP (marks as initialized)
	secret := "JBSWY3DPEHPK3PXP"
	s.UpdateUserTOTP("u1", &secret, true)

	count, _ = s.InitializedUserCount()
	if count != 1 {
		t.Fatalf("expected 1 initialized user, got %d", count)
	}
}

func TestInitialSetupComplete_UsesPersistentFlag(t *testing.T) {
	s := testStore(t)

	if initialized, err := s.InitialSetupComplete(); err != nil {
		t.Fatalf("initial setup complete: %v", err)
	} else if initialized {
		t.Fatal("expected initial setup incomplete for empty store")
	}

	if err := s.CreateUser(&model.User{
		ID: "u1", Username: "alice", Email: testAliceEmail,
		PasswordHash: "h", Role: model.RoleAdmin, TOTPEnabled: false,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	if initialized, err := s.InitialSetupComplete(); err != nil {
		t.Fatalf("initial setup complete: %v", err)
	} else if initialized {
		t.Fatal("expected setup incomplete before flag is written")
	}

	if err := s.MarkInitialSetupComplete(); err != nil {
		t.Fatalf("mark setup complete: %v", err)
	}

	if initialized, err := s.InitialSetupComplete(); err != nil {
		t.Fatalf("initial setup complete after mark: %v", err)
	} else if !initialized {
		t.Fatal("expected setup complete after persistent flag is written")
	}
}

func TestDeleteIncompleteUsers(t *testing.T) {
	s := testStore(t)

	// Add one complete and one incomplete user
	s.CreateUser(&model.User{
		ID: "u1", Username: "complete", Email: "c@test.com",
		PasswordHash: "h", Role: model.RoleAdmin, TOTPEnabled: true,
	})
	s.CreateUser(&model.User{
		ID: "u2", Username: "incomplete", Email: "i@test.com",
		PasswordHash: "h", Role: model.RoleViewer, TOTPEnabled: false,
	})

	if err := s.DeleteIncompleteUsers(); err != nil {
		t.Fatalf("delete incomplete users: %v", err)
	}

	users, _ := s.ListUsers()
	if len(users) != 1 {
		t.Fatalf("expected 1 user remaining, got %d", len(users))
	}
	if users[0].ID != "u1" {
		t.Fatalf("expected u1 to remain, got %s", users[0].ID)
	}
}

func TestListUsers_Empty(t *testing.T) {
	s := testStore(t)

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("list empty users: %v", err)
	}
	if users != nil && len(users) != 0 {
		t.Fatalf("expected 0 users, got %d", len(users))
	}
}
