package store_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

const (
	testUserID1 = "user-1"
	testVarLog  = "/var/log"
)

func TestCreatePermission(t *testing.T) {
	s := testStore(t)
	s.CreateUser(&model.User{ID: testUserID1, Username: "alice", Email: testAliceEmail, PasswordHash: "hashedpw", Role: model.RoleViewer})
	s.CreateServer(&model.Server{ID: "srv-1", Name: "web-1", Status: "online", Labels: "{}"})

	p, err := s.CreatePermission(testUserID1, "srv-1", testVarLog)
	if err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if p.UserID != testUserID1 || p.ServerID != "srv-1" || p.Path != testVarLog {
		t.Fatalf("unexpected permission: %+v", p)
	}
}

func TestCreatePermission_Duplicate(t *testing.T) {
	s := testStore(t)
	s.CreateUser(&model.User{ID: testUserID1, Username: "alice", Email: testAliceEmail, PasswordHash: "hashedpw", Role: model.RoleViewer})
	s.CreateServer(&model.Server{ID: "srv-1", Name: "web-1", Status: "online", Labels: "{}"})

	s.CreatePermission(testUserID1, "srv-1", testVarLog)
	_, err := s.CreatePermission(testUserID1, "srv-1", testVarLog)
	if err == nil {
		t.Fatal("expected error for duplicate permission")
	}
}

func TestListPermissionsForServer(t *testing.T) {
	s := testStore(t)
	s.CreateUser(&model.User{ID: testUserID1, Username: "alice", Email: testAliceEmail, PasswordHash: "hashedpw", Role: model.RoleViewer})
	s.CreateUser(&model.User{ID: "user-2", Username: "bob", Email: "bob@test.com", PasswordHash: "hashedpw", Role: model.RoleViewer})
	s.CreateServer(&model.Server{ID: "srv-1", Name: "web-1", Status: "online", Labels: "{}"})

	s.CreatePermission(testUserID1, "srv-1", testVarLog)
	s.CreatePermission("user-2", "srv-1", "/etc")

	perms, err := s.ListPermissionsForServer("srv-1")
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	if len(perms) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(perms))
	}
}

func TestGetUserPathsForServer(t *testing.T) {
	s := testStore(t)
	s.CreateUser(&model.User{ID: testUserID1, Username: "alice", Email: testAliceEmail, PasswordHash: "hashedpw", Role: model.RoleViewer})
	s.CreateServer(&model.Server{ID: "srv-1", Name: "web-1", Status: "online", Labels: "{}"})

	s.CreatePermission(testUserID1, "srv-1", testVarLog)
	s.CreatePermission(testUserID1, "srv-1", "/etc")

	paths, err := s.GetUserPathsForServer(testUserID1, "srv-1")
	if err != nil {
		t.Fatalf("get paths: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
}

func TestDeletePermission(t *testing.T) {
	s := testStore(t)
	s.CreateUser(&model.User{ID: testUserID1, Username: "alice", Email: testAliceEmail, PasswordHash: "hashedpw", Role: model.RoleViewer})
	s.CreateServer(&model.Server{ID: "srv-1", Name: "web-1", Status: "online", Labels: "{}"})

	p, _ := s.CreatePermission(testUserID1, "srv-1", testVarLog)
	err := s.DeletePermission(p.ID)
	if err != nil {
		t.Fatalf("delete permission: %v", err)
	}

	perms, _ := s.ListPermissionsForServer("srv-1")
	if len(perms) != 0 {
		t.Fatalf("expected 0 permissions after delete, got %d", len(perms))
	}
}

func TestDeletePermission_NotFound(t *testing.T) {
	s := testStore(t)

	err := s.DeletePermission("nonexistent-id")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent permission")
	}
}

func TestGetPermissionByID(t *testing.T) {
	s := testStore(t)
	s.CreateUser(&model.User{ID: testUserID1, Username: "alice", Email: testAliceEmail, PasswordHash: "hashedpw", Role: model.RoleViewer})
	s.CreateServer(&model.Server{ID: "srv-1", Name: "web-1", Status: "online", Labels: "{}"})

	p, _ := s.CreatePermission(testUserID1, "srv-1", testVarLog)
	got, err := s.GetPermissionByID(p.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.Path != testVarLog {
		t.Fatalf("expected /var/log, got %s", got.Path)
	}
}
