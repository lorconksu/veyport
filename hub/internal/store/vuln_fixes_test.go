package store_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

const (
	testInsertPermSQL   = "INSERT INTO permissions (id, user_id, server_id, path) VALUES (?, ?, ?, ?)"
	testU1Email         = "u1@test.com"
	testGetExclusiveFmt = "get exclusive: %v"
)

// #43: Verify parameterized LIMIT/OFFSET works correctly with actual queries.
func TestListServersForUser_ParameterizedPagination(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "viewer", Email: "v@v.com",
		PasswordHash: "h", Role: model.RoleViewer,
	})

	for i := 0; i < 5; i++ {
		id := "s" + string(rune('1'+i))
		s.CreateServer(&model.Server{ID: id, Name: "srv-" + id, Status: "online", Labels: "{}"})
		s.DB().Exec(testInsertPermSQL,
			"p"+id, "u1", id, "/")
	}

	servers, total, err := s.ListServersForUser("u1", model.ServerFilter{Limit: 2, Offset: 1})
	if err != nil {
		t.Fatalf("list servers for user: %v", err)
	}
	if total != 5 {
		t.Fatalf("expected total 5, got %d", total)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
}

// #44: Test GetExclusiveServerAccess.
func TestGetExclusiveServerAccess_NoExclusive(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "user1", Email: testU1Email,
		PasswordHash: "h", Role: model.RoleViewer,
	})
	s.CreateUser(&model.User{
		ID: "u2", Username: "user2", Email: "u2@test.com",
		PasswordHash: "h", Role: model.RoleViewer,
	})

	s.CreateServer(&model.Server{ID: "s1", Name: "shared", Status: "online", Labels: "{}"})

	// Both users have access
	s.DB().Exec(testInsertPermSQL, "p1", "u1", "s1", "/")
	s.DB().Exec(testInsertPermSQL, "p2", "u2", "s1", "/")

	exclusive, err := s.GetExclusiveServerAccess("u1")
	if err != nil {
		t.Fatalf(testGetExclusiveFmt, err)
	}
	if len(exclusive) != 0 {
		t.Fatalf("expected no exclusive servers, got %v", exclusive)
	}
}

func TestGetExclusiveServerAccess_HasExclusive(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "user1", Email: testU1Email,
		PasswordHash: "h", Role: model.RoleViewer,
	})

	s.CreateServer(&model.Server{ID: "s1", Name: "exclusive", Status: "online", Labels: "{}"})

	// Only u1 has access
	s.DB().Exec(testInsertPermSQL, "p1", "u1", "s1", "/")

	exclusive, err := s.GetExclusiveServerAccess("u1")
	if err != nil {
		t.Fatalf(testGetExclusiveFmt, err)
	}
	if len(exclusive) != 1 || exclusive[0] != "s1" {
		t.Fatalf("expected [s1], got %v", exclusive)
	}
}

func TestGetExclusiveServerAccess_NoPermissions(t *testing.T) {
	s := testStore(t)

	s.CreateUser(&model.User{
		ID: "u1", Username: "user1", Email: testU1Email,
		PasswordHash: "h", Role: model.RoleViewer,
	})

	exclusive, err := s.GetExclusiveServerAccess("u1")
	if err != nil {
		t.Fatalf(testGetExclusiveFmt, err)
	}
	if len(exclusive) != 0 {
		t.Fatalf("expected no exclusive servers, got %v", exclusive)
	}
}

// #45: Test GetServerByName.
func TestGetServerByName(t *testing.T) {
	s := testStore(t)

	s.CreateServer(&model.Server{ID: "s1", Name: "web-prod-1", Status: "online", Labels: "{}"})

	srv, err := s.GetServerByName("web-prod-1")
	if err != nil {
		t.Fatalf("get server by name: %v", err)
	}
	if srv.ID != "s1" {
		t.Fatalf("expected ID 's1', got '%s'", srv.ID)
	}
}

func TestGetServerByName_NotFound(t *testing.T) {
	s := testStore(t)

	_, err := s.GetServerByName("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing server")
	}
}

// #45: Test UNIQUE constraint on server names.
func TestCreateServer_DuplicateName(t *testing.T) {
	s := testStore(t)

	s.CreateServer(&model.Server{ID: "s1", Name: "same-name", Status: "online", Labels: "{}"})
	err := s.CreateServer(&model.Server{ID: "s2", Name: "same-name", Status: "online", Labels: "{}"})
	if err == nil {
		t.Fatal("expected error for duplicate server name")
	}
}

// #42: Test audit log integrity hash.
func TestAuditLogIntegrityHash(t *testing.T) {
	s := testStore(t)

	// Log with nil user_id (system event)
	err := s.LogAudit(model.AuditEntry{
		ID:     "a1",
		Action: model.AuditServerConnected,
	})
	if err != nil {
		t.Fatalf("log audit: %v", err)
	}

	entries, _, err := s.ListAuditLogs(model.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].PrevHash == "" {
		t.Fatal("expected non-empty prev_hash")
	}

	// Log a second entry — hash should chain from first
	err = s.LogAudit(model.AuditEntry{
		ID:     "a2",
		Action: model.AuditServerDisconnected,
	})
	if err != nil {
		t.Fatalf("log second audit: %v", err)
	}

	entries2, _, err := s.ListAuditLogs(model.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries2) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries2))
	}
	// Entries are ordered DESC, so index 0 is the newer one
	if entries2[0].PrevHash == entries2[1].PrevHash {
		t.Fatal("expected different hashes for chained entries")
	}
}
