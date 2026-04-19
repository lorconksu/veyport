package store_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/wyiu/aerodocs/hub/internal/model"
)

const (
	testListFmt        = "list: %v"
	testExpectedTotal1 = "expected total 1, got %d"
)

func TestLogAndListAudit(t *testing.T) {
	s := testStore(t)

	// Create user first to satisfy FK constraint on audit_logs.user_id
	if err := s.CreateUser(&model.User{
		ID: "user-1", Username: "testuser", Email: "test@test.com",
		PasswordHash: "h", Role: model.RoleViewer,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	userID := "user-1"
	ip := "127.0.0.1"
	if err := s.LogAudit(model.AuditEntry{
		ID:        "a1",
		UserID:    &userID,
		Action:    model.AuditUserLogin,
		IPAddress: &ip,
	}); err != nil {
		t.Fatalf("log audit: %v", err)
	}

	entries, total, err := s.ListAuditLogs(model.AuditFilter{Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if total != 1 {
		t.Fatalf(testExpectedTotal1, total)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Action != model.AuditUserLogin {
		t.Fatalf("expected action %q, got %q", model.AuditUserLogin, entries[0].Action)
	}
}

func TestListAuditWithDateRange(t *testing.T) {
	s := testStore(t)

	// Insert entries directly with controlled timestamps
	db := s.DB()
	db.Exec(`INSERT INTO audit_logs (id, action, created_at) VALUES ('a1', 'user.login', '2026-03-01 10:00:00')`)
	db.Exec(`INSERT INTO audit_logs (id, action, created_at) VALUES ('a2', 'user.login', '2026-03-15 10:00:00')`)
	db.Exec(`INSERT INTO audit_logs (id, action, created_at) VALUES ('a3', 'user.login', '2026-03-25 10:00:00')`)

	// Filter from March 10 to March 20
	from := "2026-03-10T00:00:00Z"
	to := "2026-03-20T23:59:59Z"
	entries, total, err := s.ListAuditLogs(model.AuditFilter{
		From:  &from,
		To:    &to,
		Limit: 10,
	})
	if err != nil {
		t.Fatalf(testListFmt, err)
	}
	if total != 1 {
		t.Fatalf(testExpectedTotal1, total)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ID != "a2" {
		t.Fatalf("expected entry a2, got %s", entries[0].ID)
	}
}

func TestListAuditWithFromOnly(t *testing.T) {
	s := testStore(t)

	db := s.DB()
	db.Exec(`INSERT INTO audit_logs (id, action, created_at) VALUES ('a1', 'user.login', '2026-03-01 10:00:00')`)
	db.Exec(`INSERT INTO audit_logs (id, action, created_at) VALUES ('a2', 'user.login', '2026-03-15 10:00:00')`)

	from := "2026-03-10T00:00:00Z"
	entries, total, err := s.ListAuditLogs(model.AuditFilter{
		From:  &from,
		Limit: 10,
	})
	if err != nil {
		t.Fatalf(testListFmt, err)
	}
	if total != 1 {
		t.Fatalf(testExpectedTotal1, total)
	}
	if len(entries) != 1 || entries[0].ID != "a2" {
		t.Fatalf("expected entry a2")
	}
}

func TestListAuditWithToOnly(t *testing.T) {
	s := testStore(t)

	db := s.DB()
	db.Exec(`INSERT INTO audit_logs (id, action, created_at) VALUES ('a1', 'user.login', '2026-03-01 10:00:00')`)
	db.Exec(`INSERT INTO audit_logs (id, action, created_at) VALUES ('a2', 'user.login', '2026-03-15 10:00:00')`)

	to := "2026-03-10T23:59:59Z"
	entries, total, err := s.ListAuditLogs(model.AuditFilter{
		To:    &to,
		Limit: 10,
	})
	if err != nil {
		t.Fatalf(testListFmt, err)
	}
	if total != 1 {
		t.Fatalf(testExpectedTotal1, total)
	}
	if len(entries) != 1 || entries[0].ID != "a1" {
		t.Fatalf("expected entry a1")
	}
}

func TestListAuditWithUserIDAndOffset(t *testing.T) {
	s := testStore(t)

	if err := s.CreateUser(&model.User{
		ID: "u1", Username: "audituser", Email: "a@b.com",
		PasswordHash: "h", Role: model.RoleViewer,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	uid := "u1"
	s.LogAudit(model.AuditEntry{ID: "a1", UserID: &uid, Action: model.AuditUserLogin})
	s.LogAudit(model.AuditEntry{ID: "a2", UserID: &uid, Action: model.AuditUserLogin})
	s.LogAudit(model.AuditEntry{ID: "a3", Action: model.AuditUserLogin}) // different user

	entries, total, err := s.ListAuditLogs(model.AuditFilter{
		UserID: &uid,
		Limit:  1,
		Offset: 1,
	})
	if err != nil {
		t.Fatalf(testListFmt, err)
	}
	if total != 2 {
		t.Fatalf("expected total 2 for user filter, got %d", total)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry with offset, got %d", len(entries))
	}
}

func TestListAuditWithFilter(t *testing.T) {
	s := testStore(t)

	s.LogAudit(model.AuditEntry{ID: "a1", Action: model.AuditUserLogin})
	s.LogAudit(model.AuditEntry{ID: "a2", Action: model.AuditUserLoginFailed})
	s.LogAudit(model.AuditEntry{ID: "a3", Action: model.AuditUserLogin})

	action := model.AuditUserLogin
	entries, total, err := s.ListAuditLogs(model.AuditFilter{
		Action: &action,
		Limit:  10,
	})
	if err != nil {
		t.Fatalf(testListFmt, err)
	}
	if total != 2 {
		t.Fatalf("expected total 2, got %d", total)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestLogAuditConcurrent(t *testing.T) {
	s := testStore(t)

	const total = 25

	var wg sync.WaitGroup
	errCh := make(chan error, total)
	for i := range total {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errCh <- s.LogAudit(model.AuditEntry{
				ID:     fmt.Sprintf("audit-%02d", i),
				Action: model.AuditUserLogin,
			})
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent log audit failed: %v", err)
		}
	}

	entries, totalRows, err := s.ListAuditLogs(model.AuditFilter{Limit: total})
	if err != nil {
		t.Fatalf("list audit after concurrent insert: %v", err)
	}
	if totalRows != total {
		t.Fatalf("expected %d audit rows, got %d", total, totalRows)
	}
	if len(entries) != total {
		t.Fatalf("expected %d returned rows, got %d", total, len(entries))
	}
	for _, entry := range entries {
		if entry.PrevHash == "" {
			t.Fatalf("expected prev_hash to be populated for entry %s", entry.ID)
		}
	}
}

func TestLogAudit_GeneratesUniqueIDWhenMissing(t *testing.T) {
	s := testStore(t)

	if err := s.LogAudit(model.AuditEntry{Action: model.AuditServerConnected}); err != nil {
		t.Fatalf("first log audit without id: %v", err)
	}
	if err := s.LogAudit(model.AuditEntry{Action: model.AuditServerDisconnected}); err != nil {
		t.Fatalf("second log audit without id: %v", err)
	}

	entries, total, err := s.ListAuditLogs(model.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected total 2, got %d", total)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 returned entries, got %d", len(entries))
	}
	if entries[0].ID == "" || entries[1].ID == "" {
		t.Fatal("expected generated audit ids to be non-empty")
	}
	if entries[0].ID == entries[1].ID {
		t.Fatalf("expected generated audit ids to be unique, got %q", entries[0].ID)
	}
}
