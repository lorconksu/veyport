package integration

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// This constructs the actual schema before025, including existing principals,
// session/API credentials and audit history, then exercises the automatic upgrade.
func TestSecurityGovernanceMigrationPreservesStandardInstallation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE _migrations(id INTEGER PRIMARY KEY AUTOINCREMENT,filename TEXT NOT NULL UNIQUE,applied_at TEXT NOT NULL DEFAULT (datetime('now')))"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("../migrate/migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") || entry.Name() >= "025" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("../migrate/migrations", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(string(raw)); err != nil {
			t.Fatalf("legacy migration %s: %v", entry.Name(), err)
		}
		if _, err = db.Exec("INSERT INTO _migrations(filename) VALUES(?)", entry.Name()); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		id, role, provider string
		disabled           any
	}{{"local-admin", "admin", "local", nil}, {"ldap-auditor", "auditor", "ldap", nil}, {"disabled-viewer", "viewer", "local", "2026-10-10 00:00:00"}} {
		if _, err = db.Exec("INSERT INTO users(id,username,email,password_hash,role,auth_provider,external_id,totp_enabled,totp_secret,disabled_at) VALUES(?,?,?,?,?,?,?,?,?,?)", row.id, row.id, row.id+"@test.invalid", "opaque-hash", row.role, row.provider, row.id, 1, "opaque-secret", row.disabled); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec("INSERT INTO audit_logs(id,user_id,action,detail) VALUES('existing-history','local-admin','auth.login','metadata-only')"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO sessions(id,user_id,kind,ip,user_agent,created_at,last_seen_at) VALUES('existing-session','local-admin','web','192.0.2.1','test',datetime('now'),datetime('now'))"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO api_tokens(id,user_id,name,token_hash,token_prefix) VALUES('existing-api-token','local-admin','automation','opaque-token-hash','adt_prefix')"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	st, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service := authorization.New(st)
	for id, role := range map[string]model.Role{"local-admin": model.RoleAdmin, "ldap-auditor": model.RoleAuditor, "disabled-viewer": model.RoleViewer} {
		u, err := st.GetUserByID(id)
		if err != nil || u.Role != role {
			t.Fatalf("user changed %s: %+v %v", id, u, err)
		}
		roles, err := st.UserRoles(id)
		if err != nil || len(roles) != 1 || roles[0] != role {
			t.Fatalf("legacy role assignment changed: %v %v", roles, err)
		}
	}
	admin, err := service.Effective("local-admin")
	if err != nil || !admin.Can("operations.admin") || admin.Can("security.approve") {
		t.Fatalf("admin inherited security authority %+v %v", admin, err)
	}
	auditor, err := service.Effective("ldap-auditor")
	if err != nil || !auditor.Can("audit.read") {
		t.Fatalf("auditor lost access %+v %v", auditor, err)
	}
	if _, err := service.Effective("disabled-viewer"); err == nil {
		t.Fatal("disabled user gained access")
	}
	policy, err := service.PolicyForExecution("local-admin", "node")
	if err != nil || policy.Enhanced || policy.Version != 1 {
		t.Fatalf("Standard changed: %+v %v", policy, err)
	}
	for _, table := range []string{"audit_logs", "sessions", "api_tokens"} {
		var count int
		if err := st.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("existing %s lost: %d %v", table, count, err)
		}
	}
}
