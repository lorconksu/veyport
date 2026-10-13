package migrate

import (
	"database/sql"
	"io/fs"
	_ "modernc.org/sqlite"
	"testing"
)

func TestSQLiteGovernanceIdentityBackfillAndNewUserTrigger(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("CREATE TABLE _migrations(filename TEXT)"); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() < "025_security_governance.sql" {
			if err = applyMigration(db, e.Name()); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, v := range []struct{ id, provider, external string }{{"old-local", "local", ""}, {"old-ldap", "ldap", "ldap-old"}} {
		if _, err = db.Exec("INSERT INTO users(id,username,email,password_hash,role,auth_provider,external_id) VALUES(?,?,?,'synthetic','viewer',?,?)", v.id, v.id, v.id+"@invalid", v.provider, v.external); err != nil {
			t.Fatal(err)
		}
	}
	if err = applyMigration(db, "025_security_governance.sql"); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ id, provider, external string }{{"new-local", "local", ""}, {"new-ldap", "ldap", "ldap-new"}} {
		if _, err = db.Exec("INSERT INTO users(id,username,email,password_hash,role,auth_provider,external_id) VALUES(?,?,?,'synthetic','viewer',?,?)", v.id, v.id, v.id+"@invalid", v.provider, v.external); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []struct{ id, subject string }{{"old-local", "old-local"}, {"old-ldap", "ldap-old"}, {"new-local", "new-local"}, {"new-ldap", "ldap-new"}} {
		var got string
		if err = db.QueryRow("SELECT subject FROM security_identity_links WHERE user_id=?", v.id).Scan(&got); err != nil || got != v.subject {
			t.Fatalf("%s: %q %v", v.id, got, err)
		}
	}
	var empty, notnull int
	if err = db.QueryRow("SELECT '' = '', '' IS NULL").Scan(&empty, &notnull); err != nil || empty != 1 || notnull != 0 {
		t.Fatalf("SQLite comparison: %d %d %v", empty, notnull, err)
	}
	if _, err = db.Exec("INSERT INTO users(id,username,email,password_hash,role,external_id) VALUES('null','null','null@invalid','synthetic','viewer',NULL)"); err == nil {
		t.Fatal("schema unexpectedly accepted NULL external_id")
	}
}
