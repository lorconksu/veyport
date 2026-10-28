package migrate

import (
	"database/sql"
	_ "modernc.org/sqlite"
	"strings"
	"testing"
)

func TestRetentionAndIdentityUpgradeAfter033(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE _migrations(filename TEXT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sql") && entry.Name() < "034" {
			if err := applyMigration(db, entry.Name()); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, q := range []string{
		"INSERT INTO users(id,username,email,password_hash,role) VALUES('original','reuse','reuse@test','h','admin')",
		"INSERT INTO audit_logs(id,action,created_at) VALUES('offset','user.login','2026-10-26T20:00:00+02:00')",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := Run(db); err != nil {
		t.Fatal(err)
	}
	if err := Run(db); err != nil {
		t.Fatal(err)
	}
	var epoch int64
	if err := db.QueryRow("SELECT created_at_epoch FROM audit_logs WHERE id='offset'").Scan(&epoch); err != nil || epoch != 1793037600 {
		t.Fatalf("normalized instant %d %v", epoch, err)
	}
	for _, index := range []string{"idx_audit_logs_retention", "idx_local_break_glass_recoveries_audit_id"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count); err != nil || count != 1 {
			t.Fatalf("missing upgrade index %s %v", index, err)
		}
	}
	if _, err := db.Exec("DELETE FROM users WHERE id='original'"); err != nil {
		t.Fatal(err)
	}
	for _, conflict := range []string{"", "OR IGNORE", "OR REPLACE"} {
		if _, err := db.Exec("INSERT " + conflict + " INTO users(id,username,email,password_hash,role) VALUES('original','reuse','reuse@test','h','admin')"); err == nil {
			t.Fatalf("deleted immutable identity reused: %s", conflict)
		}
	}
	if _, err := db.Exec("INSERT INTO users(id,username,email,password_hash,role) VALUES('replacement','reuse','reuse@test','h','admin')"); err != nil {
		t.Fatal(err)
	}
}
