package migrate_test

import (
	"database/sql"
	"testing"

	"github.com/wyiu/aerodocs/hub/internal/migrate"
	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestRunMigrations(t *testing.T) {
	db := testDB(t)

	if err := migrate.Run(db); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&name)
	if err != nil {
		t.Fatalf("users table not found: %v", err)
	}

	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'").Scan(&name)
	if err != nil {
		t.Fatalf("audit_logs table not found: %v", err)
	}

	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='_config'").Scan(&name)
	if err != nil {
		t.Fatalf("_config table not found: %v", err)
	}
}

func TestRunMigrations_Idempotent(t *testing.T) {
	db := testDB(t)

	if err := migrate.Run(db); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("second run should be idempotent: %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM _migrations").Scan(&count)
	if count != 17 {
		t.Fatalf("expected 17 migrations, got %d", count)
	}
}
