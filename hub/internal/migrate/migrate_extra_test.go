package migrate_test

import (
	"database/sql"
	"testing"

	"github.com/wyiu/veyport/hub/internal/migrate"
)

const testRunFmt = "run: %v"

// TestRunMigrations_SkipsAlreadyApplied verifies that already-applied migrations are skipped.
func TestRunMigrations_SkipsAlreadyApplied(t *testing.T) {
	db := testDB(t)

	// Apply once
	if err := migrate.Run(db); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Apply again - should skip all and not error
	if err := migrate.Run(db); err != nil {
		t.Fatalf("second run: %v", err)
	}

	// Verify migration records exist
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM _migrations").Scan(&count); err != nil {
		t.Fatalf("query count: %v", err)
	}
	if count == 0 {
		t.Fatal("expected migration records to exist")
	}
}

// TestRunMigrations_TablesExist verifies all expected tables are created.
func TestRunMigrations_TablesExist(t *testing.T) {
	db := testDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf(testRunFmt, err)
	}

	tables := []string{"users", "servers", "audit_logs", "permissions", "_config"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s not found: %v", table, err)
		}
	}
}

// TestRunMigrations_MigrationsTableCreatedFirst verifies _migrations table exists after run.
func TestRunMigrations_MigrationsTableExists(t *testing.T) {
	db := testDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf(testRunFmt, err)
	}

	var name string
	if err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='_migrations'").Scan(&name); err != nil {
		t.Fatalf("_migrations table not found: %v", err)
	}
}

// TestRunMigrations_AccountLockoutColumns verifies migration 021 adds the
// account-lockout columns to users with the expected defaults, and that a
// user row reads back a zero failure count and NULL timestamps.
func TestRunMigrations_AccountLockoutColumns(t *testing.T) {
	db := testDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf(testRunFmt, err)
	}

	wantColumns := map[string]bool{
		"failed_login_count":   false,
		"last_failed_login_at": false,
		"last_login_at":        false,
		"locked_until":         false,
	}

	rows, err := db.Query("PRAGMA table_info(users)")
	if err != nil {
		t.Fatalf("pragma table_info: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull int
		var dfltValue any
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		if _, ok := wantColumns[name]; ok {
			wantColumns[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate table_info: %v", err)
	}

	for col, found := range wantColumns {
		if !found {
			t.Fatalf("expected column %q on users table after migration 021", col)
		}
	}

	if _, err := db.Exec(
		`INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at)
		 VALUES ('lockout-user-1', 'lockoutuser', 'lockout@test.com', 'hash', 'viewer', datetime('now'), datetime('now'))`,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	var failedLoginCount int
	var lastFailedLoginAt, lastLoginAt, lockedUntil sql.NullString
	err = db.QueryRow(
		`SELECT failed_login_count, last_failed_login_at, last_login_at, locked_until
		 FROM users WHERE id = 'lockout-user-1'`,
	).Scan(&failedLoginCount, &lastFailedLoginAt, &lastLoginAt, &lockedUntil)
	if err != nil {
		t.Fatalf("query inserted user: %v", err)
	}
	if failedLoginCount != 0 {
		t.Fatalf("expected failed_login_count = 0, got %d", failedLoginCount)
	}
	if lastFailedLoginAt.Valid {
		t.Fatalf("expected last_failed_login_at NULL, got %q", lastFailedLoginAt.String)
	}
	if lastLoginAt.Valid {
		t.Fatalf("expected last_login_at NULL, got %q", lastLoginAt.String)
	}
	if lockedUntil.Valid {
		t.Fatalf("expected locked_until NULL, got %q", lockedUntil.String)
	}
}

// TestRunMigrations_RecordsApplied verifies migration filenames are recorded.
func TestRunMigrations_RecordsApplied(t *testing.T) {
	db := testDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf(testRunFmt, err)
	}

	rows, err := db.Query("SELECT filename FROM _migrations ORDER BY filename")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var filenames []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			t.Fatalf("scan: %v", err)
		}
		filenames = append(filenames, f)
	}

	if len(filenames) == 0 {
		t.Fatal("expected at least one migration to be recorded")
	}

	// Verify they end in .sql
	for _, f := range filenames {
		if len(f) < 4 || f[len(f)-4:] != ".sql" {
			t.Fatalf("expected .sql suffix, got: %s", f)
		}
	}
}
