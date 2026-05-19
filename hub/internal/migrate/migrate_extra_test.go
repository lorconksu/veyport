package migrate_test

import (
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
