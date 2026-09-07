package migrate_test

import (
	"database/sql"
	"embed"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/migrate"
)

const testRunFmt = "run: %v"

// lifecycleMigrationFS is a second embed of the same migrations directory,
// used only to replay individual migration files by hand (see
// applyMigrationsThrough). migrate.Run always applies every embedded
// migration file it finds in one pass — it has no cutoff parameter, and
// migrate.go is out of scope for this change — so the only honest way to
// exercise migration 022 against the schema as it looked immediately
// beforehand is to replay 001-021 ourselves (recording each in _migrations
// exactly as Run would) and then let Run finish the rest.
//
//go:embed migrations/*.sql
var lifecycleMigrationFS embed.FS

// applyMigrationsThrough replays every migration file up to and including
// cutoff (inclusive, compared lexicographically — safe because filenames
// share a fixed-width zero-padded numeric prefix), recording each in
// _migrations exactly as migrate.Run would.
func applyMigrationsThrough(t *testing.T, db *sql.DB, cutoff string) {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS _migrations (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		filename   TEXT NOT NULL UNIQUE,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		t.Fatalf("create _migrations table: %v", err)
	}

	entries, err := fs.ReadDir(lifecycleMigrationFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") || name > cutoff {
			continue
		}
		content, err := fs.ReadFile(lifecycleMigrationFS, "migrations/"+name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sqlText := string(content)
		if strings.HasPrefix(sqlText, "-- codex: no-transaction") {
			if _, err := db.Exec(sqlText); err != nil {
				t.Fatalf("exec %s: %v", name, err)
			}
		} else {
			tx, err := db.Begin()
			if err != nil {
				t.Fatalf("begin tx for %s: %v", name, err)
			}
			if _, err := tx.Exec(sqlText); err != nil {
				_ = tx.Rollback()
				t.Fatalf("exec %s: %v", name, err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatalf("commit %s: %v", name, err)
			}
		}
		if _, err := db.Exec("INSERT INTO _migrations (filename) VALUES (?)", name); err != nil {
			t.Fatalf("record %s: %v", name, err)
		}
	}
}

func seedLifecycleUser(t *testing.T, db *sql.DB, id, username, role, createdAt string, lastLoginAt *string) {
	t.Helper()
	var lastLogin any
	if lastLoginAt != nil {
		lastLogin = *lastLoginAt
	}
	if _, err := db.Exec(
		`INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at, last_login_at)
		 VALUES (?, ?, ?, 'hash', ?, ?, ?, ?)`,
		id, username, username+"@test.com", role, createdAt, createdAt, lastLogin,
	); err != nil {
		t.Fatalf("seed user %s: %v", id, err)
	}
}

func insertLifecycleAPIToken(t *testing.T, db *sql.DB, id, userID, lastUsedAt string) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, last_used_at)
		 VALUES (?, ?, 'e2e', ?, 'pfx', ?)`,
		id, userID, id+"-hash", lastUsedAt,
	); err != nil {
		t.Fatalf("insert api token %s: %v", id, err)
	}
}

func assertDormancyExempt(t *testing.T, db *sql.DB, id string, want bool) {
	t.Helper()
	var got int
	if err := db.QueryRow("SELECT dormancy_exempt FROM users WHERE id = ?", id).Scan(&got); err != nil {
		t.Fatalf("query dormancy_exempt for %s: %v", id, err)
	}
	if (got == 1) != want {
		t.Fatalf("dormancy_exempt for %s = %d, want %v", id, got, want)
	}
}

func assertLastActivity(t *testing.T, db *sql.DB, id string, want string) {
	t.Helper()
	var got sql.NullString
	if err := db.QueryRow("SELECT last_activity_at FROM users WHERE id = ?", id).Scan(&got); err != nil {
		t.Fatalf("query last_activity_at for %s: %v", id, err)
	}
	if !got.Valid || got.String != want {
		t.Fatalf("last_activity_at for %s = %+v, want %q", id, got, want)
	}
}

func assertLastActivityNull(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	var got sql.NullString
	if err := db.QueryRow("SELECT last_activity_at FROM users WHERE id = ?", id).Scan(&got); err != nil {
		t.Fatalf("query last_activity_at for %s: %v", id, err)
	}
	if got.Valid {
		t.Fatalf("expected NULL last_activity_at for %s, got %q", id, got.String)
	}
}

func strPtr(s string) *string { return &s }

// TestRunMigrations_AccountLifecycleColumns verifies migration 022 adds the
// account-lifecycle columns, backfills last_activity_at from the later of
// last_login_at and the user's latest API-token use, and marks the
// earliest-created admin as the default dormancy-exempt recovery admin.
func TestRunMigrations_AccountLifecycleColumns(t *testing.T) {
	db := testDB(t)

	// Build the pre-022 schema by replaying 001-021 ourselves (see
	// applyMigrationsThrough), so we can seed rows against the schema as it
	// existed immediately before 022 runs.
	applyMigrationsThrough(t, db, "021_account_lockout.sql")

	seedLifecycleUser(t, db, "admin-early", "admin-early", "admin", "2025-01-01 00:00:00", nil)
	seedLifecycleUser(t, db, "admin-late", "admin-late", "admin", "2025-06-01 00:00:00", nil)
	seedLifecycleUser(t, db, "viewer-a", "viewer-a", "viewer", "2025-02-01 00:00:00", strPtr("2025-03-01 00:00:00"))
	seedLifecycleUser(t, db, "viewer-b", "viewer-b", "viewer", "2025-02-01 00:00:00", nil)
	seedLifecycleUser(t, db, "viewer-c", "viewer-c", "viewer", "2025-02-01 00:00:00", nil)

	// viewer-b's only activity signal is an API token; a later token must
	// win over an earlier one, and both must beat "no login at all".
	insertLifecycleAPIToken(t, db, "token-b0", "viewer-b", "2025-01-15 00:00:00")
	insertLifecycleAPIToken(t, db, "token-b1", "viewer-b", "2025-04-01 00:00:00")

	// Now run the remaining migrations. 001-021 are already recorded above,
	// so this applies exactly 022.
	if err := migrate.Run(db); err != nil {
		t.Fatalf(testRunFmt, err)
	}

	wantColumns := map[string]bool{
		"disabled_at": false, "disabled_by": false, "reactivated_at": false,
		"dormancy_exempt": false, "last_activity_at": false,
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
			t.Fatalf("expected column %q on users table after migration 022", col)
		}
	}

	assertDormancyExempt(t, db, "admin-early", true)
	assertDormancyExempt(t, db, "admin-late", false)
	assertDormancyExempt(t, db, "viewer-a", false)
	assertDormancyExempt(t, db, "viewer-b", false)
	assertDormancyExempt(t, db, "viewer-c", false)

	assertLastActivity(t, db, "viewer-a", "2025-03-01 00:00:00")
	assertLastActivity(t, db, "viewer-b", "2025-04-01 00:00:00")
	assertLastActivityNull(t, db, "viewer-c")
}

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

// TestRunMigrations_SessionsTableAndIndexes verifies migration 023 creates
// the sessions table with its two indexes.
func TestRunMigrations_SessionsTableAndIndexes(t *testing.T) {
	db := testDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf(testRunFmt, err)
	}

	var name string
	if err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'").Scan(&name); err != nil {
		t.Fatalf("sessions table not found: %v", err)
	}

	wantIndexes := map[string]bool{
		"idx_sessions_user_id":  false,
		"idx_sessions_ended_at": false,
	}
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='sessions'")
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var idxName string
		if err := rows.Scan(&idxName); err != nil {
			t.Fatalf("scan index: %v", err)
		}
		if _, ok := wantIndexes[idxName]; ok {
			wantIndexes[idxName] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate indexes: %v", err)
	}
	for idx, found := range wantIndexes {
		if !found {
			t.Fatalf("expected index %q on sessions table after migration 023", idx)
		}
	}
}

// TestRunMigrations_SessionsKindCheckConstraint verifies the sessions table
// rejects any kind other than 'web' or 'cli'.
func TestRunMigrations_SessionsKindCheckConstraint(t *testing.T) {
	db := testDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatalf(testRunFmt, err)
	}
	seedLifecycleUser(t, db, "session-user-1", "session-user-1", "viewer", "2026-01-01 00:00:00", nil)

	for _, kind := range []string{"web", "cli"} {
		id := "sess-ok-" + kind
		if _, err := db.Exec(
			`INSERT INTO sessions (id, user_id, kind, created_at, last_seen_at) VALUES (?, ?, ?, '2026-01-01 00:00:00', '2026-01-01 00:00:00')`,
			id, "session-user-1", kind,
		); err != nil {
			t.Fatalf("insert session with valid kind %q: %v", kind, err)
		}
	}

	if _, err := db.Exec(
		`INSERT INTO sessions (id, user_id, kind, created_at, last_seen_at) VALUES ('sess-bad', ?, 'ssh', '2026-01-01 00:00:00', '2026-01-01 00:00:00')`,
		"session-user-1",
	); err == nil {
		t.Fatal("expected CHECK constraint to reject kind 'ssh'")
	}
}

// TestRunMigrations_SessionsCascadeOnUserDelete verifies a user's sessions
// are removed when the user row is deleted.
func TestRunMigrations_SessionsCascadeOnUserDelete(t *testing.T) {
	db := testDB(t)
	execSQL(t, db, "PRAGMA foreign_keys=ON")
	if err := migrate.Run(db); err != nil {
		t.Fatalf(testRunFmt, err)
	}
	seedLifecycleUser(t, db, "session-user-2", "session-user-2", "viewer", "2026-01-01 00:00:00", nil)

	if _, err := db.Exec(
		`INSERT INTO sessions (id, user_id, kind, created_at, last_seen_at) VALUES ('sess-cascade', 'session-user-2', 'web', '2026-01-01 00:00:00', '2026-01-01 00:00:00')`,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	if _, err := db.Exec("DELETE FROM users WHERE id = 'session-user-2'"); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = 'sess-cascade'").Scan(&count); err != nil {
		t.Fatalf("query sessions after user delete: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected session to be cascade-deleted, found %d rows", count)
	}
}
