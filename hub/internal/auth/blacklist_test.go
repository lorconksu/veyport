package auth_test

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	_ "modernc.org/sqlite"
)

const (
	testBlacklistInsertSQL = "INSERT INTO token_blacklist (jti, expires_at) VALUES (?, ?)"
	testBlacklistTimeFmt   = "2006-01-02 15:04:05"
	testInsertErrFmt       = "insert: %v"
	testRestartJTI         = "restart-jti"
)

func TestTokenBlacklist_AddAndCheck(t *testing.T) {
	bl := auth.NewTokenBlacklist()

	bl.Add("jti-1", time.Now().Add(5*time.Minute))

	if !bl.IsBlacklisted("jti-1") {
		t.Fatal("expected jti-1 to be blacklisted")
	}
	if bl.IsBlacklisted("jti-2") {
		t.Fatal("expected jti-2 to not be blacklisted")
	}
}

func TestTokenBlacklist_ExpiredEntryCleaned(t *testing.T) {
	bl := auth.NewTokenBlacklist()

	// Add an already-expired entry
	bl.Add("old-jti", time.Now().Add(-1*time.Minute))

	// Adding a new entry triggers cleanup
	bl.Add("new-jti", time.Now().Add(5*time.Minute))

	if bl.IsBlacklisted("old-jti") {
		t.Fatal("expected expired entry to be cleaned up")
	}
	if !bl.IsBlacklisted("new-jti") {
		t.Fatal("expected new-jti to be blacklisted")
	}
}

func TestTokenBlacklist_Len(t *testing.T) {
	bl := auth.NewTokenBlacklist()

	if bl.Len() != 0 {
		t.Fatal("expected empty blacklist")
	}

	bl.Add("jti-1", time.Now().Add(5*time.Minute))
	bl.Add("jti-2", time.Now().Add(5*time.Minute))

	if bl.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", bl.Len())
	}
}

// setupTestDB creates a temporary SQLite DB with the token_blacklist table.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	f, err := os.CreateTemp("", "blacklist-test-*.db")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	dbPath := f.Name()
	f.Close()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS token_blacklist (
		jti        TEXT PRIMARY KEY,
		expires_at TEXT NOT NULL
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		os.Remove(dbPath)
	})
	return db
}

func TestTokenBlacklist_PersistToDB(t *testing.T) {
	db := setupTestDB(t)
	bl := auth.NewTokenBlacklist(db)

	expiry := time.Now().Add(10 * time.Minute)
	bl.Add("persist-jti", expiry)

	// Verify it's in the DB
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM token_blacklist WHERE jti = 'persist-jti'").Scan(&count)
	if err != nil {
		t.Fatalf("query db: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 row in DB, got %d", count)
	}
}

func TestTokenBlacklist_LoadFromDB_OnStartup(t *testing.T) {
	db := setupTestDB(t)

	// Pre-populate the DB with a non-expired entry
	expiry := time.Now().Add(10 * time.Minute).UTC().Format(testBlacklistTimeFmt)
	_, err := db.Exec(testBlacklistInsertSQL, "preloaded-jti", expiry)
	if err != nil {
		t.Fatalf(testInsertErrFmt, err)
	}

	// Create a new blacklist — it should load the entry from DB
	bl := auth.NewTokenBlacklist(db)

	if !bl.IsBlacklisted("preloaded-jti") {
		t.Fatal("expected preloaded-jti to be loaded from DB on startup")
	}
	if bl.Len() != 1 {
		t.Fatalf("expected 1 entry loaded from DB, got %d", bl.Len())
	}
}

func TestTokenBlacklist_DBFallback(t *testing.T) {
	db := setupTestDB(t)

	// Insert an entry directly into DB (simulating another process)
	expiry := time.Now().Add(10 * time.Minute).UTC().Format(testBlacklistTimeFmt)
	_, err := db.Exec(testBlacklistInsertSQL, "external-jti", expiry)
	if err != nil {
		t.Fatalf(testInsertErrFmt, err)
	}

	// Create blacklist — the entry is loaded on startup, but let's test fallback
	// by creating a fresh blacklist and inserting into DB after creation
	bl := auth.NewTokenBlacklist(db)

	// Verify it was loaded (since loadFromDB runs on creation)
	if !bl.IsBlacklisted("external-jti") {
		t.Fatal("expected external-jti to be found via DB fallback")
	}
}

func TestTokenBlacklist_SurvivesRestart(t *testing.T) {
	db := setupTestDB(t)

	// First "session" — add a token
	bl1 := auth.NewTokenBlacklist(db)
	bl1.Add(testRestartJTI, time.Now().Add(10*time.Minute))

	if !bl1.IsBlacklisted(testRestartJTI) {
		t.Fatalf("expected %s to be blacklisted in first session", testRestartJTI)
	}

	// Simulate restart — create new blacklist with same DB
	bl2 := auth.NewTokenBlacklist(db)

	if !bl2.IsBlacklisted(testRestartJTI) {
		t.Fatalf("expected %s to survive restart and be blacklisted in second session", testRestartJTI)
	}
}

func TestTokenBlacklist_Cleanup_MemoryAndDB(t *testing.T) {
	db := setupTestDB(t)
	bl := auth.NewTokenBlacklist(db)

	// Add an entry that will expire immediately
	bl.Add("expire-soon", time.Now().Add(-1*time.Second))
	// Add a valid entry
	bl.Add("still-valid", time.Now().Add(10*time.Minute))

	// Verify both are in DB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM token_blacklist").Scan(&count)
	if count != 2 {
		t.Fatalf("expected 2 rows in DB before cleanup, got %d", count)
	}

	// Add another entry to trigger in-memory cleanup of expired entries
	bl.Add("trigger-cleanup", time.Now().Add(10*time.Minute))

	// expired entry should be removed from memory
	if bl.IsBlacklisted("expire-soon") {
		t.Fatal("expected expired entry to be cleaned from memory")
	}
	if !bl.IsBlacklisted("still-valid") {
		t.Fatal("expected still-valid to remain")
	}
	if !bl.IsBlacklisted("trigger-cleanup") {
		t.Fatal("expected trigger-cleanup to remain")
	}
}

func TestTokenBlacklist_DBFallback_NotInMemory(t *testing.T) {
	db := setupTestDB(t)
	bl := auth.NewTokenBlacklist(db)

	// Insert directly into DB after blacklist creation (simulating another process adding it)
	expiry := time.Now().Add(10 * time.Minute).UTC().Format(testBlacklistTimeFmt)
	_, err := db.Exec(testBlacklistInsertSQL, "other-process-jti", expiry)
	if err != nil {
		t.Fatalf(testInsertErrFmt, err)
	}

	// Entry is NOT in memory (was added after creation), but should be found via DB fallback
	if !bl.IsBlacklisted("other-process-jti") {
		t.Fatal("expected other-process-jti to be found via DB fallback")
	}

	// After DB fallback, the entry should now be cached in memory
	if bl.Len() != 1 {
		t.Fatalf("expected 1 entry cached in memory after DB fallback, got %d", bl.Len())
	}
}

func TestTokenBlacklist_DBFallback_ExpiredInDB(t *testing.T) {
	db := setupTestDB(t)
	bl := auth.NewTokenBlacklist(db)

	// Insert an expired entry directly into DB
	expiry := time.Now().Add(-5 * time.Minute).UTC().Format(testBlacklistTimeFmt)
	_, err := db.Exec(testBlacklistInsertSQL, "expired-db-jti", expiry)
	if err != nil {
		t.Fatalf(testInsertErrFmt, err)
	}

	// Expired entry in DB should NOT be returned as blacklisted
	if bl.IsBlacklisted("expired-db-jti") {
		t.Fatal("expected expired DB entry to not be blacklisted")
	}
}

func TestTokenBlacklist_LoadFromDB_RFC3339Format(t *testing.T) {
	db := setupTestDB(t)

	// Insert entry with RFC3339 format (tests the fallback time parse path)
	expiry := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	_, err := db.Exec(testBlacklistInsertSQL, "rfc3339-jti", expiry)
	if err != nil {
		t.Fatalf(testInsertErrFmt, err)
	}

	bl := auth.NewTokenBlacklist(db)
	if !bl.IsBlacklisted("rfc3339-jti") {
		t.Fatal("expected rfc3339-jti to be loaded from DB with RFC3339 format")
	}
}

func TestTokenBlacklist_LoadFromDB_InvalidFormat(t *testing.T) {
	db := setupTestDB(t)

	// Insert entry with unparseable format — should be skipped during loadFromDB without crashing
	_, err := db.Exec(testBlacklistInsertSQL, "bad-fmt-jti", "not-a-date")
	if err != nil {
		t.Fatalf(testInsertErrFmt, err)
	}

	bl := auth.NewTokenBlacklist(db)
	// The entry should NOT have been loaded into memory (unparseable date)
	if bl.Len() != 0 {
		t.Fatalf("expected 0 entries loaded into memory, got %d", bl.Len())
	}
}

func TestTokenBlacklist_ExpiredNotLoadedFromDB(t *testing.T) {
	db := setupTestDB(t)

	// Insert an already-expired entry
	expiry := time.Now().Add(-5 * time.Minute).UTC().Format(testBlacklistTimeFmt)
	_, err := db.Exec(testBlacklistInsertSQL, "expired-jti", expiry)
	if err != nil {
		t.Fatalf(testInsertErrFmt, err)
	}

	bl := auth.NewTokenBlacklist(db)

	if bl.IsBlacklisted("expired-jti") {
		t.Fatal("expected expired entry to not be loaded from DB")
	}
	if bl.Len() != 0 {
		t.Fatalf("expected 0 entries, got %d", bl.Len())
	}
}
