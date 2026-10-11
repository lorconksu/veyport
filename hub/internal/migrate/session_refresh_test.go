package migrate

import (
	"database/sql"
	"io/fs"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSessionRefreshMigrationPreservesLegacySessionAndRevocationGeneration(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE _migrations(filename TEXT PRIMARY KEY);
		CREATE TABLE users(id TEXT PRIMARY KEY, token_generation INTEGER NOT NULL);
		INSERT INTO users VALUES('operator',7)`); err != nil {
		t.Fatal(err)
	}
	legacy, err := fs.ReadFile(migrationFS, "migrations/023_create_sessions.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(legacy)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions(id,user_id,kind,created_at,last_seen_at,expires_at)
		VALUES('legacy','operator','cli','2026-10-11 08:00:00','2026-10-11 08:30:00','2026-10-11 20:00:00')`); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sql") && entry.Name() != "028_session_refresh_rotation.sql" {
			if _, err := db.Exec("INSERT INTO _migrations(filename) VALUES(?)", entry.Name()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := Run(db); err != nil {
		t.Fatal(err)
	}
	var digest, expiry, seen string
	if err := db.QueryRow("SELECT refresh_token_sha256,expires_at,last_seen_at FROM sessions WHERE id='legacy'").Scan(&digest, &expiry, &seen); err != nil {
		t.Fatal(err)
	}
	if digest != "" || expiry != "2026-10-11 20:00:00" || seen != "2026-10-11 08:30:00" {
		t.Fatal("migration changed the existing session's authority or lifetime")
	}
	var generation int
	if err := db.QueryRow("SELECT token_generation FROM users WHERE id='operator'").Scan(&generation); err != nil || generation != 7 {
		t.Fatalf("generation=%d err=%v", generation, err)
	}
	if _, err := db.Exec("UPDATE sessions SET refresh_token_sha256='invalid' WHERE id='legacy'"); err == nil {
		t.Fatal("migration accepted an invalid digest")
	}
	if err := Run(db); err != nil {
		t.Fatal(err)
	}
}
