package migrate_test

import (
	"database/sql"
	"strings"
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

func TestRunMigrations_NullsOrphanedAuditUsersBeforeCascadeMigration(t *testing.T) {
	db := testDB(t)
	execSQL(t, db, "PRAGMA foreign_keys=ON")
	setupMigratedThroughNotifications(t, db)

	execSQL(t, db, "PRAGMA foreign_keys=OFF")
	execSQL(t, db, `
		INSERT INTO audit_logs (id, user_id, action, created_at)
		VALUES ('orphan-audit', 'missing-user', 'user.totp_enabled', '2026-03-23 19:18:23')
	`)
	execSQL(t, db, "PRAGMA foreign_keys=ON")

	if err := migrate.Run(db); err != nil {
		t.Fatalf("run migrations with orphan audit user: %v", err)
	}

	var userID sql.NullString
	if err := db.QueryRow("SELECT user_id FROM audit_logs WHERE id = 'orphan-audit'").Scan(&userID); err != nil {
		t.Fatalf("query migrated audit row: %v", err)
	}
	if userID.Valid {
		t.Fatalf("expected orphaned audit user_id to be nulled, got %q", userID.String)
	}

	var onDelete string
	if err := db.QueryRow("SELECT \"on_delete\" FROM pragma_foreign_key_list('audit_logs') WHERE \"from\" = 'user_id'").Scan(&onDelete); err != nil {
		t.Fatalf("query audit_logs foreign key: %v", err)
	}
	if onDelete != "SET NULL" {
		t.Fatalf("expected audit_logs.user_id ON DELETE SET NULL, got %q", onDelete)
	}
}

func execSQL(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	if _, err := db.Exec(query); err != nil {
		t.Fatalf("exec %q: %v", strings.TrimSpace(query), err)
	}
}

func setupMigratedThroughNotifications(t *testing.T, db *sql.DB) {
	t.Helper()
	execSQL(t, db, `
		CREATE TABLE _migrations (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			filename   TEXT NOT NULL UNIQUE,
			applied_at TEXT NOT NULL DEFAULT (datetime('now'))
		);
		CREATE TABLE users (
			id            TEXT PRIMARY KEY,
			username      TEXT NOT NULL UNIQUE,
			email         TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role          TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin', 'viewer')),
			totp_secret   TEXT,
			totp_enabled  INTEGER NOT NULL DEFAULT 0,
			created_at    TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
			avatar        TEXT
		);
		CREATE TABLE audit_logs (
			id         TEXT PRIMARY KEY,
			user_id    TEXT,
			action     TEXT NOT NULL,
			target     TEXT,
			detail     TEXT,
			ip_address TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
		CREATE INDEX idx_audit_logs_action ON audit_logs(action);
		CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
		CREATE TABLE _config (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		CREATE TABLE servers (
			id                 TEXT PRIMARY KEY,
			name               TEXT NOT NULL,
			hostname           TEXT,
			ip_address         TEXT,
			os                 TEXT,
			status             TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','online','offline')),
			registration_token TEXT UNIQUE,
			token_expires_at   TEXT,
			agent_version      TEXT,
			labels             TEXT DEFAULT '{}',
			last_seen_at       TEXT,
			created_at         TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
		);
		CREATE INDEX idx_servers_status ON servers (status);
		CREATE INDEX idx_servers_created_at ON servers (created_at DESC);
		CREATE INDEX idx_servers_status_created_at ON servers (status, created_at DESC);
		CREATE TABLE permissions (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			server_id  TEXT NOT NULL,
			path       TEXT NOT NULL DEFAULT '/',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
			UNIQUE(user_id, server_id, path)
		);
		CREATE INDEX idx_permissions_user_id ON permissions(user_id);
		CREATE INDEX idx_permissions_server_id ON permissions(server_id);
		CREATE TABLE IF NOT EXISTS ca_config (
			id TEXT PRIMARY KEY DEFAULT 'default',
			ca_cert BLOB NOT NULL,
			ca_key_encrypted BLOB NOT NULL,
			created_at DATETIME DEFAULT (datetime('now'))
		);
		CREATE TABLE IF NOT EXISTS notification_preferences (
			user_id    TEXT NOT NULL,
			event_type TEXT NOT NULL,
			enabled    INTEGER NOT NULL DEFAULT 1,
			PRIMARY KEY (user_id, event_type),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS notification_log (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			event_type TEXT NOT NULL,
			subject    TEXT NOT NULL,
			status     TEXT NOT NULL CHECK(status IN ('sent', 'failed')),
			error      TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_notification_log_created ON notification_log(created_at);
		CREATE INDEX IF NOT EXISTS idx_notification_log_user ON notification_log(user_id);
		INSERT INTO _migrations (filename) VALUES
			('001_create_users.sql'),
			('002_create_audit_logs.sql'),
			('003_create_config.sql'),
			('004_create_servers.sql'),
			('005_create_permissions.sql'),
			('006_add_user_avatar.sql'),
			('007_add_server_indexes.sql'),
			('008_add_ca_config.sql'),
			('009_create_notifications.sql');
	`)
}
