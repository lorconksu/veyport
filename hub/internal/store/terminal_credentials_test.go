package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"modernc.org/sqlite"
)

func installDelayedSessionRead(t *testing.T, s *Store, prefix string, delay time.Duration) {
	t.Helper()
	name := prefix + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := sqlite.RegisterScalarFunction(name, 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		time.Sleep(delay)
		return args[0], nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"ALTER TABLE sessions RENAME TO delayed_sessions",
		"CREATE VIEW sessions AS SELECT id,user_id,kind,created_at," + name + "(last_seen_at) AS last_seen_at,expires_at,ended_at FROM delayed_sessions",
	} {
		if _, err := s.DB().Exec(query); err != nil {
			t.Fatal(err)
		}
	}
}

func expiringSessionStore(t *testing.T) (*Store, time.Time) {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "session-expiry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", PasswordHash: "h", Role: model.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := s.CreateSession(&model.Session{ID: "sid", UserID: "actor", Kind: model.SessionKindWeb, CreatedAt: expires.Add(-time.Minute), LastSeenAt: expires.Add(-time.Second), ExpiresAt: &expires}); err != nil {
		t.Fatal(err)
	}
	return s, expires
}

func TestTerminalSessionExpiryDuringFinalRead(t *testing.T) {
	s, expires := expiringSessionStore(t)
	installDelayedSessionRead(t, s, "terminal_session_read_delay", 120*time.Millisecond)
	if s.TerminalSessionLive(context.Background(), "sid", "actor", expires.Add(-60*time.Millisecond)) {
		t.Fatal("terminal authority that expired during its final read was accepted")
	}
}

func TestStepupSessionExpiryDuringFinalRead(t *testing.T) {
	s, expires := expiringSessionStore(t)
	now := expires.Add(-60 * time.Millisecond)
	digest := strings.Repeat("a", 64)
	proof, err := s.IssueStepup("actor", "sid", "security.apply", digest, now)
	if err != nil {
		t.Fatal(err)
	}
	installDelayedSessionRead(t, s, "governance_session_read_delay", 120*time.Millisecond)
	if err := s.ConsumeStepup(proof, "actor", "sid", "security.apply", digest, now); err == nil {
		t.Fatal("step-up proof was consumed after its owning session expired")
	}
}

func TestStepupSessionExpiryDuringPolicyRead(t *testing.T) {
	s, expires := expiringSessionStore(t)
	now := expires.Add(-60 * time.Millisecond)
	digest := strings.Repeat("b", 64)
	proof, err := s.IssueStepup("actor", "sid", "security.approve", digest, now)
	if err != nil {
		t.Fatal(err)
	}
	consumeErr := s.withImmediateTxAt(now, func(ctx context.Context, conn *sql.Conn, txNow time.Time) error {
		return consumeStepupWithPolicy(ctx, conn, proof, "actor", "sid", "security.approve", digest, txNow, func() lockout.Policy {
			time.Sleep(120 * time.Millisecond)
			return lockout.Defaults()
		})
	})
	if consumeErr == nil {
		t.Fatal("step-up proof was consumed after its owning session expired during policy reads")
	}
	var consumed bool
	if err := s.DB().QueryRow("SELECT consumed_at IS NOT NULL FROM stepup_proofs WHERE hash=?", SecurityDigest([]byte(proof))).Scan(&consumed); err != nil || consumed {
		t.Fatalf("expired session consumed step-up proof: consumed=%t err=%v", consumed, err)
	}
}

func TestTerminalCredentialPoolDeadlineAndIsolation(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", PasswordHash: "h", Role: model.RoleViewer}); err != nil {
		t.Fatal(err)
	}
	if !s.TerminalCredentialLive(context.Background(), "actor", 0, false) {
		t.Fatal("credential pool cannot read the same in-memory database")
	}
	s.credentialDB.SetMaxOpenConns(1)
	lease, err := s.credentialDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	var busy, queryOnly int
	if err := lease.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&busy); err != nil || busy != 0 {
		t.Fatalf("credential busy timeout=%d: %v", busy, err)
	}
	if err := lease.QueryRowContext(context.Background(), "PRAGMA query_only").Scan(&queryOnly); err != nil || queryOnly != 1 {
		t.Fatalf("credential pool is writable: %v", err)
	}
	if err := s.DB().QueryRow("PRAGMA busy_timeout").Scan(&busy); err != nil || busy != 5000 {
		t.Fatalf("writer busy timeout changed: %d %v", busy, err)
	}
	started := time.Now()
	if s.TerminalCredentialLive(context.Background(), "actor", 0, false) {
		t.Fatal("credential query succeeded without a pool lease")
	}
	if elapsed := time.Since(started); elapsed > TerminalCredentialTimeout+100*time.Millisecond {
		t.Fatalf("pool acquisition exceeded deadline: %s", elapsed)
	}
}

func TestTerminalCredentialSQLiteBusyDeadline(t *testing.T) {
	for _, journal := range []string{"WAL", "DELETE"} {
		t.Run(journal, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hub.db")
			s, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", PasswordHash: "h", Role: model.RoleViewer}); err != nil {
				t.Fatal(err)
			}
			s.db.SetMaxIdleConns(0)
			locker, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer locker.Close()
			conn, err := locker.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.ExecContext(context.Background(), "PRAGMA journal_mode="+journal); err != nil {
				t.Fatal(err)
			}
			if journal == "DELETE" {
				// Exercise a connection already initialized before contention as
				// well as WAL's cold-connection initialization under contention.
				s.credentialDB.SetMaxIdleConns(1)
				if !s.TerminalCredentialLive(context.Background(), "actor", 0, false) {
					t.Fatal("live credential refused before lock")
				}
			}
			for _, query := range []string{"PRAGMA locking_mode=EXCLUSIVE", "BEGIN EXCLUSIVE", "SELECT COUNT(*) FROM users"} {
				if _, err := conn.ExecContext(context.Background(), query); err != nil {
					t.Fatal(err)
				}
			}
			defer conn.ExecContext(context.Background(), "ROLLBACK")
			probe, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(0)")
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			var count int
			err = probe.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
			var code interface{ Code() int }
			if !errors.As(err, &code) || code.Code()&255 != 5 { // SQLITE_BUSY
				t.Fatalf("fixture did not cause a real SQLite busy read: %v", err)
			}
			started := time.Now()
			if s.TerminalCredentialLive(context.Background(), "actor", 0, false) {
				t.Fatal("storage outage retained credential authority")
			}
			if elapsed := time.Since(started); elapsed > TerminalCredentialTimeout {
				t.Fatalf("SQLite busy handling exceeded 250ms deadline: %s", elapsed)
			}
		})
	}
}
