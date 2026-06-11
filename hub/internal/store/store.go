package store

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wyiu/veyport/hub/internal/migrate"
	"github.com/wyiu/veyport/hub/internal/model"
	_ "modernc.org/sqlite" // registers the SQLite driver
)

type Store struct {
	db *sql.DB

	auditStateMu    sync.Mutex
	auditDegraded   bool
	onAuditFailure  func(model.AuditHealth)
	onAuditRecovery func(model.AuditHealth)
}

// connectionPragmas are applied to every pooled connection via the
// modernc.org/sqlite DSN ?_pragma=... form. foreign_keys is per-connection
// in SQLite, so it MUST come in through the DSN to apply to all pool members.
var connectionPragmas = []string{
	"foreign_keys(1)",
	"synchronous(NORMAL)",
	"busy_timeout(5000)",
	"cache_size(-20000)",
	"mmap_size(268435456)",
}

func appendConnectionPragmas(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	parts := make([]string, 0, len(connectionPragmas))
	for _, p := range connectionPragmas {
		parts = append(parts, "_pragma="+p)
	}
	return dsn + sep + strings.Join(parts, "&")
}

func New(dbPath string) (*Store, error) {
	if dbPath == ":memory:" {
		dbPath = fmt.Sprintf("file:veyport-%d?mode=memory&cache=shared", time.Now().UnixNano())
	} else if !strings.HasPrefix(dbPath, "file:") {
		dbPath = "file:" + dbPath
	}
	dbPath = appendConnectionPragmas(dbPath)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// journal_mode is database-level (persistent in the DB header), so a
	// single Exec is sufficient. It cannot go in the DSN pragma list
	// reliably because some pooled connections may run before WAL is set.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("exec PRAGMA journal_mode=WAL: %w", err)
	}

	// Run migrations
	if err := migrate.Run(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	st := &Store{db: db}
	if health, err := st.GetAuditHealth(); err == nil {
		st.auditDegraded = health.Degraded
	}
	return st, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) SetAuditObservers(onFailure func(model.AuditHealth), onRecovery func(model.AuditHealth)) {
	s.auditStateMu.Lock()
	defer s.auditStateMu.Unlock()
	s.onAuditFailure = onFailure
	s.onAuditRecovery = onRecovery
}
