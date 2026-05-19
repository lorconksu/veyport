package store

import (
	"database/sql"
	"fmt"
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

func New(dbPath string) (*Store, error) {
	if dbPath == ":memory:" {
		dbPath = fmt.Sprintf("file:veyport-%d?mode=memory&cache=shared", time.Now().UnixNano())
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// SQLite performance and safety PRAGMAs
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA synchronous=NORMAL",  // safe with WAL; reduces fsync from every write to checkpoint
		"PRAGMA busy_timeout=5000",   // wait up to 5s on lock contention instead of immediate BUSY error
		"PRAGMA cache_size=-20000",   // 20MB page cache (negative = KB)
		"PRAGMA mmap_size=268435456", // 256MB memory-mapped I/O for read performance
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("exec %s: %w", p, err)
		}
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
