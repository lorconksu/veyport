package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/model"
)

func (s *Store) LogAudit(entry model.AuditEntry) (err error) {
	entry = normalizeAuditEntry(entry)
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		err = fmt.Errorf("acquire connection: %w", err)
		s.noteAuditFailure(err)
		return err
	}

	// Use BEGIN IMMEDIATE to acquire a write lock upfront, preventing two
	// concurrent goroutines from reading the same prev_hash before inserting.
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		err = fmt.Errorf("begin immediate: %w", err)
		_ = conn.Close()
		s.noteAuditFailure(err)
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
		_ = conn.Close()
		if err != nil {
			s.noteAuditFailure(err)
			return
		}
		s.noteAuditSuccess()
	}()

	// Compute integrity hash chain: SHA-256(prev_hash + current entry fields)
	var prevHash string
	err = conn.QueryRowContext(ctx, "SELECT prev_hash FROM audit_logs ORDER BY rowid DESC LIMIT 1").Scan(&prevHash)
	if err != nil && err != sql.ErrNoRows {
		err = fmt.Errorf("query previous audit hash: %w", err)
		return err
	}

	hashInput := fmt.Sprintf("%s|%s|%v|%s|%v|%v|%v|%s|%s|%v|%v",
		prevHash, entry.ID, entry.UserID, entry.Action, entry.Target, entry.Detail, entry.IPAddress,
		entry.Outcome, entry.ActorType, entry.CorrelationID, entry.ResourceType)
	hash := sha256.Sum256([]byte(hashInput))
	entry.PrevHash = fmt.Sprintf("%x", hash[:])

	_, err = conn.ExecContext(
		ctx,
		`INSERT INTO audit_logs (
			id, user_id, action, target, detail, ip_address, outcome, actor_type,
			correlation_id, resource_type, prev_hash
		)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.UserID, entry.Action, entry.Target, entry.Detail, entry.IPAddress,
		entry.Outcome, entry.ActorType, entry.CorrelationID, entry.ResourceType, entry.PrevHash,
	)
	if err != nil {
		err = fmt.Errorf("log audit: %w", err)
		return err
	}

	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		err = fmt.Errorf("commit audit: %w", err)
		return err
	}
	committed = true
	return nil
}

func (s *Store) ListAuditLogs(filter model.AuditFilter) ([]model.AuditEntry, int, error) {
	qb := newQueryBuilder(`SELECT id, user_id, action, target, detail, ip_address, outcome, actor_type,
		correlation_id, resource_type, prev_hash, created_at FROM audit_logs`)

	if filter.UserID != nil {
		qb.Where("user_id = ?", *filter.UserID)
	}
	if filter.Action != nil {
		qb.Where("action = ?", *filter.Action)
	}
	if filter.Outcome != nil {
		qb.Where("outcome = ?", *filter.Outcome)
	}
	if filter.ActorType != nil {
		qb.Where("actor_type = ?", *filter.ActorType)
	}
	if filter.CorrelationID != nil {
		qb.Where("correlation_id = ?", *filter.CorrelationID)
	}
	if filter.ResourceType != nil {
		qb.Where("resource_type = ?", *filter.ResourceType)
	}
	if filter.From != nil {
		qb.Where("created_at >= ?", *filter.From)
	}
	if filter.To != nil {
		qb.Where("created_at <= ?", *filter.To)
	}

	// Get total count
	var total int
	countQuery, countArgs := qb.CountQuery("audit_logs")
	if err := s.db.QueryRow(countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}

	// Get paginated results
	qb.OrderBy("created_at DESC")
	if filter.Limit > 0 {
		qb.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		qb.Offset(filter.Offset)
	}
	query, args := qb.Build()

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit logs: %w", err)
	}
	defer rows.Close()

	entries, err := scanAuditRows(rows)
	if err != nil {
		return nil, 0, err
	}
	return entries, total, rows.Err()
}

// scanAuditRows scans all audit log rows into a slice.
func scanAuditRows(rows interface {
	Next() bool
	Scan(...interface{}) error
	Err() error
}) ([]model.AuditEntry, error) {
	var entries []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		var createdAt string
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.Target, &e.Detail, &e.IPAddress,
			&e.Outcome, &e.ActorType, &e.CorrelationID, &e.ResourceType, &e.PrevHash, &createdAt); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		e.CreatedAt, _ = time.Parse(sqliteTimeFormat, createdAt)
		entries = append(entries, e)
	}
	return entries, nil
}

func normalizeAuditEntry(entry model.AuditEntry) model.AuditEntry {
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	if entry.Outcome == "" {
		if strings.HasSuffix(entry.Action, "_failed") {
			entry.Outcome = model.AuditOutcomeFailure
		} else {
			entry.Outcome = model.AuditOutcomeSuccess
		}
	}
	if entry.ActorType == "" {
		switch {
		case entry.UserID != nil:
			entry.ActorType = model.AuditActorTypeUser
		case strings.HasPrefix(entry.Action, "server.register") || strings.HasPrefix(entry.Action, "server.registration"):
			entry.ActorType = model.AuditActorTypeDevice
		default:
			entry.ActorType = model.AuditActorTypeSystem
		}
	}
	if entry.ResourceType == nil {
		resourceType := deriveAuditResourceType(entry.Action)
		entry.ResourceType = &resourceType
	}
	return entry
}

func deriveAuditResourceType(action string) string {
	switch {
	case strings.HasPrefix(action, "user."):
		return "user"
	case strings.HasPrefix(action, "server."):
		return "server"
	case strings.HasPrefix(action, "file."):
		return "file"
	case strings.HasPrefix(action, "path."):
		return "path"
	case strings.HasPrefix(action, "log."):
		return "log"
	case strings.HasPrefix(action, "audit."):
		return "audit"
	default:
		return "system"
	}
}

func (s *Store) DeleteAuditLogsBefore(cutoff string) (int, error) {
	result, err := s.db.Exec(`DELETE FROM audit_logs WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete audit logs before cutoff: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete audit logs affected rows: %w", err)
	}
	return int(rows), nil
}
