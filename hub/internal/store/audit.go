package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
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

	if err = logAuditConn(ctx, conn, entry); err != nil {
		return err
	}

	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		err = fmt.Errorf("commit audit: %w", err)
		return err
	}
	committed = true
	return nil
}

// logAuditConn appends to the integrity chain within an existing write transaction.
func logAuditConn(ctx context.Context, conn *sql.Conn, entry model.AuditEntry) error {
	entry = normalizeAuditEntry(entry)
	// Compute integrity hash chain: SHA-256(prev_hash + current entry fields)
	var prevHash string
	err := conn.QueryRowContext(ctx, "SELECT prev_hash FROM audit_logs ORDER BY rowid DESC LIMIT 1").Scan(&prevHash)
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
	case strings.HasPrefix(action, "ssh."):
		return "ssh"
	default:
		return "system"
	}
}

const auditRetentionBatch = 256
const auditRetentionBatches = 4
const auditRetentionRewindCalls = 8

// DeleteAuditLogsBefore scans at most 1024 indexed candidates and releases the
// writer after every 256 rows. Repeated calls resume past pinned provenance;
// reaching the end resets the cursor for the next sweep. Every eighth call
// gives one batch to an independent forward-moving rescan, so provenance that
// became deletable is revisited without resetting or starving the main sweep.
// Invalid timestamps are retained. A concurrent call on this Store yields to
// the current sweep.
func (s *Store) DeleteAuditLogsBefore(cutoff string) (int, error) {
	before, err := auditInstant(cutoff)
	if err != nil {
		return 0, fmt.Errorf("invalid audit cutoff: %w", err)
	}
	if !s.auditRetentionMu.TryLock() {
		return 0, nil
	}
	defer s.auditRetentionMu.Unlock()
	previous, previousErr := auditInstant(s.auditRetentionCutoff)
	if previousErr != nil || before.Before(previous) {
		s.auditRetentionEpoch, s.auditRetentionID = -1<<63, ""
		s.auditRevisitEpoch, s.auditRevisitID = -1<<63, ""
		s.auditRetentionCalls = 0
	}
	s.auditRetentionCutoff = cutoff
	s.auditRetentionCalls++
	total := 0
	scan := func(startEpoch int64, startID string) (int64, string, int, error) {
		count := 0
		epoch, id := startEpoch, startID
		err := s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
			rows, err := conn.QueryContext(ctx, auditRetentionCandidates, epoch, id, before.Unix()+1, auditRetentionBatch)
			if err != nil {
				return err
			}
			type candidate struct {
				id, stamp string
				epoch     int64
			}
			candidates := []candidate{}
			for rows.Next() {
				var c candidate
				if err := rows.Scan(&c.id, &c.stamp, &c.epoch); err != nil {
					rows.Close()
					return err
				}
				candidates = append(candidates, c)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			count = len(candidates)
			for _, c := range candidates {
				epoch, id = c.epoch, c.id
				instant, err := auditInstant(c.stamp)
				if err != nil || !instant.Before(before) {
					continue
				}
				// The live-grant decision and deletion share the writer transaction.
				result, err := conn.ExecContext(ctx, `DELETE FROM audit_logs WHERE id=? AND NOT EXISTS(
     SELECT 1 FROM local_break_glass_recoveries r WHERE r.audit_id=audit_logs.id
     AND (unixepoch(r.expires_at)>unixepoch() OR unixepoch(r.expires_at) IS NULL))`, c.id)
				if err != nil {
					return err
				}
				n, err := result.RowsAffected()
				if err != nil {
					return err
				}
				total += int(n)
			}
			return nil
		})
		if err != nil {
			return startEpoch, startID, count, fmt.Errorf("delete audit batch: %w", err)
		}
		return epoch, id, count, nil
	}
	batches := auditRetentionBatches
	if s.auditRetentionCalls%auditRetentionRewindCalls == 0 {
		epoch, id, count, err := scan(s.auditRevisitEpoch, s.auditRevisitID)
		if err != nil {
			return total, err
		}
		s.auditRevisitEpoch, s.auditRevisitID = epoch, id
		if count < auditRetentionBatch {
			s.auditRevisitEpoch, s.auditRevisitID = -1<<63, ""
		}
		batches--
	}
	for batch := 0; batch < batches; batch++ {
		epoch, id, count, err := scan(s.auditRetentionEpoch, s.auditRetentionID)
		if err != nil {
			return total, err
		}
		s.auditRetentionEpoch, s.auditRetentionID = epoch, id
		if count < auditRetentionBatch {
			s.auditRetentionEpoch, s.auditRetentionID = -1<<63, ""
			break
		}
	}
	return total, nil
}

const auditRetentionCandidates = `SELECT id,created_at,created_at_epoch FROM audit_logs
 WHERE (created_at_epoch,id)>(?,?) AND created_at_epoch<=?
 ORDER BY created_at_epoch,id LIMIT ?`

func auditInstant(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp")
}
