package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
)

// protectedTransaction upgrades this connection to FULL synchronous durability
// before claiming any permit. WAL NORMAL can lose an acknowledged transaction
// after power loss and is insufficient for single-use execution authority.
func (s *Store) protectedTransaction(ctx context.Context) (*sql.Tx, func(), error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	if _, err = conn.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		conn.Close()
		return nil, func() {}, err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		conn.Close()
		return nil, func() {}, err
	}
	return tx, func() { _ = tx.Rollback(); _ = conn.Close() }, nil
}

func (s *Store) SetExecutionSubmission(id, scriptHash string, length int64, eventID, recordHash string) error {
	res, err := s.db.Exec(`UPDATE executions SET script_sha256=?,script_length=?,admission_event_id=?,admission_record_sha256=? WHERE id=? AND state IN ('submitted','prepared') AND enhanced=1`, scriptHash, length, eventID, recordHash, id)
	return executionUpdated(res, err)
}

// Claim implements auditgate.Consumer. The receipt's one-use consumption and
// dispatch state share one transaction; Enhanced must never call the separate
// Standard ClaimExecutionDispatch afterward.
func (s *Store) Claim(ctx context.Context, id, preparation, receiptHash string) error {
	if !auditrecord.ValidHash(receiptHash) {
		return auditgate.ErrReceipt
	}
	tx, cleanup, err := s.protectedTransaction(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	now := time.Now().UTC().Format(sqliteTimeFormat)
	res, err := tx.ExecContext(ctx, `UPDATE executions SET state='dispatching',evidence_state='pending',admission_disposition='consumed_dispatch',updated_at=? WHERE id=? AND enhanced=1 AND state='prepared' AND json_extract(preparation,'$.preparation_id')=? AND json_extract(preparation,'$.expires_unix_milli')>?`, now, id, preparation, time.Now().UnixMilli())
	if err = executionUpdated(res, err); err != nil {
		return errors.Join(auditgate.ErrReplay, err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO execution_dispatches(execution_id,preparation_id,receipt_sha256,claimed_at) VALUES(?,?,?,?)`, id, preparation, receiptHash, now); err != nil {
		return err
	}
	if err = executionEvent(tx, id, "admitted", now); err != nil {
		return err
	}
	if err = executionEvent(tx, id, "dispatching", now); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SaveExecutionReceipt(id, token string) error {
	if len(token) == 0 || len(token) > auditrecord.MaxReceiptBytes {
		return auditgate.ErrReceipt
	}
	_, err := s.db.Exec(`UPDATE executions SET admission_receipt=? WHERE id=? AND enhanced=1`, token, id)
	return err
}

type ExecutionEvidence struct {
	EventID, ExecutionID, RecordSHA256 string
	PolicyVersion                      uint64
	Envelope                           []byte
	MinRetainUntil, CreatedAt          time.Time
	Attempts                           int
}

const MaxRecoveryEvents = 1024
const MaxRecoveryBytes = 16 << 20
const MaxRecoveryAge = 24 * time.Hour

func (s *Store) QueueExecutionEvidence(raw []byte, minRetain time.Time) error {
	expected, envelope, err := auditrecord.ExpectedFor(raw)
	if err != nil || (envelope.EventType != auditrecord.ExecutionLifecycle && envelope.EventType != auditrecord.ExecutionDenial) || len(raw) > 16384 || len(envelope.Command) != 0 || len(envelope.Attachments) != 0 {
		return auditrecord.ErrSchema
	}
	if _, err = DecodeExecutionEvidence(raw); err != nil {
		return err
	}
	executionID := envelope.Details.CorrelationID
	tx, cleanup, err := s.protectedWriteTransaction(context.Background(), "UPDATE execution_evidence_recovery SET attempts=attempts WHERE 0")
	if err != nil {
		return err
	}
	defer cleanup()
	var confirmed string
	if err = tx.QueryRow(`SELECT record_sha256 FROM execution_evidence_confirmations WHERE event_id=?`, envelope.EventID).Scan(&confirmed); err == nil {
		if confirmed != expected.RecordSHA256 {
			return auditrecord.ErrSchema
		}
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var existing string
	if err = tx.QueryRow(`SELECT record_sha256 FROM execution_evidence_recovery WHERE event_id=?`, envelope.EventID).Scan(&existing); err == nil {
		if existing != expected.RecordSHA256 {
			return auditrecord.ErrSchema
		}
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var count, bytes int
	if err = tx.QueryRow(`SELECT count(*),COALESCE(sum(length(envelope)),0) FROM execution_evidence_recovery`).Scan(&count, &bytes); err != nil {
		return err
	}
	if count >= MaxRecoveryEvents || bytes+len(raw) > MaxRecoveryBytes {
		_, err = tx.Exec(`UPDATE executions SET evidence_state='permanently_incomplete' WHERE id=?`, executionID)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	now := time.Now().UTC().Format(sqliteTimeFormat)
	_, err = tx.Exec(`INSERT INTO execution_evidence_recovery(event_id,execution_id,policy_version,record_sha256,envelope,min_retain_until,created_at,next_attempt_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(event_id) DO NOTHING`, envelope.EventID, executionID, envelope.PolicyVersion, expected.RecordSHA256, raw, minRetain.UTC().Format(time.RFC3339Nano), now, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE executions SET evidence_state=CASE WHEN finished_at IS NULL THEN 'pending' ELSE 'completion_unconfirmed' END WHERE id=? AND evidence_state!='permanently_incomplete'`, executionID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) DueExecutionEvidence(now time.Time, limit int) ([]ExecutionEvidence, error) {
	if limit < 1 || limit > 32 {
		limit = 32
	}
	rows, err := s.db.Query(`SELECT event_id,execution_id,policy_version,record_sha256,envelope,min_retain_until,created_at,attempts FROM execution_evidence_recovery WHERE next_attempt_at<=? ORDER BY created_at LIMIT ?`, now.UTC().Format(sqliteTimeFormat), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ExecutionEvidence
	for rows.Next() {
		var e ExecutionEvidence
		var retain, created string
		if err = rows.Scan(&e.EventID, &e.ExecutionID, &e.PolicyVersion, &e.RecordSHA256, &e.Envelope, &retain, &created, &e.Attempts); err != nil {
			return nil, err
		}
		e.MinRetainUntil, err = time.Parse(time.RFC3339Nano, retain)
		if err != nil {
			return nil, err
		}
		e.CreatedAt = parseSQLiteTimeValue(created)
		result = append(result, e)
	}
	return result, rows.Err()
}
func (s *Store) ConfirmExecutionEvidence(eventID string) error {
	tx, cleanup, err := s.protectedWriteTransaction(context.Background(), "UPDATE execution_evidence_recovery SET attempts=attempts WHERE 0")
	if err != nil {
		return err
	}
	defer cleanup()
	var id, recordHash string
	if err = tx.QueryRow(`SELECT execution_id,record_sha256 FROM execution_evidence_recovery WHERE event_id=?`, eventID).Scan(&id, &recordHash); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO execution_evidence_confirmations(event_id,execution_id,record_sha256,confirmed_at) VALUES(?,?,?,?) ON CONFLICT(event_id) DO NOTHING`, eventID, id, recordHash, time.Now().UTC().Format(sqliteTimeFormat)); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM execution_evidence_recovery WHERE event_id=?`, eventID); err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE executions SET evidence_state='confirmed' WHERE id=? AND finished_at IS NOT NULL AND evidence_state!='permanently_incomplete' AND EXISTS(SELECT 1 FROM execution_evidence_confirmations WHERE event_id=executions.id||'.completion') AND NOT EXISTS(SELECT 1 FROM execution_evidence_recovery WHERE execution_id=?)`, id, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) RetryExecutionEvidence(e ExecutionEvidence, now time.Time) error {
	if now.Sub(e.CreatedAt) >= MaxRecoveryAge {
		tx, cleanup, err := s.protectedTransaction(context.Background())
		if err != nil {
			return err
		}
		defer cleanup()
		if _, err = tx.Exec(`UPDATE executions SET evidence_state='permanently_incomplete' WHERE id=?`, e.ExecutionID); err != nil {
			return err
		}
		if _, err = tx.Exec(`DELETE FROM execution_evidence_recovery WHERE event_id=?`, e.EventID); err != nil {
			return err
		}
		return tx.Commit()
	}
	_, err := s.db.Exec(`UPDATE execution_evidence_recovery SET attempts=attempts+1,next_attempt_at=?,last_error='external evidence unavailable' WHERE event_id=?`, now.Add(time.Minute).UTC().Format(sqliteTimeFormat), e.EventID)
	return err
}

// Envelope validation also prevents arbitrary raw payloads hidden in generic
// details from entering this bounded, ordinary recovery queue.
func DecodeExecutionEvidence(raw []byte) (auditrecord.Envelope, error) {
	var e auditrecord.Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return e, err
	}
	if (e.EventType != auditrecord.ExecutionLifecycle && e.EventType != auditrecord.ExecutionDenial) || len(e.Command) != 0 || len(e.Attachments) != 0 || e.Details == nil || e.Details.Reason != "" || len(e.Details.ApprovedChange) != 0 {
		return e, auditrecord.ErrSchema
	}
	return e, e.Validate()
}

func (s *Store) MarkExecutionAdmissionUnused(id string) error {
	_, err := s.db.Exec(`UPDATE executions SET admission_disposition=CASE WHEN admission_disposition='consumed_dispatch' THEN 'consumed_unused' WHEN admission_disposition='archived_unused' THEN 'archived_unused' ELSE 'unconfirmed_unused' END WHERE id=? AND enhanced=1 AND admission_record_sha256!=''`, id)
	return err
}
func (s *Store) MarkExecutionEvidencePermanent(id string) error {
	tx, cleanup, err := s.protectedTransaction(context.Background())
	if err != nil {
		return err
	}
	defer cleanup()
	if _, err = tx.Exec(`UPDATE executions SET evidence_state='permanently_incomplete' WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) UnqueuedEnhancedExecutions(limit int) ([]*model.Execution, error) {
	if limit < 1 || limit > 32 {
		limit = 32
	}
	rows, err := s.db.Query("SELECT "+executionColumns+` FROM executions WHERE enhanced=1 AND finished_at IS NOT NULL AND evidence_state='completion_unconfirmed' AND NOT EXISTS(SELECT 1 FROM execution_evidence_recovery r WHERE r.execution_id=executions.id) AND NOT EXISTS(SELECT 1 FROM execution_evidence_confirmations WHERE event_id=executions.id||'.completion') ORDER BY created_at LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.Execution
	for rows.Next() {
		e, err := scanExecution(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

func (s *Store) SaveUnusedExecutionReceipt(id, token string) error {
	if len(token) == 0 || len(token) > auditrecord.MaxReceiptBytes {
		return auditgate.ErrReceipt
	}
	_, err := s.db.Exec(`UPDATE executions SET admission_receipt=?,admission_disposition='archived_unused' WHERE id=? AND enhanced=1 AND state='prepared'`, token, id)
	return err
}
