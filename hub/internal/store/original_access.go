package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
)

var ErrOriginalAccess = errors.New("original access unavailable, expired or already used")

const MaxOriginalAccess = 4096
const MaxOriginalEvidence = 1024
const MaxOriginalEvidenceBytes = 16 << 20
const OriginalEvidenceMaxAge = 24 * time.Hour

const originalColumns = `id,execution_id,user_id,person_id,session_id,security_revision,policy_version,policy_sha256,digest,purpose,kind,object_ref,actor,intent,intent_token,handle_sha256,created_at,expires_at,consumed_at,state,evidence_state,bytes_written`

func (s *Store) originalTransaction(ctx context.Context) (*sql.Tx, func(), error) {
	return s.protectedWriteTransaction(ctx, "UPDATE original_access SET state=state WHERE 0")
}

func originalPrincipal(tx *sql.Tx, a model.OriginalAccess, now time.Time, policy lockout.Policy) error {
	var count int
	cliIdle := session.IdleTimeout(model.SessionKindCLI, policy)
	webIdle := session.IdleTimeout(model.SessionKindWeb, policy)
	err := tx.QueryRow(`SELECT COUNT(*) FROM users u JOIN security_identity_links l ON l.user_id=u.id JOIN sessions s ON s.user_id=u.id
 WHERE u.id=? AND u.disabled_at IS NULL AND u.security_revision=? AND u.totp_enabled=1 AND u.must_change_password=0
 AND l.person_id=? AND s.id=? AND s.ended_at IS NULL AND (s.expires_at IS NULL OR s.expires_at>?)
 AND (CASE WHEN s.kind=? THEN ? ELSE ? END<=0
      OR s.last_seen_at>=CASE WHEN s.kind=? THEN ? ELSE ? END)
 AND EXISTS(SELECT 1 FROM user_roles r WHERE r.user_id=u.id AND r.role='original-reader')`,
		a.UserID, a.SecurityRevision, a.PersonID, a.SessionID, now.UTC().Format(sqliteTimeFormat),
		model.SessionKindCLI, cliIdle.Nanoseconds(), webIdle.Nanoseconds(), model.SessionKindCLI,
		now.Add(-cliIdle).UTC().Format(sqliteTimeFormat), now.Add(-webIdle).UTC().Format(sqliteTimeFormat)).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrOriginalAccess
	}
	return nil
}

func queueOriginal(tx *sql.Tx, a model.OriginalAccess, raw []byte, retain, now time.Time) error {
	expected, e, err := auditrecord.ExpectedFor(raw)
	if err != nil || (e.EventType != auditrecord.OriginalReadIntent && e.EventType != auditrecord.OriginalReadResult) || len(raw) > 16384 || len(e.Command) != 0 || len(e.Attachments) != 0 || e.Execution != nil || e.Details.CorrelationID != a.ID || e.PolicyVersion != a.PolicyVersion || e.PolicySHA256 != a.PolicySHA256 || auditrecord.Digest(e.Actor) != auditrecord.Digest(a.Actor) || e.Details.SessionSHA256 != SecurityDigest([]byte(a.SessionID)) || e.Details.Reason != a.Purpose || len(e.Details.Originals) != 1 || auditrecord.Digest(e.Details.Originals[0]) != auditrecord.Digest(a.Object) || retain.IsZero() {
		return auditrecord.ErrSchema
	}
	var existing []byte
	err = tx.QueryRow("SELECT exact_record FROM original_read_evidence WHERE event_id=?", expected.EventID).Scan(&existing)
	if err == nil {
		if auditrecord.Hash(existing) != expected.RecordSHA256 {
			return ErrOriginalAccess
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var confirmedHash string
	err = tx.QueryRow("SELECT record_sha256 FROM original_read_confirmations WHERE event_id=?", expected.EventID).Scan(&confirmedHash)
	if err == nil {
		if confirmedHash != expected.RecordSHA256 {
			return ErrOriginalAccess
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var count, bytes int
	if err = tx.QueryRow("SELECT COUNT(*),COALESCE(SUM(length(exact_record)),0) FROM original_read_evidence").Scan(&count, &bytes); err != nil {
		return err
	}
	if count >= MaxOriginalEvidence || bytes+len(raw) > MaxOriginalEvidenceBytes {
		return ErrOriginalAccess
	}
	_, err = tx.Exec(`INSERT INTO original_read_evidence(event_id,access_id,policy_version,exact_record,min_retain_until,created_at,next_attempt_at) VALUES(?,?,?,?,?,?,?)`, e.EventID, a.ID, a.PolicyVersion, raw, retain.UTC().Format(time.RFC3339Nano), now.UnixMilli(), now.UnixMilli())
	return err
}

// CreateOriginalAccess consumes the operation proof and durably records the
// pending intent together. No handle is usable until independent preservation.
func (s *Store) CreateOriginalAccess(a model.OriginalAccess, proof string, retain, now time.Time, policy lockout.Policy) error {
	if !auditrecord.ValidID(a.ID) || !auditrecord.ValidID(a.ExecutionID) || !auditrecord.ValidHash(a.HandleSHA256) || !auditrecord.ValidHash(a.Digest) || !a.Object.Valid() || a.ExpiresAt.After(now.Add(time.Minute)) || !a.ExpiresAt.After(now) || len(proof) != 64 || (a.Kind != "envelope" && a.Kind != "script") {
		return ErrOriginalAccess
	}
	tx, cleanup, err := s.originalTransaction(context.Background())
	if err != nil {
		return err
	}
	defer cleanup()
	if err = originalPrincipal(tx, a, now, policy); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow("SELECT COUNT(*) FROM original_access").Scan(&count); err != nil || count >= MaxOriginalAccess {
		return ErrOriginalAccess
	}
	res, err := tx.Exec(`UPDATE stepup_proofs SET consumed_at=? WHERE hash=? AND user_id=? AND session_id=? AND action=? AND digest=? AND consumed_at IS NULL AND created_at<=? AND expires_at>?`, now.Unix(), SecurityDigest([]byte(proof)), a.UserID, a.SessionID, model.OriginalReadAction, a.Digest, now.Unix(), now.Unix())
	if err = executionUpdated(res, err); err != nil {
		return ErrStepup
	}
	object, _ := json.Marshal(a.Object)
	actor, _ := json.Marshal(a.Actor)
	_, err = tx.Exec(`INSERT INTO original_access(id,execution_id,user_id,person_id,session_id,security_revision,policy_version,policy_sha256,digest,purpose,kind,object_ref,actor,intent,handle_sha256,created_at,expires_at,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')`, a.ID, a.ExecutionID, a.UserID, a.PersonID, a.SessionID, a.SecurityRevision, a.PolicyVersion, a.PolicySHA256, a.Digest, a.Purpose, a.Kind, object, actor, a.Intent, a.HandleSHA256, now.UnixMilli(), a.ExpiresAt.UnixMilli())
	if err != nil {
		return err
	}
	if err = queueOriginal(tx, a, a.Intent, retain, now); err != nil {
		return err
	}
	return tx.Commit()
}

func scanOriginal(row executionScanner) (model.OriginalAccess, error) {
	var a model.OriginalAccess
	var object, actor []byte
	var created, expires int64
	var consumed sql.NullInt64
	err := row.Scan(&a.ID, &a.ExecutionID, &a.UserID, &a.PersonID, &a.SessionID, &a.SecurityRevision, &a.PolicyVersion, &a.PolicySHA256, &a.Digest, &a.Purpose, &a.Kind, &object, &actor, &a.Intent, &a.IntentToken, &a.HandleSHA256, &created, &expires, &consumed, &a.State, &a.EvidenceState, &a.BytesWritten)
	if err != nil {
		return a, err
	}
	if auditrecord.Decode(object, &a.Object, 8192) != nil || auditrecord.Decode(actor, &a.Actor, 2048) != nil {
		return a, ErrOriginalAccess
	}
	a.CreatedAt, a.ExpiresAt = time.UnixMilli(created), time.UnixMilli(expires)
	if consumed.Valid {
		stamp := time.UnixMilli(consumed.Int64)
		a.ConsumedAt = &stamp
	}
	return a, nil
}

func (s *Store) GetOriginalAccess(id string) (model.OriginalAccess, error) {
	return scanOriginal(s.db.QueryRow("SELECT "+originalColumns+" FROM original_access WHERE id=?", id))
}

func confirmOriginal(tx *sql.Tx, event string, manifest auditrecord.ObjectRef, now time.Time) error {
	var access string
	var raw []byte
	err := tx.QueryRow("SELECT access_id,exact_record FROM original_read_evidence WHERE event_id=?", event).Scan(&access, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		var previous []byte
		if err = tx.QueryRow("SELECT manifest FROM original_read_confirmations WHERE event_id=?", event).Scan(&previous); err != nil {
			return err
		}
		var ref auditrecord.ObjectRef
		if auditrecord.Decode(previous, &ref, 8192) != nil || auditrecord.Digest(ref) != auditrecord.Digest(manifest) {
			return ErrOriginalAccess
		}
		return nil
	}
	if err != nil {
		return err
	}
	encoded, _ := json.Marshal(manifest)
	if _, err = tx.Exec(`INSERT INTO original_read_confirmations VALUES(?,?,?,?,?) ON CONFLICT(event_id) DO NOTHING`, event, access, auditrecord.Hash(raw), encoded, now.UnixMilli()); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM original_read_evidence WHERE event_id=?", event); err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE original_access SET evidence_state='confirmed' WHERE id=? AND state IN ('completed','interrupted','unconfirmed','expired') AND evidence_state!='permanently_incomplete' AND NOT EXISTS(SELECT 1 FROM original_read_evidence WHERE access_id=?)`, access, access)
	return err
}

func (s *Store) AuthorizeOriginalAccess(id, token string, expiry time.Time, manifest auditrecord.ObjectRef, now time.Time, policy lockout.Policy) error {
	if len(token) == 0 || len(token) > auditrecord.MaxReceiptBytes || !manifest.Valid() || !expiry.After(now) {
		return ErrOriginalAccess
	}
	tx, cleanup, err := s.originalTransaction(context.Background())
	if err != nil {
		return err
	}
	defer cleanup()
	a, err := scanOriginal(tx.QueryRow("SELECT "+originalColumns+" FROM original_access WHERE id=?", id))
	if err != nil || a.State != "pending" || expiry.UnixMilli() > a.ExpiresAt.UnixMilli() {
		return ErrOriginalAccess
	}
	if err = originalPrincipal(tx, a, now, policy); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE original_access SET intent_token=?,expires_at=?,state='authorized' WHERE id=?`, token, expiry.UnixMilli(), id); err != nil {
		return err
	}
	if err = confirmOriginal(tx, id+".intent", manifest, now); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeOriginalAccess commits the hashed one-use claim before any archive
// stream opens. Permission, identity revision and session are checked inside it.
func (s *Store) ConsumeOriginalAccess(hash, user, session string, now time.Time, policy lockout.Policy) (model.OriginalAccess, error) {
	var a model.OriginalAccess
	if !auditrecord.ValidHash(hash) || session == "" {
		return a, ErrOriginalAccess
	}
	tx, cleanup, err := s.originalTransaction(context.Background())
	if err != nil {
		return a, err
	}
	defer cleanup()
	a, err = scanOriginal(tx.QueryRow("SELECT "+originalColumns+" FROM original_access WHERE handle_sha256=? AND user_id=? AND session_id=? AND state='authorized' AND consumed_at IS NULL AND expires_at>?", hash, user, session, now.UnixMilli()))
	if err != nil {
		return a, ErrOriginalAccess
	}
	if err = originalPrincipal(tx, a, now, policy); err != nil {
		return a, err
	}
	res, err := tx.Exec(`UPDATE original_access SET consumed_at=?,state='started',evidence_state='pending' WHERE id=? AND consumed_at IS NULL AND state='authorized'`, now.UnixMilli(), a.ID)
	if err = executionUpdated(res, err); err != nil {
		return a, ErrOriginalAccess
	}
	if err = tx.Commit(); err != nil {
		return a, err
	}
	a.State, a.ConsumedAt = "started", &now
	return a, nil
}

func (s *Store) RecordOriginalOutcome(id, state string, n int64, raw []byte, retain, now time.Time) error {
	if state != "started" && state != "completed" && state != "interrupted" && state != "unconfirmed" && state != "expired" || n < 0 || n > auditrecord.MaxAttachmentBytes {
		return ErrOriginalAccess
	}
	tx, cleanup, err := s.originalTransaction(context.Background())
	if err != nil {
		return err
	}
	defer cleanup()
	a, err := scanOriginal(tx.QueryRow("SELECT "+originalColumns+" FROM original_access WHERE id=?", id))
	if err != nil {
		return err
	}
	_, e, err := auditrecord.ExpectedFor(raw)
	expectedEvent := id + ".result"
	if state == "started" {
		expectedEvent = id + ".started"
	}
	if err != nil || e.EventType != auditrecord.OriginalReadResult || e.EventID != expectedEvent || e.Details.State != state || e.Details.Delivery == nil || n > a.Object.Bytes || (state == "completed" && n != a.Object.Bytes) || (e.Details.Delivery.BytesWritten != nil && *e.Details.Delivery.BytesWritten != n) {
		return auditrecord.ErrSchema
	}
	if a.EvidenceState == "permanently_incomplete" {
		return ErrOriginalAccess
	}
	terminal := a.State == "completed" || a.State == "interrupted" || a.State == "unconfirmed" || a.State == "expired"
	if terminal {
		if state != a.State || n != a.BytesWritten {
			return ErrOriginalAccess
		}
		// An exact result replay is idempotent. It cannot downgrade an already
		// confirmed result or replace a terminal delivery outcome.
		if err = queueOriginal(tx, a, raw, retain, now); err != nil {
			return err
		}
		return tx.Commit()
	}
	if state == "expired" {
		if a.State != "pending" && a.State != "authorized" {
			return ErrOriginalAccess
		}
	} else if a.State != "started" {
		return ErrOriginalAccess
	}
	if err = queueOriginal(tx, a, raw, retain, now); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE original_access SET state=?,bytes_written=?,evidence_state=CASE WHEN evidence_state='permanently_incomplete' THEN evidence_state WHEN ?='started' THEN 'pending' ELSE 'unconfirmed' END WHERE id=?`, state, n, state, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConfirmOriginalEvidence(event string, manifest auditrecord.ObjectRef, now time.Time) error {
	if !manifest.Valid() {
		return ErrOriginalAccess
	}
	tx, cleanup, err := s.originalTransaction(context.Background())
	if err != nil {
		return err
	}
	defer cleanup()
	if err = confirmOriginal(tx, event, manifest, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DueOriginalEvidence(now time.Time) ([]model.OriginalEvidence, error) {
	rows, err := s.db.Query(`SELECT event_id,access_id,policy_version,exact_record,min_retain_until,created_at,attempts FROM original_read_evidence WHERE next_attempt_at<=? ORDER BY created_at,event_id LIMIT 32`, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []model.OriginalEvidence{}
	for rows.Next() {
		var e model.OriginalEvidence
		var retain string
		var created int64
		if err := rows.Scan(&e.EventID, &e.AccessID, &e.PolicyVersion, &e.Raw, &retain, &created, &e.Attempts); err != nil {
			return nil, err
		}
		if e.MinRetainUntil, err = time.Parse(time.RFC3339Nano, retain); err != nil {
			return nil, err
		}
		e.CreatedAt = time.UnixMilli(created)
		items = append(items, e)
	}
	return items, rows.Err()
}

func (s *Store) RetryOriginalEvidence(e model.OriginalEvidence, now time.Time) error {
	if now.Sub(e.CreatedAt) >= OriginalEvidenceMaxAge {
		return s.MarkOriginalPermanent(e.AccessID)
	}
	_, err := s.db.Exec(`UPDATE original_read_evidence SET attempts=attempts+1,next_attempt_at=? WHERE event_id=?`, now.Add(time.Minute).UnixMilli(), e.EventID)
	return err
}

func (s *Store) MarkOriginalPermanent(id string) error {
	tx, cleanup, err := s.originalTransaction(context.Background())
	if err != nil {
		return err
	}
	defer cleanup()
	if _, err = tx.Exec(`UPDATE original_access SET evidence_state='permanently_incomplete',state=CASE WHEN state IN ('pending','authorized') THEN 'expired' ELSE state END WHERE id=?`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM original_read_evidence WHERE access_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// Expired/abandoned permits cannot be recreated by recovery. Metadata retained
// for thirty days is bounded; unresolved gaps retain their explicit status.
func (s *Store) SweepOriginalAccess(now time.Time) ([]model.OriginalAccess, error) {
	tx, cleanup, err := s.originalTransaction(context.Background())
	if err != nil {
		return nil, err
	}
	defer cleanup()
	rows, err := tx.Query("SELECT "+originalColumns+" FROM original_access WHERE evidence_state!='permanently_incomplete' AND ((state IN ('pending','authorized') AND expires_at<=?) OR (state='started' AND consumed_at<?)) ORDER BY created_at LIMIT 32", now.UnixMilli(), now.Add(-2*time.Minute).UnixMilli())
	if err != nil {
		return nil, err
	}
	items := []model.OriginalAccess{}
	for rows.Next() {
		a, err := scanOriginal(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, a)
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`DELETE FROM original_read_confirmations WHERE access_id IN (SELECT id FROM original_access WHERE created_at<? AND evidence_state IN ('confirmed','permanently_incomplete'))`, now.Add(-30*24*time.Hour).UnixMilli()); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`DELETE FROM original_access WHERE created_at<? AND evidence_state IN ('confirmed','permanently_incomplete') AND NOT EXISTS(SELECT 1 FROM original_read_evidence WHERE access_id=original_access.id)`, now.Add(-30*24*time.Hour).UnixMilli()); err != nil {
		return nil, err
	}
	return items, tx.Commit()
}
