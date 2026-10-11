package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

var ErrExecutionState = errors.New("execution state changed or execution not found")

func (s *Store) CreateExecution(e *model.Execution) error {
	now := time.Now().UTC().Format(sqliteTimeFormat)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO executions(id,actor_id,actor_name,actor_provider,node_id,node_name,requested_user,command_sha256,command_length,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, e.ID, e.ActorID, e.ActorName, e.ActorProvider, e.NodeID, e.NodeName, e.RequestedUser, e.CommandSHA256, e.CommandLength, now, now)
	if err != nil {
		return fmt.Errorf("create execution: %w", err)
	}
	if err = executionEvent(tx, e.ID, "submitted", now); err != nil {
		return err
	}
	return tx.Commit()
}

func executionEvent(tx *sql.Tx, id, state, now string) error {
	_, err := tx.Exec(`INSERT INTO execution_events(id,execution_id,sequence,event_type,created_at) SELECT ?,?,COALESCE(MAX(sequence)+1,0),?,? FROM execution_events WHERE execution_id=?`, uuid.NewString(), id, state, now, id)
	return err
}

func (s *Store) PrepareExecution(id string, p model.ExecutionPreparation) error {
	if p.PreparationID == "" || p.BootID == "" || p.Identity.Username == "" {
		return errors.New("execution preparation metadata missing")
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(sqliteTimeFormat)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE executions SET preparation=?,state='prepared',updated_at=? WHERE id=? AND state='submitted'`, string(data), now, id)
	if err = executionUpdated(res, err); err != nil {
		return err
	}
	if err = executionEvent(tx, id, "prepared", now); err != nil {
		return err
	}
	return tx.Commit()
}

// ClaimExecutionDispatch is durable metadata before network dispatch. A failed
// or lost Start is never eligible for another claim.
func (s *Store) ClaimExecutionDispatch(id, preparation string) error {
	now := time.Now().UTC().Format(sqliteTimeFormat)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE executions SET state='dispatching',updated_at=? WHERE id=? AND state='prepared' AND json_extract(preparation,'$.preparation_id')=?`, now, id, preparation)
	if err = executionUpdated(res, err); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO execution_dispatches(execution_id,preparation_id,claimed_at) VALUES(?,?,?)`, id, preparation, now); err != nil {
		return err
	}
	if err = executionEvent(tx, id, "dispatching", now); err != nil {
		return err
	}
	return tx.Commit()
}

func executionUpdated(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrExecutionState
	}
	return nil
}

func (s *Store) MarkExecutionRunning(id string) error {
	now := time.Now().UTC().Format(sqliteTimeFormat)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE executions SET state='running',updated_at=? WHERE id=? AND state='dispatching'`, now, id)
	if err = executionUpdated(res, err); err != nil {
		return err
	}
	if err = executionEvent(tx, id, "running", now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) FinishExecution(id, state string, exitCode *int32, signal, reason string) error {
	switch state {
	case "exited", "denied", "admission_failed", "launch_failed", "cancelled", "transport_lost", "outcome_unknown":
	default:
		return errors.New("invalid execution outcome")
	}
	now := time.Now().UTC().Format(sqliteTimeFormat)
	evidence := "local"
	if state == "transport_lost" || state == "outcome_unknown" {
		evidence = "completion_unconfirmed"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE executions SET state=?,evidence_state=?,exit_code=?,signal=?,reason=?,updated_at=?,finished_at=? WHERE id=? AND finished_at IS NULL`, state, evidence, exitCode, signal, reason, now, now, id)
	if err = executionUpdated(res, err); err != nil {
		return err
	}
	if err = executionEvent(tx, id, state, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetExecution(id string) (*model.Execution, error) {
	var e model.Execution
	var preparation, created, updated string
	var finished sql.NullString
	var code sql.NullInt32
	err := s.db.QueryRow(`SELECT id,actor_id,actor_name,actor_provider,node_id,node_name,requested_user,command_sha256,command_length,policy_version,preparation,state,evidence_state,exit_code,signal,reason,created_at,updated_at,finished_at FROM executions WHERE id=?`, id).Scan(&e.ID, &e.ActorID, &e.ActorName, &e.ActorProvider, &e.NodeID, &e.NodeName, &e.RequestedUser, &e.CommandSHA256, &e.CommandLength, &e.PolicyVersion, &preparation, &e.State, &e.EvidenceState, &code, &e.Signal, &e.Reason, &created, &updated, &finished)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(preparation), &e.Preparation); err != nil {
		return nil, err
	}
	e.CreatedAt, e.UpdatedAt, e.FinishedAt = parseSQLiteTimeValue(created), parseSQLiteTimeValue(updated), parseSQLiteTime(finished)
	if code.Valid {
		e.ExitCode = &code.Int32
	}
	return &e, nil
}

// ReconcileExecutions preserves crash uncertainty instead of retrying effects.
func (s *Store) ReconcileExecutions() error {
	now := time.Now().UTC().Format(sqliteTimeFormat)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO execution_events(id,execution_id,sequence,event_type,created_at) SELECT lower(hex(randomblob(16))),e.id,COALESCE(MAX(ev.sequence)+1,0),CASE WHEN e.state IN ('dispatching','running') THEN 'outcome_unknown' ELSE 'cancelled' END,? FROM executions e LEFT JOIN execution_events ev ON ev.execution_id=e.id WHERE e.finished_at IS NULL GROUP BY e.id`, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE executions SET state=CASE WHEN state IN ('dispatching','running') THEN 'outcome_unknown' ELSE 'cancelled' END,evidence_state=CASE WHEN state IN ('dispatching','running') THEN 'completion_unconfirmed' ELSE evidence_state END,reason='hub restarted',updated_at=?,finished_at=? WHERE finished_at IS NULL`, now, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) MarkExecutionEvidenceIncomplete(id string) error {
	_, err := s.db.Exec(`UPDATE executions SET evidence_state='completion_unconfirmed' WHERE id=?`, id)
	return err
}
