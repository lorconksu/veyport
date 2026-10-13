package store_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func persistenceExecution(id string) *model.Execution {
	return &model.Execution{ID: id, ActorID: "synthetic-actor", ActorName: "synthetic-actor", NodeID: "synthetic-node", NodeName: "synthetic-node", CommandSHA256: auditrecord.Hash([]byte("private synthetic command")), CommandLength: 25}
}

func persistencePreparation() model.ExecutionPreparation {
	return model.ExecutionPreparation{PreparationID: "synthetic-preparation", BootID: "synthetic-boot", Identity: model.ExecutionIdentity{Username: "root", UID: 0, GID: 0}}
}

func assertPersistenceState(t *testing.T, s *store.Store, id, state string, events, dispatches int) {
	t.Helper()
	e, err := s.GetExecution(id)
	if err != nil || e.State != state || e.FinishedAt != nil || e.ExitCode != nil {
		t.Fatalf("durable process metadata changed during failed transition: %+v %v", e, err)
	}
	for _, query := range []struct {
		sql  string
		want int
	}{{"SELECT COUNT(*) FROM execution_events WHERE execution_id=?", events}, {"SELECT COUNT(*) FROM execution_dispatches WHERE execution_id=?", dispatches}} {
		var count int
		if err := s.DB().QueryRow(query.sql, id).Scan(&count); err != nil || count != query.want {
			t.Fatalf("partial journal/claim transaction: count=%d want=%d err=%v", count, query.want, err)
		}
	}
}

func TestExecutionJournalFailuresRollbackStateAndSingleDispatchClaim(t *testing.T) {
	s, err := store.New(filepath.Join(t.TempDir(), "execution-persistence.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	e := persistenceExecution("atomic-process")
	failEvent := func() {
		originalExec(t, s, `CREATE TRIGGER execution_event_fault BEFORE INSERT ON execution_events BEGIN SELECT RAISE(ABORT,'synthetic journal unavailable'); END`)
	}
	repair := func() { originalExec(t, s, "DROP TRIGGER execution_event_fault") }
	failEvent()
	if err = s.CreateExecution(e); err == nil {
		t.Fatal("missing submitted journal was reported durable")
	}
	if _, err = s.GetExecution(e.ID); err == nil {
		t.Fatal("failed initial journal retained a partial process record")
	}
	repair()
	if err = s.CreateExecution(e); err != nil {
		t.Fatal(err)
	}
	failEvent()
	if err = s.PrepareExecution(e.ID, persistencePreparation()); err == nil {
		t.Fatal("failed preparation journal was reported durable")
	}
	assertPersistenceState(t, s, e.ID, "submitted", 1, 0)
	repair()
	if err = s.PrepareExecution(e.ID, persistencePreparation()); err != nil {
		t.Fatal(err)
	}
	originalExec(t, s, `CREATE TRIGGER dispatch_claim_fault BEFORE INSERT ON execution_dispatches BEGIN SELECT RAISE(ABORT,'synthetic claim unavailable'); END`)
	if err = s.ClaimExecutionDispatch(e.ID, "synthetic-preparation"); err == nil {
		t.Fatal("failed durable claim allowed dispatch")
	}
	assertPersistenceState(t, s, e.ID, "prepared", 2, 0)
	originalExec(t, s, "DROP TRIGGER dispatch_claim_fault")
	failEvent()
	if err = s.ClaimExecutionDispatch(e.ID, "synthetic-preparation"); err == nil {
		t.Fatal("dispatch journal failure left a usable claim")
	}
	assertPersistenceState(t, s, e.ID, "prepared", 2, 0)
	repair()
	if err = s.ClaimExecutionDispatch(e.ID, "synthetic-preparation"); err != nil {
		t.Fatal(err)
	}
	failEvent()
	if err = s.MarkExecutionRunning(e.ID); err == nil {
		t.Fatal("running was reported without its durable event")
	}
	assertPersistenceState(t, s, e.ID, "dispatching", 3, 1)
	repair()
	if err = s.MarkExecutionRunning(e.ID); err != nil {
		t.Fatal(err)
	}
	failEvent()
	code := int32(42)
	if err = s.FinishExecution(e.ID, "exited", &code, "", ""); err == nil {
		t.Fatal("completion was reported without its durable event")
	}
	assertPersistenceState(t, s, e.ID, "running", 4, 1)
	if err = s.ReconcileExecutions(); err == nil {
		t.Fatal("restart reconciled without its durable event")
	}
	assertPersistenceState(t, s, e.ID, "running", 4, 1)
	repair()
	originalExec(t, s, `CREATE TRIGGER restart_state_fault BEFORE UPDATE ON executions WHEN NEW.reason='hub restarted' BEGIN SELECT RAISE(ABORT,'synthetic restart write unavailable'); END`)
	if err = s.ReconcileExecutions(); err == nil {
		t.Fatal("failed restart metadata write was reported reconciled")
	}
	assertPersistenceState(t, s, e.ID, "running", 4, 1)
	originalExec(t, s, "DROP TRIGGER restart_state_fault")
	if err = s.ReconcileExecutions(); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetExecution(e.ID)
	if err != nil || got.State != "outcome_unknown" || got.EvidenceState != "completion_unconfirmed" || got.ExitCode != nil {
		t.Fatal("repaired restart fabricated process completion")
	}
	if err = s.ClaimExecutionDispatch(e.ID, "synthetic-preparation"); !errors.Is(err, store.ErrExecutionState) {
		t.Fatal("uncertain process effects became eligible for replay")
	}
}

func TestExecutionClosedStorageCannotClaimFinishOrReconcileEffects(t *testing.T) {
	s := testStore(t)
	e := persistenceExecution("closed-process")
	if err := s.CreateExecution(e); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for name, operation := range map[string]func() error{
		"create":    func() error { return s.CreateExecution(persistenceExecution("another-process")) },
		"prepare":   func() error { return s.PrepareExecution(e.ID, persistencePreparation()) },
		"claim":     func() error { return s.ClaimExecutionDispatch(e.ID, "synthetic-preparation") },
		"running":   func() error { return s.MarkExecutionRunning(e.ID) },
		"finish":    func() error { return s.FinishExecution(e.ID, "cancelled", nil, "", "transport stopped") },
		"reconcile": s.ReconcileExecutions,
		"evidence":  func() error { return s.MarkExecutionEvidenceIncomplete(e.ID) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil {
				t.Fatal("closed durable storage reported successful process metadata")
			}
		})
	}
}

func TestExecutionCorruptPreparationDoesNotInventAnIdentity(t *testing.T) {
	s := testStore(t)
	e := persistenceExecution("damaged-preparation")
	if err := s.CreateExecution(e); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareExecution(e.ID, model.ExecutionPreparation{}); err == nil {
		t.Fatal("absent preparation identity was persisted")
	}
	originalExec(t, s, "UPDATE executions SET preparation='invalid JSON' WHERE id=?", e.ID)
	if got, err := s.GetExecution(e.ID); err == nil || got != nil {
		t.Fatal("corrupt metadata yielded an apparent root identity")
	}
	if items, _, err := s.ListExecutions(model.ExecutionFilter{Limit: 10}); err == nil || items != nil {
		t.Fatal("corrupt metadata escaped through investigation listing")
	}
}
