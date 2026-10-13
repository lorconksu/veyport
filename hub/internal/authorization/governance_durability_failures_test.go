package authorization

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestGovernanceDurabilityFailuresDoNotConvertArchivedEvidenceIntoAuthority(t *testing.T) {
	for _, boundary := range []struct {
		name, trigger string
		active        uint64
		events        int
		pending       bool
	}{
		{"before_intent_persistence", "BEFORE INSERT ON security_evidence WHEN NEW.event_type='policy.intent'", 1, 0, false},
		{"after_external_intent", "BEFORE UPDATE OF reference ON security_evidence WHEN NEW.event_type='policy.intent' AND NEW.reference!=''", 1, 1, false},
		{"pending_version_insert", "BEFORE INSERT ON audit_policy_versions WHEN NEW.version=2", 1, 1, false},
		{"pending_state_install", "BEFORE UPDATE ON audit_policy_state WHEN NEW.pending_version IS NOT NULL AND OLD.pending_version IS NULL", 1, 1, false},
		{"after_external_commit", "BEFORE UPDATE OF commit_ref ON security_changes WHEN NEW.commit_ref!=''", 1, 2, true},
		{"after_external_result", "BEFORE UPDATE OF reference ON security_evidence WHEN NEW.event_type='policy.result' AND NEW.reference!=''", 2, 4, true},
		{"completed_request_write", "BEFORE UPDATE ON security_changes WHEN NEW.state='applied' AND OLD.state='applying'", 2, 4, true},
		{"completed_policy_write", "BEFORE UPDATE ON audit_policy_state WHEN NEW.pending_version IS NULL AND OLD.pending_version IS NOT NULL AND NEW.state='enhanced'", 2, 4, true},
	} {
		t.Run(boundary.name, func(t *testing.T) {
			s, f := fixtureGovernance(t)
			approveFixture(t, s, f, "approver-one")
			approveFixture(t, s, f, "approver-two")
			_, err := s.Store.DB().Exec("CREATE TRIGGER durability_fault " + boundary.trigger + " BEGIN SELECT RAISE(ABORT,'injected durable write failure'); END")
			if err != nil {
				t.Fatal(err)
			}
			proof, err := s.Store.IssueStepup("requester", "session-requester", ActionApply, f.change.Digest, s.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Apply(context.Background(), f.change.ID, "requester", "session-requester", proof, f.config); err == nil {
				t.Fatal("failed durable write reported a completed transition")
			}
			if err := s.Store.ConsumeStepup(proof, "requester", "session-requester", ActionApply, f.change.Digest, s.Now()); !errors.Is(err, store.ErrStepup) {
				t.Fatalf("archive/database failure made an already claimed MFA proof replayable: %v", err)
			}
			state, err := s.Store.GetPolicyState()
			if err != nil || state.Active.Version != boundary.active || (state.Pending != nil) != boundary.pending {
				t.Fatalf("failed write crossed its durable policy boundary: %+v %v", state, err)
			}
			change, err := s.Store.GetSecurityChange(f.change.ID)
			if err != nil || change.ResultRef != "" || change.State == "applied" {
				t.Fatalf("external preservation falsely completed the local transaction: %+v %v", change, err)
			}
			if !boundary.pending {
				var versions int
				if err := s.Store.DB().QueryRow("SELECT COUNT(*) FROM audit_policy_versions").Scan(&versions); err != nil || versions != 1 || change.State != "approved" {
					t.Fatalf("failed pending install left an orphan version or changed approvals: %d %s %v", versions, change.State, err)
				}
			}
			if boundary.pending {
				if _, err := s.PolicyForExecution("requester", "node"); !errors.Is(err, ErrTransition) {
					t.Fatalf("uncertain durable transition reopened covered execution: %v", err)
				}
			}
			if len(f.evidence.records) != boundary.events {
				t.Fatalf("wrong external crash boundary: %d records, want %d", len(f.evidence.records), boundary.events)
			}
			frozen := map[string][]byte{}
			for id, record := range f.evidence.records {
				frozen[id] = append([]byte(nil), record...)
			}
			before := map[string]*model.User{}
			for _, id := range []string{"requester", "approver-one", "approver-two"} {
				before[id], err = s.Store.GetUserByID(id)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Store.DB().Exec("DROP TRIGGER durability_fault"); err != nil {
				t.Fatal(err)
			}
			if boundary.pending {
				err = s.Startup(context.Background(), f.config)
			} else {
				err = applyFixture(t, s, f)
			}
			if err != nil {
				t.Fatalf("exact durable recovery failed after restoring writes: %v", err)
			}
			state, err = s.Store.GetPolicyState()
			if err != nil || state.State != "enhanced" || state.Active.Version != 2 || state.Pending != nil {
				t.Fatalf("recovery did not finish one exact transition: %+v %v", state, err)
			}
			if len(f.evidence.records) != 4 {
				t.Fatalf("recovery lost or duplicated exact external events: %d", len(f.evidence.records))
			}
			for id, record := range frozen {
				if !bytes.Equal(record, f.evidence.records[id]) {
					t.Fatalf("retry edited preserved evidence %s", id)
				}
			}
			for id, prior := range before {
				current, err := s.Store.GetUserByID(id)
				if err != nil || (boundary.active == 2 && current.TokenGeneration != prior.TokenGeneration) || (boundary.active == 1 && current.TokenGeneration <= prior.TokenGeneration) {
					t.Fatalf("activation was skipped or replayed for %s: %v %v", id, current, err)
				}
				before[id] = current
			}
			// Retrying an already completed transition returns its immutable result
			// and cannot run role/person credential side effects a second time.
			if _, err := s.ReconcileChange(context.Background(), f.change.ID, f.config); err != nil {
				t.Fatal(err)
			}
			for id, prior := range before {
				current, err := s.Store.GetUserByID(id)
				if err != nil || current.TokenGeneration != prior.TokenGeneration || current.SecurityRevision != prior.SecurityRevision {
					t.Fatalf("completed reconciliation replayed credential authority for %s", id)
				}
			}
			if err := s.ValidateAnchor(context.Background(), f.config); err != nil {
				t.Fatalf("recovered policy lost exact anchor continuity: %v", err)
			}
		})
	}
}
