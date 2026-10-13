package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestStoredPolicyPayloadCannotRetainAnotherPoliciesApprovedDigest(t *testing.T) {
	for _, corruption := range []struct {
		name   string
		change func(*model.AuditPolicy)
	}{
		{"standard_downgrade", func(p *model.AuditPolicy) { *p = model.AuditPolicy{Profile: "standard"} }},
		{"scope_reduction", func(p *model.AuditPolicy) { p.Nodes = []string{"unrelated-node"} }},
	} {
		t.Run(corruption.name, func(t *testing.T) {
			s, f := activatedFixture(t)
			var original []byte
			if err := s.Store.DB().QueryRow("SELECT payload FROM audit_policy_versions WHERE version=2").Scan(&original); err != nil {
				t.Fatal(err)
			}
			state, err := s.Store.GetPolicyState()
			if err != nil {
				t.Fatal(err)
			}
			policy := state.Active.Policy
			corruption.change(&policy)
			raw, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			// Model a selectively restored or corrupted payload while the cached
			// digest, exact request, marker and external anchor remain unchanged.
			if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=? WHERE version=?", raw, state.Active.Version); err != nil {
				t.Fatal(err)
			}
			if err := s.ValidateAnchor(context.Background(), f.config); err == nil {
				t.Error("external anchor trusted policy bytes that do not match its approved digest")
			}
			if policy, err := s.PolicyForExecution("requester", "node"); err == nil {
				t.Errorf("corrupted policy reopened an execution path: enhanced=%v version=%d", policy.Enhanced, policy.Version)
			}
			if err := s.GuardInteractive("requester", "node"); err == nil {
				t.Error("corrupted policy reopened an unaudited interactive shell")
			}
			if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=? WHERE version=2", original); err != nil {
				t.Fatal(err)
			}
			if err := s.ValidateAnchor(context.Background(), f.config); err != nil {
				t.Fatalf("exact policy byte repair rejected unchanged external evidence: %v", err)
			}
			if policy, err := s.PolicyForExecution("requester", "node"); err != nil || !policy.Enhanced || policy.SHA256 != state.Active.SHA256 {
				t.Fatalf("exact repair did not restore approved enforcement: %+v %v", policy, err)
			}
			if !errors.Is(s.GuardInteractive("requester", "node"), ErrInteractive) {
				t.Fatal("exact repair reopened interactive shells under Enhanced")
			}
		})
	}
}

func TestLocalContinuityRejectsRecomputedPolicyDigestBeforeRouting(t *testing.T) {
	for _, scope := range []string{"standard", "unrelated_scope"} {
		t.Run(scope, func(t *testing.T) {
			s, f := activatedFixture(t)
			before, err := s.Store.GetPolicyState()
			if err != nil {
				t.Fatal(err)
			}
			var original []byte
			if err := s.Store.DB().QueryRow("SELECT payload FROM audit_policy_versions WHERE version=2").Scan(&original); err != nil {
				t.Fatal(err)
			}
			corrupt := before.Active.Policy
			if scope == "standard" {
				corrupt = model.AuditPolicy{Profile: "standard", RuntimeSeconds: 3600, RetentionHours: 24}
			} else {
				corrupt.Nodes = []string{"unrelated-node"}
			}
			raw, err := json.Marshal(corrupt)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=2", raw, Digest(raw)); err != nil {
				t.Fatal(err)
			}
			// The row's self-consistent digest is insufficient. Exact approval and
			// outside-DB marker continuity must precede Standard/scope routing.
			if _, err := s.Store.GetPolicyVersion(2); err != nil {
				t.Fatalf("test did not model a recomputed row digest: %v", err)
			}
			if _, err := New(s.Store).PolicyForExecution("requester", "node"); !errors.Is(err, ErrRecovery) {
				t.Fatalf("recomputed digest reopened execution: %v", err)
			}
			if err := New(s.Store).GuardInteractive("requester", "node"); !errors.Is(err, ErrRecovery) {
				t.Fatalf("recomputed digest reopened interactive access: %v", err)
			}
			if err := s.ValidateAnchor(context.Background(), f.config); !errors.Is(err, ErrRecovery) {
				t.Fatalf("recomputed digest bypassed external continuity: %v", err)
			}
			if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=2", original, before.Active.SHA256); err != nil {
				t.Fatal(err)
			}
			f.evidence.anchorErr = fmt.Errorf("receipt service unavailable")
			if policy, err := New(s.Store).PolicyForExecution("requester", "node"); err != nil || !policy.Enhanced {
				t.Fatalf("exact local repair introduced archive dependence: %+v %v", policy, err)
			}
			if err := New(s.Store).GuardInteractive("requester", "node"); !errors.Is(err, ErrInteractive) {
				t.Fatalf("exact repair did not restore interactive restriction: %v", err)
			}
		})
	}
}

func TestLocalContinuityAuthenticatesPreviousScopeWhenPendingMarkerAdvanced(t *testing.T) {
	s, f := activatedFixture(t)
	before, err := s.Store.GetPolicyState()
	if err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err := s.Store.DB().QueryRow("SELECT payload FROM audit_policy_versions WHERE version=2").Scan(&original); err != nil {
		t.Fatal(err)
	}
	standard := model.AuditPolicy{Profile: "standard", RuntimeSeconds: 3600, RetentionHours: 24}
	change, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &standard})
	if err != nil {
		t.Fatal(err)
	}
	f.change = change
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	f.evidence.fail = auditrecord.PolicyAnchor
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("anchor fault did not interrupt disable")
	}
	state, err := s.Store.GetPolicyState()
	if err != nil || state.Active.Version != 2 || state.Pending == nil || state.Pending.Version != 3 {
		t.Fatalf("missing pending disable: %+v %v", state, err)
	}
	if marker, err := readMarker(f.config.EnrollmentPath); err != nil || marker.Version != 3 || marker.SHA256 != state.Pending.SHA256 {
		t.Fatalf("test did not reach marker-before-CAS boundary: %+v %v", marker, err)
	}
	if policy, err := New(s.Store).PolicyForExecution("requester", "node"); !errors.Is(err, ErrTransition) || !policy.Enhanced {
		t.Fatalf("pending marker lost stricter old policy: %+v %v", policy, err)
	}
	corrupt, err := json.Marshal(standard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=2", corrupt, Digest(corrupt)); err != nil {
		t.Fatal(err)
	}
	if _, err := New(s.Store).PolicyForExecution("requester", "node"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("advanced marker hid corrupted previous scope: %v", err)
	}
	if err := New(s.Store).GuardInteractive("requester", "node"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("pending previous corruption opened interactive access: %v", err)
	}
	if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=2", original, before.Active.SHA256); err != nil {
		t.Fatal(err)
	}
	f.evidence.fail = ""
	if _, err := s.ReconcileChange(context.Background(), change.ID, f.config); err != nil {
		t.Fatalf("exact previous repair stranded pending disable: %v", err)
	}
	f.evidence.anchorErr = fmt.Errorf("receipt service unavailable")
	if policy, err := New(s.Store).PolicyForExecution("requester", "node"); err != nil || policy.Enhanced || policy.Version != 3 {
		t.Fatalf("approved Standard disable requires unrelated external availability: %+v %v", policy, err)
	}
	if err := New(s.Store).GuardInteractive("requester", "node"); err != nil {
		t.Fatalf("approved Standard interactive access refused while archive offline: %v", err)
	}
}

func TestLocalContinuityRefusesApplyingStateWithLostPendingPointer(t *testing.T) {
	s, f := activatedFixture(t)
	standard := model.AuditPolicy{Profile: "standard", RuntimeSeconds: 3600, RetentionHours: 24}
	change, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &standard})
	if err != nil {
		t.Fatal(err)
	}
	f.change = change
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	f.evidence.fail = auditrecord.PolicyCommit
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("commit fault did not interrupt disable")
	}
	if _, err := s.Store.DB().Exec("UPDATE audit_policy_state SET pending_version=NULL WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(s.Store).PolicyForExecution("requester", "node"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("inconsistent applying state admitted covered execution: %v", err)
	}
	if err := New(s.Store).GuardInteractive("requester", "node"); !errors.Is(err, ErrRecovery) {
		t.Fatalf("inconsistent applying state admitted a shell: %v", err)
	}
	if _, err := s.Store.DB().Exec("UPDATE audit_policy_state SET pending_version=3 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if policy, err := New(s.Store).PolicyForExecution("requester", "node"); !errors.Is(err, ErrTransition) || !policy.Enhanced {
		t.Fatalf("exact pending pointer repair lost strict transition enforcement: %+v %v", policy, err)
	}
}

func TestLocalContinuityRejectsInconsistentReadablePolicySnapshots(t *testing.T) {
	s, f := activatedFixture(t)
	stable, err := s.Store.GetPolicyState()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"standard", "setup_pending", "applying", "unknown"} {
		state := stable
		state.State = phase
		if err := s.Store.ValidateExecutionPolicy(state); !errors.Is(err, ErrRecovery) {
			t.Errorf("Enhanced snapshot accepted inconsistent stable phase %s: %v", phase, err)
		}
	}
	state := stable
	state.Previous = &stable.Active
	if err := s.Store.ValidateExecutionPolicy(state); !errors.Is(err, ErrRecovery) {
		t.Fatalf("nonpending snapshot accepted unexpected previous policy: %v", err)
	}
	state = stable
	state.State = "recovery_required"
	if err := s.Store.ValidateExecutionPolicy(state); err != nil {
		t.Fatalf("valid recovery state could not be inspected: %v", err)
	}
	standard := model.AuditPolicy{Profile: "standard", RuntimeSeconds: 3600, RetentionHours: 24}
	change, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &standard})
	if err != nil {
		t.Fatal(err)
	}
	f.change = change
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	f.evidence.fail = auditrecord.PolicyCommit
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("commit failure did not leave a pending snapshot")
	}
	pending, err := s.Store.GetPolicyState()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"standard", "enhanced", "setup_pending", "unknown"} {
		state := pending
		state.State = phase
		if err := s.Store.ValidateExecutionPolicy(state); !errors.Is(err, ErrRecovery) {
			t.Errorf("pending snapshot accepted phase %s: %v", phase, err)
		}
	}
	state = pending
	state.State = "recovery_required"
	if err := s.Store.ValidateExecutionPolicy(state); err != nil {
		t.Fatalf("known pending recovery snapshot rejected: %v", err)
	}
}

func TestStoredPolicyIntegrityBlocksPendingReconciliationUntilExactRepair(t *testing.T) {
	for _, boundary := range []string{auditrecord.PolicyCommit, auditrecord.PolicyResult} {
		for _, corruption := range []string{"profile_downgrade", "scope_reduction", "digest_removal", "same_policy_different_bytes"} {
			t.Run(boundary+"/"+corruption, func(t *testing.T) {
				s, f := fixtureGovernance(t)
				approveFixture(t, s, f, "approver-one")
				approveFixture(t, s, f, "approver-two")
				f.evidence.fail = boundary
				if err := applyFixture(t, s, f); err == nil {
					t.Fatal("archive fault did not leave a pending transition")
				}
				before, err := s.Store.GetPolicyState()
				if err != nil || before.Pending == nil {
					t.Fatalf("missing durable pending transition: %+v %v", before, err)
				}
				var original []byte
				if err := s.Store.DB().QueryRow("SELECT payload FROM audit_policy_versions WHERE version=2").Scan(&original); err != nil {
					t.Fatal(err)
				}
				policy := before.Pending.Policy
				digest := before.Pending.SHA256
				switch corruption {
				case "profile_downgrade":
					policy = model.AuditPolicy{Profile: "standard"}
				case "scope_reduction":
					policy.Nodes = []string{"unrelated-node"}
				case "digest_removal":
					digest = ""
				}
				raw, err := json.Marshal(policy)
				if err != nil {
					t.Fatal(err)
				}
				if corruption == "same_policy_different_bytes" {
					raw = append(original, ' ')
				}
				if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=2", raw, digest); err != nil {
					t.Fatal(err)
				}
				f.evidence.fail = ""
				records := len(f.evidence.records)
				requester, err := s.Store.GetUserByID("requester")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.ReconcileChange(context.Background(), f.change.ID, f.config); !errors.Is(err, ErrRecovery) {
					t.Fatalf("pending corruption reached reconciliation: %v", err)
				}
				if _, err := s.PolicyForExecution("requester", "node"); !errors.Is(err, store.ErrPolicyIntegrity) {
					t.Fatalf("pending corruption admitted execution: %v", err)
				}
				if !errors.Is(s.GuardInteractive("requester", "node"), store.ErrPolicyIntegrity) {
					t.Fatal("pending corruption admitted an interactive shell")
				}
				var active uint64
				var state string
				if err := s.Store.DB().QueryRow("SELECT active_version,state FROM audit_policy_state WHERE id=1").Scan(&active, &state); err != nil {
					t.Fatal(err)
				}
				current, err := s.Store.GetUserByID("requester")
				if err != nil || current.SecurityRevision != requester.SecurityRevision || current.TokenGeneration != requester.TokenGeneration || active != before.Active.Version || state != before.State || len(f.evidence.records) != records {
					t.Fatalf("corruption caused a reconciliation side effect: active=%d state=%s records=%d user=%+v err=%v", active, state, len(f.evidence.records), current, err)
				}
				if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=2", original, before.Pending.SHA256); err != nil {
					t.Fatal(err)
				}
				if _, err := s.ReconcileChange(context.Background(), f.change.ID, f.config); err != nil {
					t.Fatalf("exact pending repair could not reconcile: %v", err)
				}
				if state, err := s.Store.GetPolicyState(); err != nil || state.State != "enhanced" || state.Active.Version != 2 || state.Pending != nil || len(f.evidence.records) != 4 {
					t.Fatalf("exact repair lost the approved transition: %+v %v", state, err)
				}
			})
		}
	}
}

func TestStoredPolicyHistoryCannotEraseGovernanceAfterApprovedDisable(t *testing.T) {
	s, f := activatedFixture(t)
	var enrolledRaw []byte
	if err := s.Store.DB().QueryRow("SELECT payload FROM audit_policy_versions WHERE version=2").Scan(&enrolledRaw); err != nil {
		t.Fatal(err)
	}
	policy := model.AuditPolicy{Profile: "standard", RuntimeSeconds: 3600, RetentionHours: 24}
	change, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	f.change = change
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	if err := applyFixture(t, s, f); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateAnchor(context.Background(), f.config); err != nil {
		t.Fatalf("legitimate Standard disable rejected: %v", err)
	}
	if enrolled, err := s.Store.GovernanceEnrolled(); err != nil || !enrolled {
		t.Fatalf("approved disable lost governance: %v %v", enrolled, err)
	}
	settings := s.Store.GetAuditSettings()
	settings.RetentionDays++
	if err := s.Store.UpdateAuditSettings(settings); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("approved disable reopened legacy settings mutation: %v", err)
	}
	if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=? WHERE version=2", []byte(`{"profile":"standard"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.GetPolicyVersion(2); !errors.Is(err, store.ErrPolicyIntegrity) {
		t.Fatalf("historical original destination accepted modified bytes: %v", err)
	}
	if enrolled, err := s.Store.GovernanceEnrolled(); !errors.Is(err, store.ErrPolicyIntegrity) || enrolled {
		t.Fatalf("corrupted history erased enrollment: %v %v", enrolled, err)
	}
	if err := s.Store.UpdateAuditSettings(settings); !errors.Is(err, store.ErrPolicyIntegrity) {
		t.Fatalf("corrupted history reopened legacy settings mutation: %v", err)
	}
	if got := s.Store.GetAuditSettings(); got.RetentionDays == settings.RetentionDays {
		t.Fatal("refused settings mutation changed retention")
	}
	if err := s.ValidateAnchor(context.Background(), f.config); !errors.Is(err, store.ErrPolicyIntegrity) {
		t.Fatalf("external continuity ignored corrupted history: %v", err)
	}
	if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=? WHERE version=2", enrolledRaw); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateAnchor(context.Background(), f.config); err != nil {
		t.Fatalf("exact history repair rejected: %v", err)
	}
	if enrolled, err := s.Store.GovernanceEnrolled(); err != nil || !enrolled {
		t.Fatalf("exact history repair lost enrollment: %v %v", enrolled, err)
	}
	if err := s.Store.UpdateAuditSettings(settings); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("exact history repair did not restore protected settings: %v", err)
	}
}
