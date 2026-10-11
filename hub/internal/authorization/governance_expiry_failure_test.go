package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestBootstrapExpiryCannotPartiallyReleaseNominatedPrincipals(t *testing.T) {
	for _, approvals := range []int{0, 1, 2} {
		for _, fault := range []struct{ name, trigger string }{
			{"request_expiration", "BEFORE UPDATE ON security_changes WHEN NEW.state='expired'"},
			{"nomination_thaw", "BEFORE UPDATE ON audit_policy_state WHEN OLD.state='setup_pending' AND NEW.state='standard'"},
		} {
			t.Run(fault.name+"/"+[]string{"requested", "partially_approved", "approved"}[approvals], func(t *testing.T) {
				s, f := fixtureGovernance(t)
				for _, user := range []string{"approver-one", "approver-two"}[:approvals] {
					approveFixture(t, s, f, user)
				}
				before, err := s.Store.GetSecurityChange(f.change.ID)
				if err != nil {
					t.Fatal(err)
				}
				expires := before.ExpiresAt
				s.Now = func() time.Time { return expires }
				if _, err := s.Store.DB().Exec("CREATE TRIGGER expiry_fault " + fault.trigger + " BEGIN SELECT RAISE(ABORT,'injected expiration write failure'); END"); err != nil {
					t.Fatal(err)
				}
				if err := s.Store.ExpireSecurityChanges(expires); err == nil {
					t.Fatal("failed expiration write released a bootstrap freeze")
				}
				current, err := s.Store.GetSecurityChange(before.ID)
				state, stateErr := s.Store.GetPolicyState()
				if err != nil || stateErr != nil || current.State != before.State || len(current.Approvals) != approvals || state.State != "setup_pending" || state.Active.Version != 1 || state.Pending != nil {
					t.Fatalf("expiration failure published partial state: request%s policy%s errors%v/%v", current.State, state.State, err, stateErr)
				}
				for _, user := range []string{"requester", "approver-one", "approver-two"} {
					if err := s.Store.GuardSecurityUserMutation(user); !errors.Is(err, store.ErrProtectedChange) {
						t.Fatalf("expiration failure released nominated principal %s: %v", user, err)
					}
				}
				proof, err := s.Store.IssueStepup("approver-two", "session-approver-two", ActionApprove, before.Digest, expires)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.Approve(before.ID, "approver-two", "session-approver-two", proof); err == nil {
					t.Fatal("fresh MFA revived an expired request while the sweep was unavailable")
				}
				if err := applyFixture(t, s, f); err == nil || len(f.evidence.records) != 0 {
					t.Fatal("expired request published external application authority")
				}
				if _, err := s.Store.DB().Exec("DROP TRIGGER expiry_fault"); err != nil {
					t.Fatal(err)
				}
				if err := s.Store.ExpireSecurityChanges(expires); err != nil {
					t.Fatal(err)
				}
				current, err = s.Store.GetSecurityChange(before.ID)
				state, stateErr = s.Store.GetPolicyState()
				if err != nil || stateErr != nil || current.State != "expired" || len(current.Approvals) != approvals || current.Digest != before.Digest || state.State != "standard" || state.Active.Version != 1 {
					t.Fatalf("completed expiry erased history or changed active policy: request%s policy%s errors%v/%v", current.State, state.State, err, stateErr)
				}
				for _, user := range []string{"requester", "approver-one", "approver-two"} {
					if err := s.Store.GuardSecurityUserMutation(user); err != nil {
						t.Fatalf("completed initial expiry retained an unfinished nomination freeze: %v", err)
					}
				}
				if err := s.Store.ExpireSecurityChanges(expires.Add(time.Hour)); err != nil {
					t.Fatalf("expiry retry was not idempotent: %v", err)
				}
			})
		}
	}
}

func TestExpiryDoesNotReleaseAnAlreadyApplyingBootstrap(t *testing.T) {
	s, f := fixtureGovernance(t)
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	f.evidence.fail = auditrecord.PolicyCommit
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("injected commit outage did not leave an applying transition")
	}
	before, err := s.Store.GetSecurityChange(f.change.ID)
	if err != nil || before.State != "applying" {
		t.Fatalf("fixture did not begin one durable transition: %s %v", before.State, err)
	}
	expires := before.ExpiresAt.Add(time.Hour)
	s.Now = func() time.Time { return expires }
	if err := s.Store.ExpireSecurityChanges(expires); err != nil {
		t.Fatal(err)
	}
	state, err := s.Store.GetPolicyState()
	if err != nil || state.State != "applying" || state.PendingChange != before.ID || state.Active.Version != 1 || state.Pending == nil {
		t.Fatalf("expiry swept an unresolved durable transition: %+v %v", state, err)
	}
	for _, user := range []string{"requester", "approver-one", "approver-two"} {
		if err := s.Store.GuardSecurityUserMutation(user); !errors.Is(err, store.ErrProtectedChange) {
			t.Fatalf("expiry released an applying nomination: %s %v", user, err)
		}
	}
	if _, err := s.PolicyForExecution("requester", "node"); !errors.Is(err, ErrTransition) {
		t.Fatalf("expiry reopened execution during unresolved application: %v", err)
	}
	f.evidence.fail = ""
	if _, err := s.ReconcileChange(context.Background(), before.ID, f.config); err != nil {
		t.Fatalf("exact transition recovery lost its committed authorization boundary: %v", err)
	}
	current, err := s.Store.GetSecurityChange(before.ID)
	if err != nil || current.State != "applied" || current.Digest != before.Digest || len(f.evidence.records) != 4 {
		t.Fatalf("recovery changed the approved request or external records: %s %v", current.State, err)
	}
}
