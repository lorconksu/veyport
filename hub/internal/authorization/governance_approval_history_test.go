package authorization

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestUnchangedPolicyRevisionsRequireTheirExactAppliedApprovalHistory(t *testing.T) {
	for _, corruption := range []struct {
		name   string
		modify func(*testing.T, *Service, model.SecurityChange)
	}{
		{"missing_request_binding", func(t *testing.T, s *Service, c model.SecurityChange) {
			t.Helper()
			if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET request_id='absent-approved-change' WHERE version=?", c.ExpectedVersion+1); err != nil {
				t.Fatal(err)
			}
		}},
		{"unapplied_predecessor", func(t *testing.T, s *Service, c model.SecurityChange) {
			t.Helper()
			if _, err := s.Store.DB().Exec("UPDATE security_changes SET state='approved' WHERE id=?", c.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed_reason_snapshot", func(t *testing.T, s *Service, c model.SecurityChange) {
			t.Helper()
			if _, err := s.Store.DB().Exec("UPDATE security_changes SET reason='Unapproved substituted reason' WHERE id=?", c.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{"rehashed_reason", func(t *testing.T, s *Service, c model.SecurityChange) {
			rewriteApprovedHistory(t, s, c, func(proposal map[string]any) { proposal["reason"] = "Different immutable approval reason" })
		}},
		{"rehashed_expected_version", func(t *testing.T, s *Service, c model.SecurityChange) {
			rewriteApprovedHistory(t, s, c, func(proposal map[string]any) { proposal["expected_version"] = c.ExpectedVersion + 1 })
		}},
		{"rehashed_unknown_field", func(t *testing.T, s *Service, c model.SecurityChange) {
			rewriteApprovedHistory(t, s, c, func(proposal map[string]any) { proposal["unapproved_override"] = true })
		}},
		{"rehashed_invalid_typed_change", func(t *testing.T, s *Service, c model.SecurityChange) {
			rewriteApprovedHistory(t, s, c, func(proposal map[string]any) { proposal["change"] = map[string]any{"kind": "recovery"} })
		}},
		{"different_predecessor_policy", func(t *testing.T, s *Service, c model.SecurityChange) {
			t.Helper()
			previous, err := s.Store.GetPolicyVersion(c.ExpectedVersion)
			if err != nil {
				t.Fatal(err)
			}
			previous.Policy.Nodes = []string{"unrelated-node"}
			raw, err := json.Marshal(previous.Policy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=?", raw, Digest(raw), c.ExpectedVersion); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(corruption.name, func(t *testing.T) {
			s, f := activatedFixture(t)
			initial, err := s.Store.GetPolicyState()
			if err != nil {
				t.Fatal(err)
			}
			scoped := initial.Active.Policy
			scoped.Nodes = []string{"node"}
			policy, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &scoped})
			if err != nil {
				t.Fatal(err)
			}
			f.change = policy
			approveFixture(t, s, f, "approver-one")
			approveFixture(t, s, f, "approver-two")
			if err := applyFixture(t, s, f); err != nil {
				t.Fatal(err)
			}
			role, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "role", Role: &model.SecurityRoleChange{UserID: "other-admin", Role: model.RoleOriginalReader, Grant: true}})
			if err != nil {
				t.Fatal(err)
			}
			f.change = role
			approveFixture(t, s, f, "approver-one")
			approveFixture(t, s, f, "approver-two")
			if err := applyFixture(t, s, f); err != nil {
				t.Fatal(err)
			}
			person, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "person", Person: &model.SecurityPersonChange{UserID: "other-admin", PersonID: "independently-reverified-person", Verification: "Synthetic independent identity verification"}})
			if err != nil {
				t.Fatal(err)
			}
			f.change = person
			approveFixture(t, s, f, "approver-one")
			approveFixture(t, s, f, "approver-two")
			if err := applyFixture(t, s, f); err != nil {
				t.Fatal(err)
			}
			before, err := s.PolicyForExecution("requester", "node")
			if err != nil || !before.Enhanced || before.Version != 5 {
				t.Fatalf("valid inherited policy did not authenticate its history: %+v %v", before, err)
			}
			if outside, err := s.PolicyForExecution("requester", "uncovered-node"); err != nil || outside.Enhanced {
				t.Fatalf("fixture did not provide a legitimate uncovered route: %+v %v", outside, err)
			}
			// Restore the exact bytes after each out-of-band corruption. A local
			// admission check must consult neither archive availability nor mutate
			// the policy while refusing an inconsistent approval chain.
			var approved []byte
			var reason, state, policyRequest string
			var policyRaw []byte
			var policySHA string
			if err := s.Store.DB().QueryRow("SELECT payload,reason,state FROM security_changes WHERE id=?", role.ID).Scan(&approved, &reason, &state); err != nil {
				t.Fatal(err)
			}
			if err := s.Store.DB().QueryRow("SELECT payload,digest,request_id FROM audit_policy_versions WHERE version=?", role.ExpectedVersion).Scan(&policyRaw, &policySHA, &policyRequest); err != nil {
				t.Fatal(err)
			}
			corruption.modify(t, s, role)
			f.evidence.anchorErr = errors.New("independent archive offline")
			events := len(f.evidence.records)
			if _, err := New(s.Store).PolicyForExecution("requester", "uncovered-node"); !errors.Is(err, ErrRecovery) {
				t.Fatalf("inconsistent approved history supplied out-of-scope routing: %v", err)
			}
			if err := s.GuardInteractive("requester", "uncovered-node"); !errors.Is(err, ErrRecovery) {
				t.Fatalf("inconsistent approved history admitted an uncovered shell: %v", err)
			}
			if len(f.evidence.records) != events {
				t.Fatal("local approval-chain validation wrote external evidence")
			}
			if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET request_id=? WHERE version=?", role.ID, role.ExpectedVersion+1); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Store.DB().Exec("UPDATE security_changes SET payload=?,digest=?,reason=?,state=? WHERE id=?", approved, Digest(approved), reason, state, role.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=?,request_id=? WHERE version=?", policyRaw, policySHA, policyRequest, role.ExpectedVersion); err != nil {
				t.Fatal(err)
			}
			if repaired, err := New(s.Store).PolicyForExecution("requester", "node"); err != nil || repaired != before {
				t.Fatalf("exact history repair did not restore local policy continuity: %+v %v", repaired, err)
			}
		})
	}
}

func rewriteApprovedHistory(t *testing.T, s *Service, c model.SecurityChange, change func(map[string]any)) {
	t.Helper()
	var proposal map[string]any
	if err := json.Unmarshal(c.ApprovedBytes, &proposal); err != nil {
		t.Fatal(err)
	}
	change(proposal)
	raw, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB().Exec("UPDATE security_changes SET payload=?,digest=? WHERE id=?", raw, Digest(raw), c.ID); err != nil {
		t.Fatal(err)
	}
}
