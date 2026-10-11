package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestActiveGovernanceAnchorMustMatchExactCommittedChange(t *testing.T) {
	for _, mismatch := range []struct {
		name   string
		change func(*PolicyAnchor)
	}{
		{"installation", func(a *PolicyAnchor) { a.InstallationID = "different-installation" }},
		{"older_version", func(a *PolicyAnchor) { a.Version-- }},
		{"newer_version", func(a *PolicyAnchor) { a.Version++ }},
		{"policy_digest", func(a *PolicyAnchor) { a.SHA256 = Digest([]byte("different-policy")) }},
		{"request_id", func(a *PolicyAnchor) { a.RequestID = "different-request" }},
		{"request_digest", func(a *PolicyAnchor) { a.RequestSHA256 = Digest([]byte("different-approved-change")) }},
	} {
		t.Run(mismatch.name, func(t *testing.T) {
			s, f := activatedFixture(t)
			before, err := s.Store.GetPolicyState()
			if err != nil {
				t.Fatal(err)
			}
			mismatch.change(&f.evidence.anchor)
			if err := s.ValidateAnchor(context.Background(), f.config); !errors.Is(err, ErrRecovery) {
				t.Errorf("mismatched committed governance anchor was trusted: %v", err)
			}
			after, err := s.Store.GetPolicyState()
			if err != nil || after.State != before.State || after.Active.Version != before.Active.Version || after.Pending != nil {
				t.Fatalf("read-only anchor validation mutated policy: %+v %v", after, err)
			}
		})
	}
}

func TestActiveGovernanceAnchorTracksRoleAndPersonChangesWithUnchangedPolicy(t *testing.T) {
	for _, payload := range []model.SecurityChangePayload{
		{Kind: "role", Role: &model.SecurityRoleChange{UserID: "other-admin", Role: model.RoleOriginalReader, Grant: true}},
		{Kind: "person", Person: &model.SecurityPersonChange{UserID: "other-admin", PersonID: "verified-other-person", Verification: "Independent synthetic identity verification"}},
	} {
		t.Run(payload.Kind, func(t *testing.T) {
			s, f := activatedFixture(t)
			previous := f.evidence.anchor
			change, err := protectedChange(t, s, payload)
			if err != nil {
				t.Fatal(err)
			}
			f.change = change
			approveFixture(t, s, f, "approver-one")
			approveFixture(t, s, f, "approver-two")
			if err := applyFixture(t, s, f); err != nil {
				t.Fatal(err)
			}
			committed := f.evidence.anchor
			if committed.SHA256 != previous.SHA256 || committed.Version != previous.Version+1 || committed.RequestID != change.ID || committed.RequestSHA256 != change.Digest {
				t.Fatalf("security mutation did not retain policy fields and bind its exact approval: %+v", committed)
			}
			if err := s.ValidateAnchor(context.Background(), f.config); err != nil {
				t.Fatalf("exact new governance anchor rejected: %v", err)
			}
			// Matching current policy fields cannot substitute another change's
			// approvals, even when the original destination and scope are equal.
			f.evidence.anchor.RequestID = previous.RequestID
			f.evidence.anchor.RequestSHA256 = previous.RequestSHA256
			if err := s.ValidateAnchor(context.Background(), f.config); !errors.Is(err, ErrRecovery) {
				t.Fatalf("previous change substituted at current policy version: %v", err)
			}
			f.evidence.anchor = previous
			if err := s.Startup(context.Background(), f.config); !errors.Is(err, ErrRecovery) {
				t.Fatalf("old external anchor reopened restored policy: %v", err)
			}
			if _, err := s.PolicyForExecution("requester", "node"); !errors.Is(err, ErrRecovery) {
				t.Fatalf("anchor rollback did not freeze execution: %v", err)
			}
		})
	}
}

func TestEnrollmentMarkerRejectsRestoredIdentityVersionAndUntrustedFile(t *testing.T) {
	restoreMarker := func(t *testing.T, path string, marker EnrollmentMarker) {
		t.Helper()
		raw, err := json.Marshal(marker)
		if err != nil {
			t.Fatal(err)
		}
		// Model an out-of-band restored or corrupted file, bypassing the writer
		// that correctly refuses non-monotonic replacements.
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, mismatch := range []struct {
		name   string
		change func(*testing.T, authorizationFixture, model.PolicyState)
	}{
		{"installation", func(t *testing.T, f authorizationFixture, p model.PolicyState) {
			restoreMarker(t, f.config.EnrollmentPath, EnrollmentMarker{"different-installation", p.Active.Version, p.Active.SHA256})
		}},
		{"older_version", func(t *testing.T, f authorizationFixture, p model.PolicyState) {
			restoreMarker(t, f.config.EnrollmentPath, EnrollmentMarker{f.config.InstallationID, p.Active.Version - 1, p.Active.SHA256})
		}},
		{"wrong_digest", func(t *testing.T, f authorizationFixture, p model.PolicyState) {
			restoreMarker(t, f.config.EnrollmentPath, EnrollmentMarker{f.config.InstallationID, p.Active.Version, Digest([]byte("other-marker-policy"))})
		}},
		{"public_permissions", func(t *testing.T, f authorizationFixture, _ model.PolicyState) {
			if err := os.Chmod(f.config.EnrollmentPath, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"duplicate_identity", func(t *testing.T, f authorizationFixture, _ model.PolicyState) {
			if err := os.WriteFile(f.config.EnrollmentPath, []byte(`{"installation_id":"one","installation_id":"two","version":2}`), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized_marker", func(t *testing.T, f authorizationFixture, _ model.PolicyState) {
			if err := os.WriteFile(f.config.EnrollmentPath, make([]byte, 8193), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(mismatch.name, func(t *testing.T) {
			s, f := activatedFixture(t)
			state, err := s.Store.GetPolicyState()
			if err != nil {
				t.Fatal(err)
			}
			mismatch.change(t, f, state)
			if EnrollmentMarkerMatches(f.config, state) {
				t.Error("restored or untrusted marker was reported ready")
			}
			if err := s.Startup(context.Background(), f.config); !errors.Is(err, ErrRecovery) {
				t.Fatalf("startup accepted untrusted enrollment marker: %v", err)
			}
			if _, err := s.PolicyForExecution("requester", "node"); !errors.Is(err, ErrRecovery) {
				t.Fatalf("marker failure reopened execution: %v", err)
			}
		})
	}
}
