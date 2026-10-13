package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// Stop after preservation, where the submitted intent is durable but the local
// writer transaction has not yet revalidated or installed its candidate.
type intentRevalidationBarrier struct {
	*fakeEvidence
	requestID string
	entered   chan struct{}
	release   chan struct{}
}

func (b *intentRevalidationBarrier) Preserve(ctx context.Context, raw []byte) (string, error) {
	reference, err := b.fakeEvidence.Preserve(ctx, raw)
	if err != nil {
		return "", err
	}
	_, event, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return "", err
	}
	if event.EventType == auditrecord.PolicyIntent && event.Details.RequestID == b.requestID {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return reference, nil
}

func TestGovernanceIntentRevalidatesRequestAndDistinctApplierBeforePendingInstall(t *testing.T) {
	for _, mutation := range []string{"requester_suspended", "applier_suspended", "request_expires", "approved_bytes_edited"} {
		t.Run(mutation, func(t *testing.T) {
			s, f := activatedFixture(t)
			grant, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "role", Role: &model.SecurityRoleChange{UserID: "other-admin", Role: model.RoleSecurityOfficer, Grant: true}})
			if err != nil {
				t.Fatal(err)
			}
			f.change = grant
			approveFixture(t, s, f, "approver-one")
			approveFixture(t, s, f, "approver-two")
			if err := applyFixture(t, s, f); err != nil {
				t.Fatal(err)
			}
			before, err := s.Store.GetPolicyState()
			if err != nil {
				t.Fatal(err)
			}
			candidate := before.Active.Policy
			candidate.RuntimeSeconds /= 2
			change, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &candidate})
			if err != nil {
				t.Fatal(err)
			}
			f.change = change
			approveFixture(t, s, f, "approver-one")
			approveFixture(t, s, f, "approver-two")
			marker, err := os.ReadFile(f.config.EnrollmentPath)
			if err != nil {
				t.Fatal(err)
			}
			preserved := len(f.evidence.records)
			claimedAt := s.Now()
			var clock atomic.Int64
			clock.Store(claimedAt.Unix())
			s.Now = func() time.Time { return time.Unix(clock.Load(), 0).UTC() }
			proof, err := s.Store.IssueStepup("other-admin", "session-other-admin", ActionApply, change.Digest, claimedAt)
			if err != nil {
				t.Fatal(err)
			}
			barrier := &intentRevalidationBarrier{fakeEvidence: f.evidence, requestID: change.ID, entered: make(chan struct{}), release: make(chan struct{})}
			cfg := f.config
			cfg.Evidence = barrier
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var release sync.Once
			defer release.Do(func() { close(barrier.release) })
			finished := make(chan error, 1)
			go func() {
				_, err := s.Apply(ctx, change.ID, "other-admin", "session-other-admin", proof, cfg)
				finished <- err
			}()
			select {
			case <-barrier.entered:
			case <-ctx.Done():
				t.Fatal("application did not reach the preserved-intent boundary")
			}
			// Prove the proof was spent before I/O, rather than rejected later
			// solely because the test moves beyond its five-minute lifetime.
			var consumed int64
			if err := s.Store.DB().QueryRow("SELECT consumed_at FROM stepup_proofs WHERE hash=?", Digest([]byte(proof))).Scan(&consumed); err != nil || consumed != claimedAt.Unix() {
				t.Fatalf("applier claim was not durable before intent I/O: %d %v", consumed, err)
			}
			switch mutation {
			case "requester_suspended":
				_, err = s.Store.DisableUser("requester", "other-admin", s.Now())
			case "applier_suspended":
				_, err = s.Store.DisableUser("other-admin", "requester", s.Now())
			case "request_expires":
				clock.Store(change.ExpiresAt.Unix())
			case "approved_bytes_edited":
				var proposal Proposal
				if err = json.Unmarshal(change.ApprovedBytes, &proposal); err == nil {
					proposal.Reason = "Unapproved edit while the exact intent was being preserved"
					var raw []byte
					raw, err = json.Marshal(proposal)
					if err == nil {
						_, err = s.Store.DB().Exec("UPDATE security_changes SET payload=? WHERE id=?", raw, change.ID)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			release.Do(func() { close(barrier.release) })
			select {
			case err := <-finished:
				if !errors.Is(err, store.ErrSecurityConflict) {
					t.Fatalf("changed live authority/request reached pending installation: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("application did not finish after intent I/O")
			}
			state, err := s.Store.GetPolicyState()
			if err != nil || state.State != "enhanced" || state.Active.Version != before.Active.Version || state.Active.SHA256 != before.Active.SHA256 || state.Pending != nil || state.PendingChange != "" {
				t.Fatalf("refused intent installed a policy: %+v %v", state, err)
			}
			var versions int
			if err := s.Store.DB().QueryRow("SELECT COUNT(*) FROM audit_policy_versions").Scan(&versions); err != nil || uint64(versions) != before.Active.Version {
				t.Fatalf("refused intent left an orphan candidate: %d %v", versions, err)
			}
			current, err := s.Store.GetSecurityChange(change.ID)
			if err != nil || current.State != "approved" || current.IntentRef != "" || current.CommitRef != "" || current.ResultRef != "" || current.ApplierID != "other-admin" || len(current.Approvals) != 2 {
				t.Fatalf("refused intent falsely advanced the approved request: %+v %v", current, err)
			}
			if err := s.Store.ConsumeStepup(proof, "other-admin", "session-other-admin", ActionApply, change.Digest, claimedAt); !errors.Is(err, store.ErrStepup) {
				t.Fatalf("refused application restored its claimed proof: %v", err)
			}
			afterMarker, err := os.ReadFile(cfg.EnrollmentPath)
			if err != nil || !bytes.Equal(marker, afterMarker) || len(f.evidence.records) != preserved+1 {
				t.Fatalf("refused pending install advanced the external anchor/marker: %v", err)
			}
			raw := f.evidence.records[change.ID+"-"+auditrecord.PolicyIntent]
			_, event, err := auditrecord.ExpectedFor(raw)
			if err != nil || event.Actor.UserID != "other-admin" || event.Details.Requester.UserID != "requester" || !bytes.Equal(event.Details.ApprovedChange, change.ApprovedBytes) || len(event.Details.Approvals) != 2 {
				t.Fatalf("preserved intent lost the exact request and distinct applier: %v", err)
			}
		})
	}
}
