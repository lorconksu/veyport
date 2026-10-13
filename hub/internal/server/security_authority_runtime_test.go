package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestGovernanceHTTPApprovedAuthorityChangesInvalidateEarlierVotesAndProofs(t *testing.T) {
	for _, mutation := range []struct {
		name    string
		payload model.SecurityChangePayload
	}{
		{"role_grant", model.SecurityChangePayload{Kind: "role", Role: &model.SecurityRoleChange{UserID: "approver-a", Role: model.RoleOriginalReader, Grant: true}}},
		{"role_revoke", model.SecurityChangePayload{Kind: "role", Role: &model.SecurityRoleChange{UserID: "approver-a", Role: model.RoleSecurityApprover, Grant: false}}},
		{"person_relink", model.SecurityChangePayload{Kind: "person", Person: &model.SecurityPersonChange{UserID: "approver-a", PersonID: "synthetic-reverified-person-a", Verification: "Independent synthetic identity re-verification"}}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			h := newGovernanceHTTP(t)
			h.apply(t, h.approve(t, h.request(t, h.bootstrapPayload(), 1)), 200)
			stagedRole := model.SecurityRoleChange{UserID: "viewer", Role: model.RoleOriginalReader, Grant: true}
			if mutation.name == "role_revoke" {
				stagedRole = model.SecurityRoleChange{UserID: "approver-b", Role: model.RoleSecurityApprover, Grant: false}
			}
			staged := h.approve(t, h.request(t, model.SecurityChangePayload{Kind: "role", Role: &stagedRole}, 2))
			claims, err := auth.ValidateToken(h.s.jwtSecret, h.tokens["approver-a"])
			if err != nil || claims.SessionID == "" {
				t.Fatalf("real approver session unavailable: %v", err)
			}
			proofAt := h.clock.Now().Add(30 * time.Second)
			unspent := h.stepup(t, "approver-a", authorization.ActionApprove, staged.Digest, staged.ID)
			change := h.approve(t, h.request(t, mutation.payload, 2))
			h.apply(t, change, 200)
			if !h.clock.Now().Before(proofAt.Add(5 * time.Minute)) {
				t.Fatal("test proof aged out instead of testing authority invalidation")
			}
			if err := h.s.store.ConsumeStepup(unspent, "approver-a", claims.SessionID, authorization.ActionApprove, staged.Digest, h.clock.Now()); !errors.Is(err, store.ErrStepup) {
				t.Fatalf("authority change retained unspent recent-MFA proof: %v", err)
			}
			h.call(t, "GET", "/api/security/changes/"+staged.ID, "approver-a", nil, http.StatusUnauthorized)
			var current model.SecurityChange
			decodeResult(t, h.call(t, "GET", "/api/security/changes/"+staged.ID, "officer", nil, 200), &current)
			invalidated := false
			for _, approval := range current.Approvals {
				if approval.UserID == "approver-a" {
					invalidated = approval.InvalidatedAt != nil
				}
			}
			if !invalidated || len(current.Approvals) != 2 {
				t.Fatalf("API did not preserve and distinguish the revoked vote: %+v", current.Approvals)
			}
			stored, err := h.s.store.GetSecurityChange(staged.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.s.securityService().ValidateQuorum(stored); !errors.Is(err, authorization.ErrIndependent) {
				t.Fatalf("authority-invalidated approval still formed quorum: %v", err)
			}
			h.apply(t, staged, http.StatusForbidden)
			effective, err := h.s.securityService().Effective(stagedRole.UserID)
			if err != nil || effective.HasRole(stagedRole.Role) == stagedRole.Grant {
				t.Fatalf("revoked quorum applied the staged grant/revoke: %+v %v", effective, err)
			}
			state, err := h.s.store.GetPolicyState()
			if err != nil || state.Active.Version != 3 || state.Pending != nil {
				t.Fatalf("refused stale application changed active policy: %+v %v", state, err)
			}
			for _, envelope := range h.archive.Governance.Envelopes() {
				if envelope.Details != nil && envelope.Details.RequestID == staged.ID {
					t.Fatal("invalidated quorum reached the external application archive")
				}
			}
		})
	}
}

// The barrier pauses after the real scoped mTLS service durably preserves an
// event. It exercises revocation during external I/O without fake receipts.
type governancePreservationBarrier struct {
	*authorization.ReceiptEvidence
	kind    string
	blocked atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (b *governancePreservationBarrier) Preserve(ctx context.Context, raw []byte) (string, error) {
	reference, err := b.ReceiptEvidence.Preserve(ctx, raw)
	if err != nil {
		return "", err
	}
	_, envelope, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return "", err
	}
	if envelope.EventType == b.kind && b.blocked.CompareAndSwap(false, true) {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return reference, nil
}

func TestGovernanceHTTPSettingsRevocationBeforeAndAfterActivationCommit(t *testing.T) {
	for _, boundary := range []string{auditrecord.PolicyIntent, auditrecord.PolicyCommit, auditrecord.PolicyAnchor, auditrecord.PolicyResult} {
		t.Run(boundary, func(t *testing.T) {
			h := newGovernanceHTTP(t)
			h.apply(t, h.approve(t, h.request(t, h.bootstrapPayload(), 1)), 200)
			old := h.s.store.GetAuditSettings()
			settings := old
			settings.RetentionDays++
			settings.Thresholds.PrivilegedActionsPerHour++
			change := h.approve(t, h.request(t, model.SecurityChangePayload{Kind: "audit-settings", AuditSettings: &settings}, 2))
			barrier := &governancePreservationBarrier{ReceiptEvidence: h.runtime.Evidence(), kind: boundary, entered: make(chan struct{}), release: make(chan struct{})}
			h.s.securityTransition.Evidence = barrier
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(barrier.release) }) })
			proof := h.stepup(t, "officer", authorization.ActionApply, change.Digest, change.ID)
			request, err := http.NewRequest("POST", h.api.URL+"/api/security/changes/"+change.ID+"/apply", bytes.NewReader(mustMarshal(t, map[string]string{"step_up_proof": proof})))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+h.tokens["officer"])
			request.Header.Set("Content-Type", "application/json")
			type result struct {
				status int
				err    error
			}
			finished := make(chan result, 1)
			go func() {
				response, err := h.clients["officer"].Do(request)
				if err != nil {
					finished <- result{err: err}
					return
				}
				defer response.Body.Close()
				_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 256<<10))
				finished <- result{status: response.StatusCode, err: err}
			}()
			select {
			case <-barrier.entered:
			case <-time.After(10 * time.Second):
				t.Fatal("application did not reach its bounded external archive boundary")
			}
			h.call(t, "PUT", "/api/users/approver-a/status", "officer", map[string]bool{"disabled": true}, 200)
			release.Do(func() { close(barrier.release) })
			var applied result
			select {
			case applied = <-finished:
			case <-time.After(10 * time.Second):
				t.Fatal("application did not finish after archive I/O completed")
			}
			want := http.StatusConflict
			if boundary == auditrecord.PolicyResult {
				want = http.StatusOK // Authorization and settings already committed atomically.
			}
			if applied.err != nil || applied.status != want {
				t.Fatalf("application across %s: status%d want%d error%v", boundary, applied.status, want, applied.err)
			}
			state, err := h.s.store.GetPolicyState()
			if err != nil {
				t.Fatal(err)
			}
			if boundary == auditrecord.PolicyResult {
				if state.Active.Version != 3 || state.Pending != nil || h.s.store.GetAuditSettings() != settings {
					t.Fatalf("post-commit result did not finish the exact activated settings: %+v", state)
				}
			} else {
				if state.Active.Version != 2 || h.s.store.GetAuditSettings() != old {
					t.Fatalf("revoked quorum changed protected settings before activation: %+v", state)
				}
				if boundary == auditrecord.PolicyIntent {
					if state.Pending != nil {
						t.Fatal("revocation during intent installed an unauthorized transition")
					}
				} else if _, err := h.s.securityService().PolicyForExecution("officer", "synthetic-node"); !errors.Is(err, authorization.ErrTransition) {
					t.Fatalf("uncertain transition reopened covered execution: %v", err)
				}
			}
			var current model.SecurityChange
			decodeResult(t, h.call(t, "GET", "/api/security/changes/"+change.ID, "officer", nil, 200), &current)
			if boundary == auditrecord.PolicyResult && (current.State != "applied" || current.ResultRef == "") {
				t.Fatalf("activated settings lost durable result: %+v", current)
			}
			if boundary != auditrecord.PolicyResult && current.ResultRef != "" {
				t.Fatal("refused activation reported a successful archived result")
			}
			foundBoundary := false
			for _, envelope := range h.archive.Governance.Envelopes() {
				if envelope.EventID == fmt.Sprintf("%s-%s", change.ID, boundary) {
					foundBoundary = true
				}
			}
			if !foundBoundary {
				t.Fatal("test did not preserve the actual external event before revocation")
			}
		})
	}
}

func TestGovernanceHTTPAuthorityWriteFailureRollsBackAndReconcilesExactChange(t *testing.T) {
	for _, payload := range []model.SecurityChangePayload{
		{Kind: "role", Role: &model.SecurityRoleChange{UserID: "approver-a", Role: model.RoleOriginalReader, Grant: true}},
		{Kind: "role", Role: &model.SecurityRoleChange{UserID: "approver-a", Role: model.RoleSecurityApprover, Grant: false}},
		{Kind: "person", Person: &model.SecurityPersonChange{UserID: "approver-a", PersonID: "synthetic-transactional-person", Verification: "Independent synthetic identity verification"}},
	} {
		t.Run(payload.Kind, func(t *testing.T) {
			h := newGovernanceHTTP(t)
			h.apply(t, h.approve(t, h.request(t, h.bootstrapPayload(), 1)), 200)
			change := h.approve(t, h.request(t, payload, 2))
			before, err := h.s.store.GetUserByID("approver-a")
			if err != nil {
				t.Fatal(err)
			}
			identity, err := h.s.securityService().Effective("approver-a")
			if err != nil {
				t.Fatal(err)
			}
			unspent := h.stepup(t, "approver-a", authorization.ActionApprove, change.Digest, change.ID)
			// Fail a durable write after the role/person update has started. The
			// transaction must roll back identity, authority and invalidation together.
			if _, err := h.s.store.DB().Exec(`CREATE TRIGGER synthetic_authority_write_failure BEFORE UPDATE OF consumed_at ON stepup_proofs WHEN NEW.user_id='approver-a' BEGIN SELECT RAISE(ABORT,'synthetic durable authority write failure'); END`); err != nil {
				t.Fatal(err)
			}
			h.apply(t, change, http.StatusBadRequest)
			after, err := h.s.store.GetUserByID("approver-a")
			if err != nil || after.SecurityRevision != before.SecurityRevision || after.TokenGeneration != before.TokenGeneration {
				t.Fatalf("failed authority write partially revoked credentials: %+v %v", after, err)
			}
			current, err := h.s.securityService().Effective("approver-a")
			if err != nil || current.PersonID != identity.PersonID || current.HasRole(model.RoleOriginalReader) || !current.HasRole(model.RoleSecurityApprover) {
				t.Fatalf("failed authority write partially installed a role/person: %+v %v", current, err)
			}
			var liveProof bool
			if err := h.s.store.DB().QueryRow("SELECT consumed_at IS NULL AND expires_at>? FROM stepup_proofs WHERE hash=?", h.clock.Now().Unix(), store.SecurityDigest([]byte(unspent))).Scan(&liveProof); err != nil || !liveProof {
				t.Fatalf("rolled-back invalidation consumed a recent proof: %v", err)
			}
			stored, err := h.s.store.GetSecurityChange(change.ID)
			if err != nil || h.s.securityService().ValidateQuorum(stored) != nil || stored.State != "applying" || stored.CommitRef == "" || stored.ResultRef != "" {
				t.Fatalf("failed write lost exact valid quorum or claimed activation: %+v %v", stored, err)
			}
			if payload.Person != nil {
				var orphan int
				if err := h.s.store.DB().QueryRow("SELECT COUNT(*) FROM security_persons WHERE id=?", payload.Person.PersonID).Scan(&orphan); err != nil || orphan != 0 {
					t.Fatalf("failed relink retained partial person identity: count%d error%v", orphan, err)
				}
			}
			state, err := h.s.store.GetPolicyState()
			if err != nil || state.Active.Version != 2 || state.Pending == nil || state.PendingChange != change.ID {
				t.Fatalf("failed write advanced policy: %+v %v", state, err)
			}
			if _, err := h.s.securityService().PolicyForExecution("officer", "synthetic-node"); !errors.Is(err, authorization.ErrTransition) {
				t.Fatalf("failed activation reopened covered execution: %v", err)
			}
			if _, err := h.s.store.DB().Exec("DROP TRIGGER synthetic_authority_write_failure"); err != nil {
				t.Fatal(err)
			}
			h.call(t, "POST", "/api/security/changes/"+change.ID+"/reconcile", "officer", map[string]any{}, http.StatusOK)
			current, err = h.s.securityService().Effective("approver-a")
			if err != nil || payload.Role != nil && current.HasRole(payload.Role.Role) != payload.Role.Grant || payload.Person != nil && current.PersonID != payload.Person.PersonID {
				t.Fatalf("exact recovery failed to install the approved authority: %+v %v", current, err)
			}
			state, err = h.s.store.GetPolicyState()
			if err != nil || state.Active.Version != 3 || state.Pending != nil {
				t.Fatalf("exact recovery did not finish policy: %+v %v", state, err)
			}
			seen := map[string]int{}
			for _, envelope := range h.archive.Governance.Envelopes() {
				if envelope.Details.RequestID == change.ID {
					seen[envelope.EventType]++
				}
			}
			for _, kind := range []string{auditrecord.PolicyIntent, auditrecord.PolicyCommit, auditrecord.PolicyAnchor, auditrecord.PolicyResult} {
				if seen[kind] != 1 {
					t.Fatalf("exact recovery duplicated or lost %s: %v", kind, seen)
				}
			}
		})
	}
}
