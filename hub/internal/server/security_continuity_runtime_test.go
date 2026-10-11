package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestGovernanceHTTPCommittedRecoverySurvivesKeyLossWithoutReissuingCredentials(t *testing.T) {
	h := newGovernanceHTTP(t)
	h.apply(t, h.approve(t, h.request(t, h.bootstrapPayload(), 1)), 200)
	temporary := "SyntheticRecovery@1234"
	ref := h.secret(t, "password", temporary)
	change := h.approve(t, h.request(t, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "viewer", Operation: "password-reset", SecretRef: ref}}, 2))
	h.archive.SetFault("result-uncertain")
	h.apply(t, change, http.StatusBadRequest)
	before, err := h.s.store.GetUserByID("viewer")
	if err != nil || !before.MustChangePassword || !auth.ComparePassword(before.PasswordHash, temporary) {
		t.Fatal("uncertain result did not follow the committed exact recovery")
	}
	state, err := h.s.store.GetPolicyState()
	if err != nil || state.Active.Version != 3 || state.Pending == nil || state.PendingChange != change.ID {
		t.Fatalf("committed recovery lost pending result: %+v %v", state, err)
	}
	h.archive.SetFault("")
	count := len(h.archive.Governance.Envelopes())
	key := h.s.storageKey
	h.s.storageKey = "synthetic-lost-at-rest-key"
	defer func() { h.s.storageKey = key }()
	h.call(t, "POST", "/api/security/changes/"+change.ID+"/reconcile", "officer", nil, http.StatusServiceUnavailable)
	if _, err := h.s.securityService().PolicyForExecution("officer", "synthetic-node"); !errors.Is(err, authorization.ErrTransition) {
		t.Fatalf("missing credential key reopened covered execution: %v", err)
	}
	failed, err := h.s.store.GetSecurityChange(change.ID)
	if err != nil || failed.State != "applying" || failed.ResultRef != "" || len(h.archive.Governance.Envelopes()) != count {
		t.Fatalf("failed key resolution falsely finalized or rearchived recovery: %+v %v", failed, err)
	}
	h.s.storageKey = key
	h.call(t, "POST", "/api/security/changes/"+change.ID+"/reconcile", "officer", nil, http.StatusOK)
	after, err := h.s.store.GetUserByID("viewer")
	if err != nil || after.PasswordHash != before.PasswordHash || after.TokenGeneration != before.TokenGeneration || after.SecurityRevision != before.SecurityRevision || !after.MustChangePassword {
		t.Fatalf("result reconciliation reissued or invalidated committed credentials: %+v %v", after, err)
	}
	state, err = h.s.store.GetPolicyState()
	if err != nil || state.Active.Version != 3 || state.Pending != nil || state.State != "enhanced" {
		t.Fatalf("restored exact key did not finish committed recovery: %+v %v", state, err)
	}
	seen := map[string]int{}
	for _, event := range h.archive.Governance.Envelopes() {
		if event.Details.RequestID == change.ID {
			seen[event.EventType]++
			if bytes.Contains(event.Details.ApprovedChange, []byte(temporary)) || bytes.Contains(event.Details.ApprovedChange, []byte(before.PasswordHash)) {
				t.Fatal("result recovery leaked temporary credential bytes")
			}
		}
	}
	for _, kind := range []string{auditrecord.PolicyIntent, auditrecord.PolicyCommit, auditrecord.PolicyAnchor, auditrecord.PolicyResult} {
		if seen[kind] != 1 {
			t.Fatalf("recovery duplicated or lost %s: %v", kind, seen)
		}
	}
}

func TestGovernanceHTTPProofBelongsToItsInteractiveSessionAndCannotBeReplayed(t *testing.T) {
	h := newGovernanceHTTP(t)
	previewRaw := h.call(t, "POST", "/api/security/changes/preview", "officer", authorization.Proposal{Reason: "Exact session-bound synthetic request", ExpectedVersion: 1, Change: mustMarshal(t, h.bootstrapPayload())}, 200)
	var preview authorization.Preview
	decodeResult(t, previewRaw, &preview)
	firstSession := h.tokens["officer"]
	proof := h.stepup(t, "officer", authorization.ActionRequest, preview.Digest, "")
	h.login(t, "officer", "Synthetic-Test1!")
	request := map[string]any{"reason": preview.Proposal.Reason, "expected_version": preview.Proposal.ExpectedVersion, "change": json.RawMessage(preview.Proposal.Change), "step_up_proof": proof}
	h.call(t, "POST", "/api/security/changes", "officer", request, http.StatusForbidden)
	h.tokens["officer"] = firstSession
	var change model.SecurityChange
	decodeResult(t, h.call(t, "POST", "/api/security/changes", "officer", request, http.StatusCreated), &change)
	h.call(t, "POST", "/api/security/changes", "officer", request, http.StatusForbidden)
	// A fresh code still cannot attest a different request digest. Rejection must
	// not consume that code before the legitimate request is checked.
	h.clock.Advance(30 * time.Second)
	code, err := totp.GenerateCode(h.secrets["approver-a"], h.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	stepup := map[string]string{"action": authorization.ActionApprove, "digest": authorization.Digest([]byte("different-approved-request")), "change_id": change.ID, "code": code}
	h.call(t, "POST", "/api/security/step-up", "approver-a", stepup, http.StatusConflict)
	stepup["digest"] = change.Digest
	response := h.call(t, "POST", "/api/security/step-up", "approver-a", stepup, http.StatusOK)
	h.call(t, "POST", "/api/security/step-up", "approver-a", stepup, http.StatusForbidden)
	var approval struct {
		Proof string `json:"proof"`
	}
	decodeResult(t, response, &approval)
	h.call(t, "POST", "/api/security/changes/"+change.ID+"/approve", "approver-a", map[string]string{"step_up_proof": approval.Proof}, http.StatusOK)
	h.call(t, "POST", "/api/security/changes/"+change.ID+"/approve", "approver-a", map[string]string{"step_up_proof": approval.Proof}, http.StatusForbidden)
	stored, err := h.s.store.GetSecurityChange(change.ID)
	if err != nil || stored.State != "partially_approved" || len(stored.Approvals) != 1 || len(h.archive.Governance.Envelopes()) != 0 {
		t.Fatalf("proof/code replay created independent authority or external evidence: %+v %v", stored, err)
	}
	// An API token retains ordinary read access but can never stand in for the
	// interactive session used to issue fresh MFA or a write-only secret.
	apiValue, apiHash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.s.store.CreateAPIToken(&model.APIToken{ID: "synthetic-officer-api-token", UserID: "officer", Name: "Synthetic token boundary test", TokenPrefix: prefix, TokenHash: apiHash}); err != nil {
		t.Fatal(err)
	}
	h.tokens["api-officer"] = apiValue
	h.call(t, "GET", "/api/security/changes/"+change.ID, "api-officer", nil, http.StatusOK)
	h.call(t, "POST", "/api/security/step-up", "api-officer", map[string]string{"action": authorization.ActionRequest, "digest": preview.Digest, "code": code}, http.StatusForbidden)
	h.call(t, "POST", "/api/security/secrets", "api-officer", map[string]string{"kind": "destination", "value": "synthetic token must not upload this credential"}, http.StatusForbidden)
	if _, err := h.s.securityService().PolicyForExecution("officer", "synthetic-node"); err != nil {
		t.Fatalf("refused proofs changed initial Standard execution policy: %v", err)
	}
	if err := h.runtime.Evidence().GovernanceReady(context.Background()); err != nil {
		t.Fatalf("refused proofs affected the independent governance authority: %v", err)
	}
}
