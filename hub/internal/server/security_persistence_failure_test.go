package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestGovernanceHTTPPersistenceFailureCannotPublishSecretsProofsOrPartialQuorum(t *testing.T) {
	h := newGovernanceHTTP(t)
	rows := func(table string) int {
		t.Helper()
		var count int
		if err := h.s.store.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	install := func(boundary string) {
		t.Helper()
		if _, err := h.s.store.DB().Exec("CREATE TRIGGER persistence_fault " + boundary + " BEGIN SELECT RAISE(ABORT,'injected security persistence failure'); END"); err != nil {
			t.Fatal(err)
		}
	}
	restore := func() {
		t.Helper()
		if _, err := h.s.store.DB().Exec("DROP TRIGGER persistence_fault"); err != nil {
			t.Fatal(err)
		}
	}
	secretCount := rows("security_secrets")
	for _, password := range []string{"weak", strings.Repeat("SyntheticStrong@1234", 5)} {
		body := h.call(t, "POST", "/api/security/secrets", "officer", map[string]string{"kind": "password", "value": password}, http.StatusBadRequest)
		if bytes.Contains(body, []byte(password)) || rows("security_secrets") != secretCount {
			t.Fatal("refused password was disclosed or retained as a usable secret")
		}
	}
	value := "SYNTHETIC_UNCOMMITTED_SECRET_CANARY"
	install("BEFORE INSERT ON security_secrets")
	body := h.call(t, "POST", "/api/security/secrets", "officer", map[string]string{"kind": "destination", "value": value}, http.StatusBadRequest)
	if bytes.Contains(body, []byte(value)) || bytes.Contains(body, []byte("credential_ref")) || rows("security_secrets") != secretCount {
		t.Fatal("failed encrypted-secret persistence published a reference or plaintext")
	}
	restore()
	previewRaw := h.call(t, "POST", "/api/security/changes/preview", "officer", authorization.Proposal{Reason: "Synthetic SQLite refusal and exact atomic retry", ExpectedVersion: 1, Change: mustMarshal(t, h.bootstrapPayload())}, http.StatusOK)
	var preview authorization.Preview
	decodeResult(t, previewRaw, &preview)
	h.clock.Advance(30 * time.Second)
	code, err := totp.GenerateCode(h.secrets["officer"], h.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	stepup := map[string]string{"action": authorization.ActionRequest, "digest": preview.Digest, "code": code}
	proofCount := rows("stepup_proofs")
	install("BEFORE INSERT ON stepup_proofs")
	body = h.call(t, "POST", "/api/security/step-up", "officer", stepup, http.StatusBadRequest)
	if bytes.Contains(body, []byte("\"proof\"")) || rows("stepup_proofs") != proofCount {
		t.Fatal("failed proof persistence published an uncommitted MFA handle")
	}
	restore()
	// Successful MFA verification already spent the code. A persistence outage
	// cannot make that code authorize another proof after storage recovers.
	h.call(t, "POST", "/api/security/step-up", "officer", stepup, http.StatusForbidden)
	proof := h.stepup(t, "officer", authorization.ActionRequest, preview.Digest, "")
	request := map[string]any{"reason": preview.Proposal.Reason, "expected_version": preview.Proposal.ExpectedVersion, "change": json.RawMessage(preview.Proposal.Change), "step_up_proof": proof}
	install("BEFORE INSERT ON security_nominations WHEN NEW.user_id='approver-b'")
	h.call(t, "POST", "/api/security/changes", "officer", request, http.StatusBadRequest)
	state, err := h.s.store.GetPolicyState()
	if err != nil || state.State != "standard" || rows("security_changes") != 0 || rows("security_nominations") != 0 {
		t.Fatalf("failed nomination freeze leaked a partial request: %+v %v", state, err)
	}
	for _, user := range []string{"officer", "approver-a", "approver-b"} {
		protected, err := h.s.store.IsProtectedUser(user)
		if err != nil || protected {
			t.Fatalf("rolled-back proposal retained an incomplete principal freeze: %s %v", user, err)
		}
	}
	restore()
	var change model.SecurityChange
	// This proof belongs to the same session and exact request. The failed
	// transaction did not accept the request, so its proof consumption rolled back.
	decodeResult(t, h.call(t, "POST", "/api/security/changes", "officer", request, http.StatusCreated), &change)
	firstProof := h.stepup(t, "approver-a", authorization.ActionApprove, change.Digest, change.ID)
	for _, boundary := range []string{
		"BEFORE INSERT ON security_approvals",
		"BEFORE UPDATE OF state ON security_changes WHEN NEW.state='partially_approved'",
	} {
		install(boundary)
		h.call(t, "POST", "/api/security/changes/"+change.ID+"/approve", "approver-a", map[string]string{"step_up_proof": firstProof}, http.StatusBadRequest)
		stored, err := h.s.store.GetSecurityChange(change.ID)
		if err != nil || stored.State != "requested" || len(stored.Approvals) != 0 {
			t.Fatalf("failed first vote left partial independent approval: %+v %v", stored, err)
		}
		restore()
	}
	h.call(t, "POST", "/api/security/changes/"+change.ID+"/approve", "approver-a", map[string]string{"step_up_proof": firstProof}, http.StatusOK)
	secondProof := h.stepup(t, "approver-b", authorization.ActionApprove, change.Digest, change.ID)
	install("BEFORE UPDATE OF state ON security_changes WHEN NEW.state='approved'")
	h.call(t, "POST", "/api/security/changes/"+change.ID+"/approve", "approver-b", map[string]string{"step_up_proof": secondProof}, http.StatusBadRequest)
	stored, err := h.s.store.GetSecurityChange(change.ID)
	if err != nil || stored.State != "partially_approved" || len(stored.Approvals) != 1 || len(h.archive.Governance.Envelopes()) != 0 {
		t.Fatalf("failed second vote published a quorum or external authority: %+v %v", stored, err)
	}
	restore()
	decodeResult(t, h.call(t, "POST", "/api/security/changes/"+change.ID+"/approve", "approver-b", map[string]string{"step_up_proof": secondProof}, http.StatusOK), &change)
	if change.State != "approved" || len(change.Approvals) != 2 || change.Digest != preview.Digest {
		t.Fatal("atomic retries changed the exact request or independent two-person quorum")
	}
	h.apply(t, change, http.StatusOK)
	if len(h.archive.Governance.Envelopes()) != 4 {
		t.Fatal("one exact transition did not preserve intent, commit, anchor and result")
	}
}
