package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestGovernanceHTTPRefusedStepupCannotMintProofOrConsumeValidMFA(t *testing.T) {
	h := newGovernanceHTTP(t)
	previewRaw := h.call(t, "POST", "/api/security/changes/preview", "officer", authorization.Proposal{Reason: "Synthetic step-up refusal boundaries", ExpectedVersion: 1, Change: mustMarshal(t, h.bootstrapPayload())}, http.StatusOK)
	var preview authorization.Preview
	decodeResult(t, previewRaw, &preview)
	claims, err := auth.ValidateToken(h.s.jwtSecret, h.tokens["officer"])
	if err != nil || claims.SessionID == "" {
		t.Fatalf("real officer session unavailable: %v", err)
	}
	for _, test := range []struct {
		name, actor string
		mutate      func(map[string]string) any
		want        int
	}{
		{"ambiguous_action", "officer", func(body map[string]string) any {
			return json.RawMessage(`{"action":"security.request","action":"security.apply","digest":"` + body["digest"] + `","code":"` + body["code"] + `"}`)
		}, http.StatusBadRequest},
		{"malformed_digest", "officer", func(body map[string]string) any { body["digest"] = "not-an-exact-sha256"; return body }, http.StatusForbidden},
		{"unknown_action", "officer", func(body map[string]string) any { body["action"] = "security.reconcile"; return body }, http.StatusForbidden},
		{"ordinary_viewer", "viewer", func(body map[string]string) any { return body }, http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Each case uses a fresh period, not a rate-limit or replay refusal.
			h.clock.Advance(time.Minute)
			code, err := totp.GenerateCode(h.secrets[test.actor], h.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			body := map[string]string{"action": authorization.ActionRequest, "digest": preview.Digest, "code": code}
			response := h.call(t, "POST", "/api/security/step-up", test.actor, test.mutate(body), test.want)
			if bytes.Contains(response, []byte(`"proof"`)) || bytes.Contains(response, []byte(code)) {
				t.Fatal("refused step-up disclosed a proof or submitted MFA value")
			}
			assertNoRefusedStepupAuthority(t, h)
			if test.actor == "officer" {
				// Authority and shape failures precede TOTP consumption: the same
				// code can still attest the intended action once the input is fixed.
				response = h.call(t, "POST", "/api/security/step-up", "officer", map[string]string{"action": authorization.ActionRequest, "digest": preview.Digest, "code": code}, http.StatusOK)
				var issued struct {
					Proof string `json:"proof"`
				}
				decodeResult(t, response, &issued)
				if issued.Proof == "" {
					t.Fatal("refused input consumed the legitimate fresh MFA code")
				}
				if err := h.s.store.ConsumeStepup(issued.Proof, "officer", claims.SessionID, authorization.ActionRequest, preview.Digest, h.clock.Now()); err != nil {
					t.Fatalf("corrected input did not produce a usable exact-session proof: %v", err)
				}
			}
		})
	}
	// Model MFA data becoming unavailable after an already authenticated login.
	// Neither an absent secret nor damaged encrypted bytes is fresh MFA evidence.
	original := *h.users["officer"].TOTPSecret
	for _, test := range []struct {
		name    string
		secret  *string
		enabled bool
	}{
		{"mfa_disabled", &original, false},
		{"mfa_secret_missing", nil, true},
		{"encrypted_mfa_damaged", func() *string { value := "enc:00"; return &value }(), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := h.s.store.UpdateUserTOTP("officer", test.secret, test.enabled); err != nil {
				t.Fatal(err)
			}
			// The existing access session remains authenticated. These cases must
			// reach the handler's live MFA checks, not fail in token middleware.
			h.call(t, "GET", "/api/auth/me", "officer", nil, http.StatusOK)
			h.clock.Advance(time.Minute)
			code, err := totp.GenerateCode(h.secrets["officer"], h.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			response := h.call(t, "POST", "/api/security/step-up", "officer", map[string]string{"action": authorization.ActionRequest, "digest": preview.Digest, "code": code}, http.StatusForbidden)
			if !bytes.Contains(response, []byte(store.ErrStepup.Error())) || bytes.Contains(response, []byte(`"proof"`)) || bytes.Contains(response, []byte(code)) || (test.secret != nil && bytes.Contains(response, []byte(*test.secret))) {
				t.Fatal("unavailable MFA disclosed sensitive evidence")
			}
			assertNoRefusedStepupAuthority(t, h)
		})
	}
	if err := h.s.store.UpdateUserTOTP("officer", &original, true); err != nil {
		t.Fatal(err)
	}
	proof := h.stepup(t, "officer", authorization.ActionRequest, preview.Digest, "")
	if proof == "" {
		t.Fatal("exact repaired MFA could not issue a new proof")
	}
}

func assertNoRefusedStepupAuthority(t *testing.T, h *governanceHTTP) {
	t.Helper()
	var proofs int
	if err := h.s.store.DB().QueryRow("SELECT COUNT(*) FROM stepup_proofs WHERE consumed_at IS NULL").Scan(&proofs); err != nil || proofs != 0 {
		t.Fatalf("refused step-up persisted usable proof material: %d %v", proofs, err)
	}
	changes, err := h.s.store.ListSecurityChanges(100, 0)
	state, stateErr := h.s.store.GetPolicyState()
	if err != nil || stateErr != nil || len(changes) != 0 || state.State != "standard" || state.Active.Version != 1 || state.Pending != nil || len(h.archive.Governance.Envelopes()) != 0 {
		t.Fatalf("refused step-up acquired policy or archive authority: changes%d state%+v errors%v/%v", len(changes), state, err, stateErr)
	}
}
