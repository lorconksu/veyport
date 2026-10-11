package auditruntime_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func syntheticResult(h *harness, id string) []byte {
	e := auditrecord.Envelope{SchemaVersion: 1, EventID: id, EventType: auditrecord.PolicyResult, Actor: auditrecord.Actor{UserID: "synthetic-test", PersonID: "synthetic-test", Name: "Synthetic receipt recovery test"}, PolicyVersion: 2, PolicySHA256: auditrecord.Digest(h.policy), OccurredAt: h.fixture.Clock.Now(), Details: &auditrecord.Details{CorrelationID: id, RequestID: id, RequestSHA256: auditrecord.Hash([]byte("test-only approved bytes")), State: "synthetic-receipt-recovery-test"}}
	raw, _ := json.Marshal(e)
	return raw
}

func TestGovernanceReceiptLookupRecoversLostInvalidAndExpiredReplies(t *testing.T) {
	for _, fault := range []string{"lose-policy.result", "receipt", "expired-receipt"} {
		t.Run(fault, func(t *testing.T) {
			h := newHarness(t)
			h.fixture.SetFault(fault)
			reference, err := h.runtime.Evidence().Preserve(context.Background(), syntheticResult(h, "synthetic-result"))
			if err != nil || reference == "" {
				t.Fatalf("exact archive lookup did not recover %s: %v", fault, err)
			}
			if len(h.fixture.Governance.Envelopes()) != 1 {
				t.Fatal("receipt retry duplicated governing record")
			}
		})
	}
}

func TestGovernanceReceiptManifestTamperingAndAdminOutageCannotConfirm(t *testing.T) {
	h := newHarness(t)
	h.fixture.SetFault("manifest")
	if _, err := h.runtime.Evidence().Preserve(context.Background(), syntheticResult(h, "synthetic-tampered-result")); !errors.Is(err, auditgate.ErrReceipt) {
		t.Fatalf("unsigned manifest substitution confirmed: %v", err)
	}
	h.fixture.SetFault("result-uncertain")
	if _, err := h.runtime.Evidence().Preserve(context.Background(), syntheticResult(h, "synthetic-uncertain-result")); err == nil {
		t.Fatal("unconfirmed write was acknowledged without admin lookup")
	}
	if len(h.fixture.Governance.Envelopes()) != 2 {
		t.Fatal("fixture failed to retain uncertain writes")
	}
}
