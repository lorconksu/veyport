package server

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestOriginalRESTReceiptExpiresDuringIntentPreservationNeverReturnsOrRevivesHandle(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	h.s.stopOriginalRecovery()
	purpose := "Expired admission to one-use original"
	preview := h.preview(t, purpose, "envelope")
	proof := h.proof(t, purpose, "envelope", preview)
	resolve := h.s.originalAccess.ResolveArchive
	h.s.originalAccess.ResolveArchive = func(ctx context.Context, p model.PolicyVersion) (auditgate.OriginalArchive, error) {
		a, err := resolve(ctx, p)
		a.Ingest = originalBoundaryPreserver{preserver: a.Ingest, after: func(e auditrecord.Envelope) {
			if e.EventType == auditrecord.OriginalReadIntent {
				h.clock.Advance(2 * time.Minute)
			}
		}}
		return a, err
	}
	raw := h.json(t, "POST", "/api/executions/"+h.execution.ID+"/original-access", h.token, originalRequest{Purpose: purpose, Records: []string{"envelope"}, Digest: preview.Digest, StepupProof: proof}, 503)
	if bytes.Contains(raw, []byte(`"handle"`)) {
		t.Fatal("late receipt verification returned an expired permit")
	}
	var id string
	if err := h.s.store.DB().QueryRow("SELECT id FROM original_access").Scan(&id); err != nil {
		t.Fatal(err)
	}
	a, err := h.s.store.GetOriginalAccess(id)
	if err != nil || a.State != "pending" || a.IntentToken != "" || a.ConsumedAt != nil {
		t.Fatal("expired receipt created usable authority")
	}
	h.s.originalAccess.ResolveArchive = resolve
	var opens atomic.Int32
	h.setReader(func(reader auditgate.OriginalReader) auditgate.OriginalReader {
		return countedOriginalReader{reader: reader, calls: &opens}
	})
	h.s.recoverOriginalEvidence(context.Background())
	a, err = h.s.store.GetOriginalAccess(id)
	if err != nil || a.State != "expired" || a.EvidenceState != "confirmed" || a.ConsumedAt != nil || opens.Load() != 0 {
		t.Fatalf("expired intent recovery: state=%s evidence=%s consumed=%t opens=%d err=%v", a.State, a.EvidenceState, a.ConsumedAt != nil, opens.Load(), err)
	}
	intent, result := 0, 0
	for _, e := range h.fixture.Originals.Envelopes() {
		if e.EventID == id+".intent" {
			intent++
		}
		if e.EventID == id+".result" {
			result++
			if e.Details.State != "expired" || e.Details.Delivery == nil || e.Details.Delivery.BytesWritten == nil || *e.Details.Delivery.BytesWritten != 0 {
				t.Fatal("expiry recovery claimed original bytes")
			}
		}
	}
	if intent != 1 || result != 1 {
		t.Fatal("recovery lost or duplicated immutable read evidence")
	}
	// Historical confirmation cannot be used to repeat the failed action with
	// its consumed proof and obtain a replacement handle.
	h.json(t, "POST", "/api/executions/"+h.execution.ID+"/original-access", h.token, originalRequest{Purpose: purpose, Records: []string{"envelope"}, Digest: preview.Digest, StepupProof: proof}, 403)
	var permits int
	if err := h.s.store.DB().QueryRow("SELECT COUNT(*) FROM original_access").Scan(&permits); err != nil || permits != 1 {
		t.Fatal("historical intent confirmation regenerated a permit")
	}
}
