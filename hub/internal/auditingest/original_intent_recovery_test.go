package auditingest

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func TestRetainedOriginalIntentLookupPreservesExpiredPermitWithinReaderAgeWindow(t *testing.T) {
	s, archive, _, now := testService(t)
	s.config.ReceiptTTL = 10 * time.Second
	ctx := context.Background()
	admission, _ := testRecord(t, now, nil)
	if _, err := s.Preserve(ctx, admission, nil); err != nil {
		t.Fatal(err)
	}
	ref, _, err := archive.Find(ctx, "envelopes/event-1/"+auditrecord.Hash(admission))
	if err != nil {
		t.Fatal(err)
	}
	e := auditrecord.Envelope{SchemaVersion: 1, EventID: "retained-read.intent", EventType: auditrecord.OriginalReadIntent, Actor: auditrecord.Actor{UserID: "reader", PersonID: "person"}, PolicyVersion: 1, PolicySHA256: auditrecord.Hash([]byte("policy")), OccurredAt: now, Details: &auditrecord.Details{CorrelationID: "retained-read", RequestID: "event-1", RequestSHA256: auditrecord.Hash([]byte("read-selection")), SessionSHA256: auditrecord.Hash([]byte("interactive-session")), Reason: "Investigate expired permit", State: "authorized", Originals: []auditrecord.ObjectRef{ref}}}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Preserve(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected, _, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, err := auditgate.NewVerifier(auditgate.VerifierConfig{Issuer: s.config.Issuer, Audience: s.config.Audience, Keys: map[string]*ecdsa.PublicKey{s.config.Signer.KeyID: &s.config.Signer.Key.PublicKey}, QualificationSHA256: archive.Qualification().Digest, MaxTTL: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	original, err := v.Verify(before.Token, expected, now)
	if err != nil {
		t.Fatal(err)
	}
	late := now.Add(20 * time.Second) // expired receipt, still inside Reader's separate sixty-second age bound.
	s.config.Now = func() time.Time { return late }
	for _, operation := range []struct {
		name string
		read func() (auditrecord.Receipt, error)
	}{
		{"admin-lookup", func() (auditrecord.Receipt, error) { return s.Lookup(ctx, e.EventID, auditrecord.Hash(raw)) }},
		{"exact-preserve-reconciliation", func() (auditrecord.Receipt, error) { return s.Preserve(ctx, raw, nil) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			again, err := operation.read()
			if err != nil {
				t.Fatal("retained exact intent could not confirm historical evidence:", err)
			}
			claims, err := v.VerifyReadEvidence(again.Token, expected, late)
			if err != nil || auditrecord.Digest(again.Manifest) != auditrecord.Digest(before.Manifest) || claims.IssuedAt == nil || claims.NotBefore == nil || claims.ExpiresAt == nil || !claims.IssuedAt.Equal(original.IssuedAt.Time) || !claims.NotBefore.Equal(original.NotBefore.Time) || !claims.ExpiresAt.Equal(original.ExpiresAt.Time) {
				t.Fatal("reconciliation changed immutable claims or renewed read authority")
			}
			if _, err := v.Verify(again.Token, expected, late); err == nil {
				t.Fatal("historical confirmation became a currently valid permit")
			}
			if body, err := s.ReadOriginal(ctx, ref, again.Token); err == nil || body != nil {
				t.Fatal("expired permit released original bytes within the age window")
			}
		})
	}
	if _, err := s.Lookup(ctx, "event-1", auditrecord.Hash(admission)); err == nil {
		t.Fatal("intent recovery exception revived an expired execution admission")
	}
	if _, err := s.Preserve(ctx, admission, nil); err == nil {
		t.Fatal("idempotent admission preservation renewed executable authority")
	}
}
