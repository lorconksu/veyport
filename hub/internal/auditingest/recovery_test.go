package auditingest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type dispatchClaim struct{ claimed bool }

func (c *dispatchClaim) Claim(_ context.Context, _, _, _ string) error {
	if c.claimed {
		return auditgate.ErrReplay
	}
	c.claimed = true
	return nil
}

func TestGatePreservesFullRetentionAcrossFractionalSecond(t *testing.T) {
	s, original, key, second := testService(t)
	requestedAt := second.Add(500 * time.Millisecond)
	acceptedAt := second.Add(600 * time.Millisecond)
	s.config.Now = func() time.Time { return acceptedAt }
	raw, inputs := testRecord(t, requestedAt, []byte("synthetic script"))
	_, e, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auditgate.NewVerifier(auditgate.VerifierConfig{Issuer: "ingest", Audience: "hub", Keys: map[string]*ecdsa.PublicKey{"key-1": &key.PublicKey}, QualificationSHA256: original.q.Digest, MaxTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	claim := &dispatchClaim{}
	gate := auditgate.Gate{Preserver: s, Verifier: verifier, Consumer: claim, Now: func() time.Time { return acceptedAt }}
	receipt, err := gate.Admit(context.Background(), raw, inputs, *e.Execution, requestedAt.Add(24*time.Hour))
	if err != nil || !claim.claimed {
		t.Fatal("fractional deadline rejected valid retention", err)
	}
	expected := acceptedAt.Add(24 * time.Hour)
	var manifest auditrecord.Manifest
	if json.Unmarshal(original.objects[receipt.Manifest.Key].data, &manifest) != nil || !manifest.RetainUntil.Equal(expected) || !receipt.Manifest.RetainUntil.Equal(expected) || !manifest.Envelope.RetainUntil.Equal(expected) || !manifest.Attachments[0].RetainUntil.Equal(expected) {
		t.Fatal("promise shortened or changed across exact manifest/reference serialization")
	}
	if manifest.RetainUntil.Sub(acceptedAt) != 24*time.Hour {
		t.Fatal("configured duration was weakened")
	}
}

func TestStoragePrecisionMarginDoesNotShortenApplicationPromise(t *testing.T) {
	for _, days := range []int32{1, 2} {
		t.Run(string(rune('0'+days))+"day", func(t *testing.T) {
			s, _, _, second := testService(t)
			acceptedAt := second.Add(600 * time.Millisecond)
			q := validQualification()
			q.DefaultRetentionSeconds = uint64(days) * 86400
			backend := newFakeS3()
			backend.defaultRetentionDays = days
			// The qualified lab S3 truncates its later creation timestamp to seconds.
			backend.now = func() time.Time { return acceptedAt.Add(100 * time.Millisecond).Truncate(time.Second) }
			archive, err := NewS3Archive(context.Background(), S3Config{Endpoint: q.ArchiveEndpoint, Region: "region", Bucket: q.Bucket, KMSKeyID: q.KMSKeyID, AllowedHosts: []string{"archive.example:8333"}, Qualification: q}, backend)
			if err != nil {
				t.Fatal(err)
			}
			s.config.Archive = archive
			s.config.Now = func() time.Time { return acceptedAt }
			raw, inputs := testRecord(t, second.Add(500*time.Millisecond), nil)
			receipt, err := s.Preserve(context.Background(), raw, inputs)
			if days == 1 {
				if err == nil || receipt.Token != "" {
					t.Fatal("shortened actual retention authorized a receipt")
				}
				return
			}
			if err != nil || !receipt.Manifest.RetainUntil.Equal(acceptedAt.Add(24*time.Hour)) {
				t.Fatal("storage margin changed application promise", err)
			}
		})
	}
	q := validQualification()
	q.DefaultRetentionSeconds = 3651 * 86400
	if q.Validate() != nil {
		t.Fatal("approved storage-only margin rejected")
	}
	q.DefaultRetentionSeconds = 3652 * 86400
	if q.Validate() == nil {
		t.Fatal("qualification storage cap broadened beyond approved margin")
	}
	s, _, _, _ := testService(t)
	cfg := s.config
	cfg.GovernanceRetention = 3651 * 24 * time.Hour
	if _, err := NewService(cfg); err == nil {
		t.Fatal("storage margin broadened application policy maximum")
	}
}

func TestRealisticDefaultRetentionAnchorLostReply(t *testing.T) {
	original, _ := testS3(t)
	q := validQualification()
	q.Bucket = "audit-governance"
	q.DefaultRetentionSeconds = 3650 * 86400
	q.Digest = auditrecord.Hash([]byte("governance qualification"))
	backend := newFakeS3()
	backend.defaultRetentionDays = 3650
	backend.lostReplyPrefix = "manifests/"
	gov, err := NewS3Archive(context.Background(), S3Config{Endpoint: q.ArchiveEndpoint, Region: "region", Bucket: q.Bucket, KMSKeyID: q.KMSKeyID, AllowedHosts: []string{"archive.example:8333"}, Qualification: q}, backend)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	cfg := ServiceConfig{Issuer: "ingest", Audience: "hub", Retention: 24 * time.Hour, GovernanceRetention: 3650 * 24 * time.Hour, ReceiptTTL: time.Minute, Timeout: 10 * time.Second, Concurrency: 4, Signer: Signer{KeyID: "key-1", Key: key}, Archive: original, GovernanceArchive: gov, Now: func() time.Time { return now }}
	service, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := policyRecord(now, 2, "change-anchor")
	receipt, err := service.Preserve(context.Background(), raw, nil)
	if err != nil {
		t.Fatal("lost manifest reply failed recovery", err)
	}
	actual := backend.objects[receipt.Manifest.Key].ref.RetainUntil
	if !actual.After(receipt.Manifest.RetainUntil) {
		t.Fatal("fixture does not simulate later bucket retention")
	}
	found, _, err := gov.Find(context.Background(), receipt.Manifest.Key)
	if err != nil || auditrecord.Digest(found) != auditrecord.Digest(receipt.Manifest) {
		t.Fatal("Put/Find references changed with actual retention")
	}
	cfg.Now = func() time.Time { return now.Add(49 * time.Hour) }
	restarted, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.Lookup(context.Background(), "change-anchor", auditrecord.Hash(raw))
	if err != nil || auditrecord.Digest(again.Manifest) != auditrecord.Digest(receipt.Manifest) {
		t.Fatal("restart/history reconciliation changed immutable reference", err)
	}
	response, err := restarted.Anchor(context.Background(), "installation", auditrecord.Hash([]byte("fresh lookup")))
	if err != nil || response.Receipt.Manifest.VersionID != receipt.Manifest.VersionID {
		t.Fatal("anchor stranded after originals retention", err)
	}
	if len(backend.objects) != 4 {
		t.Fatal("recovery created extra versions")
	}
}

func TestCrossBucketEventConflictAndGovernanceRawIsolation(t *testing.T) {
	s, a, _, now := testService(t)
	raw, _ := testRecord(t, now, nil)
	if _, err := s.Preserve(context.Background(), raw, nil); err != nil {
		t.Fatal(err)
	}
	policy := policyRecord(now, 2, "event-1")
	if _, err := s.Preserve(context.Background(), policy, nil); err != ErrConflict {
		t.Fatal("event ID reused across archive buckets")
	}
	gov := s.config.GovernanceArchive.(*memoryArchive)
	for _, o := range gov.objects {
		if bytes.Contains(o.data, []byte("SYNTHETIC_SECRET")) {
			t.Fatal("raw execution entered governance archive")
		}
	}
	if len(a.objects) != 2 {
		t.Fatal("unexpected originals changed")
	}
	policy = policyRecord(now, 2, "policy-2")
	if _, err := s.Preserve(context.Background(), policy, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.objects["manifests/policy-2"]; ok {
		t.Fatal("governance record in original bucket")
	}
}

func TestFutureOriginalIntentAndAnchorVerificationFailClosed(t *testing.T) {
	s, a, _, now := testService(t)
	raw, _ := testRecord(t, now, nil)
	receipt, err := s.Preserve(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	var manifest auditrecord.Manifest
	json.Unmarshal(a.objects[receipt.Manifest.Key].data, &manifest)
	e := auditrecord.Envelope{SchemaVersion: 1, EventID: "future-read", EventType: auditrecord.OriginalReadIntent, Actor: auditrecord.Actor{UserID: "user", PersonID: "person"}, PolicyVersion: 1, PolicySHA256: auditrecord.Hash(nil), OccurredAt: now.Add(time.Hour), Details: &auditrecord.Details{CorrelationID: "access", SessionSHA256: auditrecord.Hash(nil), Reason: "investigation", Originals: []auditrecord.ObjectRef{manifest.Envelope}}}
	b, _ := json.Marshal(e)
	intent, err := s.Preserve(context.Background(), b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadOriginal(context.Background(), manifest.Envelope, intent.Token); err == nil {
		t.Fatal("future timestamp revived read freshness")
	}
	if _, err = s.Preserve(context.Background(), policyRecord(now, 2, "anchor"), nil); err != nil {
		t.Fatal(err)
	}
	gov := s.config.GovernanceArchive.(*memoryArchive)
	for _, prefix := range []string{"anchors/", "manifests/", "envelopes/"} {
		gov.failVerify = prefix
		if _, err = s.Anchor(context.Background(), "installation", auditrecord.Hash([]byte("nonce"))); err == nil {
			t.Fatal("unsigned/unverified archived anchor returned")
		}
	}
}
