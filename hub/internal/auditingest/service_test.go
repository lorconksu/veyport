package auditingest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func validQualification() Qualification {
	return Qualification{SchemaVersion: 1, ArchiveEndpoint: "https://archive.example:8333", ArchiveVersion: "qualified-1", Bucket: "archive", KMSKeyID: "archive-key", DefaultRetentionSeconds: 86400, ConfigurationSHA256: auditrecord.Hash([]byte("configuration")), ReportSHA256: auditrecord.Hash([]byte("report")), VerifiedAt: time.Now().UTC(), Checks: append([]string(nil), requiredChecks...), Digest: auditrecord.Hash([]byte("qualification"))}
}

type object struct {
	ref  auditrecord.ObjectRef
	data []byte
}
type memoryArchive struct {
	mu         sync.Mutex
	q          Qualification
	objects    map[string]object
	order      []string
	lostReply  string
	failVerify string
	failPut    string
	failFind   bool
	readKeys   []string
}

func newMemoryArchive() *memoryArchive {
	return &memoryArchive{q: validQualification(), objects: map[string]object{}}
}
func (a *memoryArchive) Qualification() Qualification { return a.q }
func (a *memoryArchive) Ready(ctx context.Context) error {
	if ctx.Err() != nil || a.failFind {
		return ErrUnavailable
	}
	return a.q.Validate()
}
func (a *memoryArchive) Put(ctx context.Context, key string, data []byte, retain time.Time) (auditrecord.ObjectRef, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || strings.HasPrefix(key, a.failPut) && a.failPut != "" {
		return auditrecord.ObjectRef{}, ErrUnavailable
	}
	if _, ok := a.objects[key]; ok {
		return auditrecord.ObjectRef{}, ErrConflict
	}
	r := auditrecord.ObjectRef{Bucket: a.q.Bucket, Key: key, VersionID: "v-" + auditrecord.Hash(data)[:12], SHA256: auditrecord.Hash(data), Bytes: int64(len(data)), RetainUntil: retain}
	a.objects[key] = object{r, append([]byte(nil), data...)}
	a.order = append(a.order, key)
	if strings.HasPrefix(key, a.lostReply) && a.lostReply != "" {
		return auditrecord.ObjectRef{}, ErrUnavailable
	}
	return r, nil
}
func (a *memoryArchive) Find(ctx context.Context, key string) (auditrecord.ObjectRef, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failFind || ctx.Err() != nil {
		return auditrecord.ObjectRef{}, nil, ErrUnavailable
	}
	o, ok := a.objects[key]
	if !ok {
		return auditrecord.ObjectRef{}, nil, ErrNotFound
	}
	return o.ref, append([]byte(nil), o.data...), nil
}
func (a *memoryArchive) Verify(ctx context.Context, r auditrecord.ObjectRef, retain time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	o, ok := a.objects[r.Key]
	if !ok || ctx.Err() != nil || strings.HasPrefix(r.Key, a.failVerify) && a.failVerify != "" || auditrecord.Digest(o.ref) != auditrecord.Digest(r) || r.RetainUntil.Before(retain) || auditrecord.Hash(o.data) != r.SHA256 {
		return ErrUnavailable
	}
	return nil
}
func (a *memoryArchive) Read(ctx context.Context, r auditrecord.ObjectRef) ([]byte, error) {
	if a.Verify(ctx, r, r.RetainUntil) != nil {
		return nil, ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.readKeys = append(a.readKeys, r.Key)
	return append([]byte(nil), a.objects[r.Key].data...), nil
}

func testService(t *testing.T) (*Service, *memoryArchive, *ecdsa.PrivateKey, time.Time) {
	t.Helper()
	a := newMemoryArchive()
	gov := newMemoryArchive()
	gov.q.Bucket = "audit-governance"
	gov.q.DefaultRetentionSeconds = 3650 * 86400
	gov.q.Digest = auditrecord.Hash([]byte("governance qualification"))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	s, err := NewService(ServiceConfig{Issuer: "ingest", Audience: "hub", Retention: 24 * time.Hour, ReceiptTTL: time.Minute, Timeout: 10 * time.Second, Concurrency: 4, Signer: Signer{KeyID: "key-1", Key: key}, Archive: a, GovernanceArchive: gov, GovernanceRetention: 3650 * 24 * time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return s, a, key, now
}
func testRecord(t *testing.T, now time.Time, script []byte) ([]byte, []AttachmentInput) {
	t.Helper()
	command := []byte("true")
	e := auditrecord.Envelope{SchemaVersion: 1, EventID: "event-1", EventType: auditrecord.ExecutionAdmission, Actor: auditrecord.Actor{UserID: "user", PersonID: "person", Name: "SYNTHETIC_SECRET_actor", Provider: "local", Subject: "subject"}, PolicyVersion: 1, PolicySHA256: auditrecord.Hash([]byte("policy")), OccurredAt: now, Command: command, Execution: &auditrecord.ExecutionBinding{ExecutionID: "exec", PreparationID: "prep", BootID: "boot", NodeID: "node", NodeName: "node", Identity: auditrecord.Identity{Username: "user", UID: 1000, GID: 1000, Groups: []uint32{1000}, GroupsSHA256: auditrecord.Hash([]byte("groups")), IdentitySHA256: auditrecord.Hash([]byte("identity")), Home: "/home/user", Shell: "/bin/sh", CWD: "/home/user"}, CommandSHA256: auditrecord.Hash(command), CommandBytes: int64(len(command)), PreparedUntil: now.Add(time.Minute), Limits: auditrecord.Limits{MaxFrameBytes: 64 << 10, MaxBufferBytes: 2 << 20, RuntimeSeconds: 3600, TermGraceSeconds: 3, BlockedConsumerSeconds: 30}}}
	var inputs []AttachmentInput
	if script != nil {
		e.Command = []byte("sh -s")
		e.Execution.CommandSHA256 = auditrecord.Hash(e.Command)
		e.Execution.CommandBytes = int64(len(e.Command))
		e.Execution.ScriptSHA256 = auditrecord.Hash(script)
		e.Execution.ScriptBytes = int64(len(script))
		e.Attachments = []auditrecord.Attachment{{ID: "script", SHA256: auditrecord.Hash(script), Bytes: int64(len(script))}}
		inputs = []AttachmentInput{{ID: "script", Reader: bytes.NewReader(script)}}
	}
	raw, _ := json.Marshal(e)
	return raw, inputs
}

func TestProtectedOrderAndIdempotency(t *testing.T) {
	s, a, key, now := testService(t)
	raw, inputs := testRecord(t, now, []byte("SYNTHETIC_SECRET_script\n"))
	r, err := s.Preserve(context.Background(), raw, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.order) != 3 || !strings.HasPrefix(a.order[0], "attachments/") || !strings.HasPrefix(a.order[1], "envelopes/") || a.order[2] != "manifests/event-1" {
		t.Fatalf("wrong publication order %v", a.order)
	}
	expected, _, _ := auditrecord.ExpectedFor(raw)
	expected.MinRetainUntil = now.Add(24 * time.Hour)
	v, _ := auditgate.NewVerifier(auditgate.VerifierConfig{Issuer: "ingest", Audience: "hub", Keys: map[string]*ecdsa.PublicKey{"key-1": &key.PublicKey}, QualificationSHA256: a.q.Digest, MaxTTL: time.Minute})
	if _, err = v.Verify(r.Token, expected, now); err != nil {
		t.Fatal(err)
	}
	_, inputs = testRecord(t, now, []byte("SYNTHETIC_SECRET_script\n"))
	again, err := s.Preserve(context.Background(), raw, inputs)
	if err != nil || again.Manifest.VersionID != r.Manifest.VersionID || len(a.order) != 3 {
		t.Fatal("idempotency created another version")
	}
	different := append([]byte(" "), raw...)
	_, inputs = testRecord(t, now, []byte("SYNTHETIC_SECRET_script\n"))
	if _, err = s.Preserve(context.Background(), different, inputs); !errors.Is(err, ErrConflict) {
		t.Fatal("different exact bytes accepted")
	}
	s.config.Now = func() time.Time { return now.Add(2 * time.Minute) }
	_, inputs = testRecord(t, now, []byte("SYNTHETIC_SECRET_script\n"))
	if _, err = s.Preserve(context.Background(), raw, inputs); err == nil {
		t.Fatal("expired receipt renewed")
	}
}

func TestNoReceiptForPartialArchive(t *testing.T) {
	for _, prefix := range []string{"attachments/", "envelopes/", "manifests/"} {
		t.Run(prefix, func(t *testing.T) {
			s, a, _, now := testService(t)
			a.failPut = prefix
			raw, in := testRecord(t, now, []byte("script"))
			r, err := s.Preserve(context.Background(), raw, in)
			if err == nil || r.Token != "" {
				t.Fatal("partial write authorized")
			}
			if prefix != "manifests/" {
				for _, key := range a.order {
					if strings.HasPrefix(key, "manifests/") {
						t.Fatal("published incomplete manifest")
					}
				}
			}
		})
	}
	for _, prefix := range []string{"attachments/", "envelopes/", "manifests/"} {
		t.Run("verify-"+prefix, func(t *testing.T) {
			s, a, _, now := testService(t)
			a.failVerify = prefix
			raw, in := testRecord(t, now, []byte("script"))
			if r, err := s.Preserve(context.Background(), raw, in); err == nil || r.Token != "" {
				t.Fatal("unprotected version authorized")
			}
		})
	}
	s, _, _, now := testService(t)
	raw, in := testRecord(t, now, []byte("script"))
	in[0].Reader = bytes.NewReader([]byte("wrong!"))
	if _, err := s.Preserve(context.Background(), raw, in); !errors.Is(err, auditrecord.ErrSchema) {
		t.Fatal("wrong attachment accepted")
	}
}

func TestLostRepliesReconcileExactVersions(t *testing.T) {
	for _, prefix := range []string{"attachments/", "envelopes/", "manifests/"} {
		t.Run(prefix, func(t *testing.T) {
			s, a, _, now := testService(t)
			a.lostReply = prefix
			raw, in := testRecord(t, now, []byte("script"))
			if _, err := s.Preserve(context.Background(), raw, in); err != nil {
				t.Fatal(err)
			}
			if len(a.order) != 3 {
				t.Fatal("ambiguous write overwritten")
			}
		})
	}
}

func TestConcurrentEventWinner(t *testing.T) {
	s, a, _, now := testService(t)
	raw, _ := testRecord(t, now, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := raw
			if i%2 == 1 {
				data = append([]byte(" "), raw...)
			}
			_, err := s.Preserve(context.Background(), data, nil)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
	if success == 0 {
		t.Fatal("no winner")
	}
	count := 0
	for _, key := range a.order {
		if key == "manifests/event-1" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("more than one manifest version")
	}
}

func TestOriginalReadNeedsPreservedIntent(t *testing.T) {
	s, a, _, now := testService(t)
	raw, _ := testRecord(t, now, nil)
	receipt, err := s.Preserve(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m auditrecord.Manifest
	json.Unmarshal(a.objects[receipt.Manifest.Key].data, &m)
	if _, err = s.ReadOriginal(context.Background(), m.Envelope, receipt.Token); err == nil {
		t.Fatal("admission token authorized original access")
	}
	e := auditrecord.Envelope{SchemaVersion: 1, EventID: "read-1", EventType: auditrecord.OriginalReadIntent, Actor: auditrecord.Actor{UserID: "reader", PersonID: "reader", Name: "reader"}, PolicyVersion: 1, PolicySHA256: auditrecord.Hash([]byte("policy")), OccurredAt: now, Details: &auditrecord.Details{CorrelationID: "access", SessionSHA256: auditrecord.Hash([]byte("session")), Reason: "incident", Originals: []auditrecord.ObjectRef{m.Envelope}}}
	intentBytes, _ := json.Marshal(e)
	intent, err := s.Preserve(context.Background(), intentBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	original, err := s.ReadOriginal(context.Background(), m.Envelope, intent.Token)
	if err != nil || !bytes.Equal(raw, original) {
		t.Fatal("preserved read intent rejected")
	}
	wrong := m.Envelope
	wrong.VersionID = "other"
	if _, err = s.ReadOriginal(context.Background(), wrong, intent.Token); err == nil {
		t.Fatal("wrong exact version released")
	}
	s.config.Now = func() time.Time { return now.Add(61 * time.Second) }
	if _, err = s.ReadOriginal(context.Background(), m.Envelope, intent.Token); err == nil {
		t.Fatal("expired access released originals")
	}
}

func TestQualificationCannotBeBypassed(t *testing.T) {
	q := validQualification()
	b, _ := json.Marshal(q)
	loaded, err := LoadQualification(b, auditrecord.Hash(b))
	if err != nil || loaded.Digest != auditrecord.Hash(b) {
		t.Fatal(err)
	}
	if _, err = LoadQualification(b, auditrecord.Hash(nil)); err == nil {
		t.Fatal("unreviewed report accepted")
	}
	for i := range requiredChecks {
		q := validQualification()
		q.Checks = append(q.Checks[:i], q.Checks[i+1:]...)
		if q.Validate() == nil {
			t.Fatal("missing mandatory qualification accepted")
		}
	}
	q = validQualification()
	q.VerifiedAt = time.Now().Add(time.Hour)
	if q.Validate() == nil {
		t.Fatal("future proof accepted")
	}
	q = validQualification()
	q.ArchiveEndpoint = "http://archive"
	if q.Validate() == nil {
		t.Fatal("cleartext qualified")
	}
	s, _, _, _ := testService(t)
	bad := s.config
	bad.Archive = newMemoryArchive()
	bad.Archive.(*memoryArchive).q.Checks = nil
	if _, err = NewService(bad); err == nil {
		t.Fatal("unqualified service started")
	}
}
