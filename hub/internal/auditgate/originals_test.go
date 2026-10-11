package auditgate

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func TestArchivedAdmissionIsMetadataOnlyNotFreshAuthority(t *testing.T) {
	v, key, claims, expected, now := fixture(t)
	token := sign(t, key, claims)
	if _, err := v.VerifyArchivedAdmission(token, expected, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Consume(context.Background(), token, expected, now.Add(time.Hour), &replayConsumer{}); err == nil {
		t.Fatal("retained receipt renewed execution")
	}
	if _, err := v.VerifyReadEvidence(token, expected, now.Add(time.Hour)); err == nil {
		t.Fatal("admission treated as read evidence")
	}
	expected.RecordSHA256 = auditrecord.Hash([]byte("replacement-record"))
	if _, err := v.VerifyArchivedAdmission(token, expected, now.Add(time.Hour)); err == nil {
		t.Fatal("wrong archived record selected")
	}
	_, _, _, expected, _ = fixture(t)
	for _, bad := range []string{"", strings.Repeat("x", auditrecord.MaxReceiptBytes+1), "a.b.c", "e30.e30.signature"} {
		if _, err := v.VerifyArchivedAdmission(bad, expected, now.Add(time.Hour)); err == nil {
			t.Fatal("malformed retained token accepted")
		}
	}
	var missing *Verifier
	if _, err := missing.VerifyArchivedAdmission(token, expected, now); err == nil {
		t.Fatal("nil verifier accepted")
	}
	if _, err := v.VerifyArchivedAdmission(token, expected, now.Add(-time.Hour)); err == nil {
		t.Fatal("future issuance accepted")
	}
}

func TestReadEvidenceCannotReleaseExpiredOriginals(t *testing.T) {
	v, key, claims, expected, now := fixture(t)
	expected.EventType = auditrecord.OriginalReadIntent
	expected.Execution = nil
	claims.EventType = expected.EventType
	claims.ExecutionID = ""
	claims.PreparationID = ""
	claims.BootID = ""
	claims.NodeID = ""
	claims.IdentitySHA256 = ""
	token := sign(t, key, claims)
	if _, err := v.VerifyReadEvidence(token, expected, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(token, expected, now.Add(time.Hour)); err == nil {
		t.Fatal("historical intent renewed live read permit")
	}
	if _, err := v.VerifyArchivedAdmission(token, expected, now); err == nil {
		t.Fatal("intent treated as archived admission")
	}
	expected.EventType = auditrecord.OriginalReadResult
	claims.EventType = expected.EventType
	if _, err := v.VerifyReadEvidence(sign(t, key, claims), expected, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestManifestClientBindsExactVersionHashAndLength(t *testing.T) {
	raw := []byte(`{"metadata":"only"}`)
	ref := auditrecord.ObjectRef{Bucket: "archive", Key: "manifests/event", VersionID: "exact+/version?", SHA256: auditrecord.Hash(raw), Bytes: int64(len(raw)), RetainUntil: time.Now().Add(time.Hour)}
	hash := auditrecord.Hash([]byte("original"))
	calls := 0
	c := &Client{endpoint: "https://archive.invalid", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/v1/manifests/event" || r.URL.Query().Get("sha256") != hash || r.URL.Query().Get("version_id") != ref.VersionID {
			t.Fatal("metadata request lost exact version")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
	})}}
	if b, err := c.Manifest(context.Background(), "event", hash, ref); err != nil || string(b) != string(raw) {
		t.Fatalf("manifest:%s %v", b, err)
	}
	bad := ref
	bad.SHA256 = auditrecord.Hash([]byte("different"))
	if _, err := c.Manifest(context.Background(), "event", hash, bad); err == nil {
		t.Fatal("wrong exact bytes accepted")
	}
	bad = ref
	bad.Bytes++
	if _, err := c.Manifest(context.Background(), "event", hash, bad); err == nil {
		t.Fatal("wrong length accepted")
	}
	bad = ref
	bad.Key = "envelopes/event"
	if _, err := c.Manifest(context.Background(), "event", hash, bad); err == nil {
		t.Fatal("metadata client could read envelope")
	}
	if calls != 3 {
		t.Fatalf("invalid ref reached HTTP:%d", calls)
	}
}
