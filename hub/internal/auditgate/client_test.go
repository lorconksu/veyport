package auditgate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type generatedReader struct {
	remaining int64
	maxRead   int
	consumed  int64
	closed    bool
}

func (r *generatedReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	r.remaining -= int64(n)
	r.consumed += int64(n)
	return n, nil
}
func (r *generatedReader) Close() error { r.closed = true; return nil }

func clientEnvelope(now time.Time, scriptLen int64, scriptHash string) []byte {
	command := []byte("true")
	e := auditrecord.Envelope{SchemaVersion: 1, EventID: "event", EventType: auditrecord.ExecutionAdmission, Actor: auditrecord.Actor{UserID: "user", PersonID: "person", Name: "actor"}, PolicyVersion: 1, PolicySHA256: auditrecord.Hash(nil), OccurredAt: now, Command: command, Execution: &auditrecord.ExecutionBinding{ExecutionID: "exec", PreparationID: "prep", BootID: "boot", NodeID: "node", Identity: auditrecord.Identity{Username: "u", UID: 1000, GID: 1000, GroupsSHA256: auditrecord.Hash(nil), IdentitySHA256: auditrecord.Hash([]byte("identity")), Home: "/home/u", Shell: "/bin/sh", CWD: "/home/u"}, CommandSHA256: auditrecord.Hash(command), CommandBytes: 4, PreparedUntil: now.Add(time.Minute), Limits: auditrecord.Limits{MaxFrameBytes: 65536, MaxBufferBytes: 2097152, RuntimeSeconds: 60, TermGraceSeconds: 3, BlockedConsumerSeconds: 30}}}
	if scriptHash != "" {
		e.Command = []byte("sh -s")
		e.Execution.CommandSHA256 = auditrecord.Hash(e.Command)
		e.Execution.CommandBytes = 5
		e.Execution.ScriptSHA256 = scriptHash
		e.Execution.ScriptBytes = scriptLen
		e.Attachments = []auditrecord.Attachment{{ID: "script", SHA256: scriptHash, Bytes: scriptLen}}
	}
	b, _ := json.Marshal(e)
	return b
}
func fakeReceipt(now time.Time) auditrecord.Receipt {
	return auditrecord.Receipt{Token: "signed", Manifest: auditrecord.ObjectRef{Bucket: "archive", Key: "manifest", VersionID: "version", SHA256: auditrecord.Hash(nil), Bytes: 1, RetainUntil: now.Add(time.Hour)}}
}
func jsonResponse(v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header), ContentLength: int64(len(b))}
}

func TestSixteenMiBAttachmentStreamsWithBoundedReads(t *testing.T) {
	now := time.Now()
	hashReader := &generatedReader{remaining: 16 << 20}
	h := sha256.New()
	_, _ = io.Copy(h, hashReader)
	hash := hex.EncodeToString(h.Sum(nil))
	source := &generatedReader{remaining: 16 << 20}
	raw := clientEnvelope(now, 16<<20, hash)
	requests := 0
	c := &Client{endpoint: "https://audit.example", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if source.consumed != 0 {
			t.Fatal("attachment buffered before request")
		}
		reader, err := r.MultipartReader()
		if err != nil {
			t.Fatal(err)
		}
		part, err := reader.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(part)
		if !bytes.Equal(b, raw) {
			t.Fatal("exact envelope changed")
		}
		part, err = reader.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.CopyBuffer(io.Discard, part, make([]byte, 64<<10))
		if err != nil || n != 16<<20 {
			t.Fatal("attachment stream incomplete", n, err)
		}
		if _, err = reader.NextPart(); err != io.EOF {
			t.Fatal("extra part")
		}
		return jsonResponse(fakeReceipt(now)), nil
	})}}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := c.Preserve(context.Background(), raw, []AttachmentInput{{ID: "script", Reader: source}})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || source.maxRead > 32<<10 || source.consumed != 16<<20 || !source.closed {
		t.Fatal("unbounded reads, retry or leaked reader")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2<<20 {
		t.Fatalf("hub submission allocated %d bytes", allocated)
	}
	t.Logf("16MiB streamed; maximum attachment read %d; submission allocation %d", source.maxRead, after.TotalAlloc-before.TotalAlloc)
}

func TestStreamingCancellationAndWrongHashes(t *testing.T) {
	now := time.Now()
	for _, cancelRequest := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		source := &generatedReader{remaining: 16 << 20}
		raw := clientEnvelope(now, 16<<20, auditrecord.Hash(nil))
		requests := 0
		c := &Client{endpoint: "https://audit.example", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			requests++
			if cancelRequest {
				_, _ = io.CopyN(io.Discard, r.Body, 64<<10)
				cancel()
				_ = r.Body.Close()
				return nil, ctx.Err()
			}
			_, err := io.Copy(io.Discard, r.Body)
			return nil, err
		})}}
		if _, err := c.Preserve(ctx, raw, []AttachmentInput{{ID: "script", Reader: source}}); err == nil {
			t.Fatal("cancelled/wrong content admitted")
		}
		cancel()
		if !source.closed || requests != 1 {
			t.Fatal("cancelled input leaked or retried")
		}
		if cancelRequest && source.consumed >= 16<<20 {
			t.Fatal("cancelled request drained entire script")
		}
	}
}

func TestPinnedTLSClientAndOriginalRead(t *testing.T) {
	now := time.Now()
	raw := clientEnvelope(now, 0, "")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 32) {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v1/originals" {
			w.Header().Set("Content-Length", "4")
			_, _ = w.Write([]byte("data"))
			return
		}
		if r.URL.Path == "/v1/records/event" {
			_ = json.NewEncoder(w).Encode(fakeReceipt(now))
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_ = json.NewEncoder(w).Encode(fakeReceipt(now))
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	config := ClientConfig{Endpoint: server.URL, AllowedHosts: []string{u.Host}, AllowedAddresses: []string{"127.0.0.1"}, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, Bearer: strings.Repeat("s", 32)}
	c, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Preserve(context.Background(), raw, nil); err != nil {
		t.Fatal(err)
	}
	ref := fakeReceipt(now).Manifest
	ref.Bytes = 4
	original, err := c.ReadOriginal(context.Background(), ref, "intent")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(original)
	original.Close()
	if string(b) != "data" {
		t.Fatal("read changed")
	}
	if _, err = c.Lookup(context.Background(), "event", auditrecord.Hash(raw)); err != nil {
		t.Fatal(err)
	}
	config.AllowedAddresses = nil
	if _, err = NewClient(config); err == nil {
		t.Fatal("loopback implicitly permitted")
	}
	config.AllowedAddresses = []string{"169.254.169.254"}
	if _, err = NewClient(config); err == nil {
		t.Fatal("metadata pin accepted")
	}
	config.AllowedAddresses = []string{"127.0.0.2"}
	bad, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bad.Preserve(context.Background(), raw, nil); err == nil {
		t.Fatal("address pin not enforced")
	}
	config.AllowedAddresses = []string{"127.0.0.1"}
	config.TLS.InsecureSkipVerify = true
	if _, err = NewClient(config); err == nil {
		t.Fatal("unverified TLS permitted")
	}
}

type receiptPreserver struct {
	r   auditrecord.Receipt
	err error
}

func (p receiptPreserver) Preserve(context.Context, []byte, []AttachmentInput) (auditrecord.Receipt, error) {
	return p.r, p.err
}
func TestGateMatchesLivePreparationBeforeConsuming(t *testing.T) {
	v, k, c, _, now := fixture(t)
	raw := clientEnvelope(now, 0, "")
	expected, e, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.EventID = expected.EventID
	c.ID = expected.EventID
	c.RecordSHA256 = expected.RecordSHA256
	c.ActorSHA256 = expected.ActorSHA256
	c.BindingSHA256 = expected.BindingSHA256
	c.PolicySHA256 = expected.PolicySHA256
	c.IdentitySHA256 = e.Execution.Identity.IdentitySHA256
	consumer := &replayConsumer{}
	receipt := auditrecord.Receipt{Token: sign(t, k, c), Manifest: c.Manifest}
	g := Gate{Preserver: receiptPreserver{r: receipt}, Verifier: v, Consumer: consumer, Now: func() time.Time { return now }}
	live := *e.Execution
	live.Identity.UID++
	if _, err = g.Admit(context.Background(), raw, nil, live, now.Add(time.Hour)); err == nil || consumer.used {
		t.Fatal("changed prepared identity consumed permit")
	}
	live = *e.Execution
	if _, err = g.Admit(context.Background(), raw, nil, live, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = g.Admit(context.Background(), raw, nil, live, now.Add(time.Hour)); !errors.Is(err, ErrReplay) {
		t.Fatal("duplicate launch admitted")
	}
}
