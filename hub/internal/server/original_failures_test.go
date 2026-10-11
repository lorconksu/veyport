package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

type countedOriginalReader struct {
	reader auditgate.OriginalReader
	calls  *atomic.Int32
}

func (r countedOriginalReader) ReadOriginal(ctx context.Context, ref auditrecord.ObjectRef, token string) (io.ReadCloser, error) {
	r.calls.Add(1)
	return r.reader.ReadOriginal(ctx, ref, token)
}

func TestOriginalRESTCrashRecoveryRecordsUnknownCountWithoutReading(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	issued := h.handle(t, "Crash investigation", "envelope")
	var reads atomic.Int32
	h.setReader(func(reader auditgate.OriginalReader) auditgate.OriginalReader {
		return countedOriginalReader{reader: reader, calls: &reads}
	})
	// Simulate process loss immediately after the durable one-use claim, before
	// the handler can record a start/result. Recovery must not open the original.
	a, err := h.s.store.ConsumeOriginalAccess(auditrecord.Hash([]byte(issued.Handle)), "original-reader", h.sid, h.clock.Now(), h.s.lockoutPolicy().SessionIdle)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(3 * time.Minute)
	h.s.recoverOriginalEvidence(context.Background())
	h.awaitAccess(t, issued.Handle, "unconfirmed", "confirmed")
	found := false
	for _, e := range h.fixture.Originals.Envelopes() {
		if e.EventID == a.ID+".result" {
			found = true
			if e.Details.State != "unconfirmed" || e.Details.Delivery == nil || e.Details.Delivery.BytesWritten != nil || e.Details.Delivery.Scope != "hub_response" {
				t.Fatal("crash recovery fabricated a known delivery count")
			}
		}
	}
	if !found || reads.Load() != 0 {
		t.Fatal("recovery missed the result or opened an original")
	}
	h.json(t, "GET", issued.DownloadURL, h.token, nil, 403)
}

func TestOriginalRESTFreshMFAMalformedInputsAndNoAPIToken(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	path := "/api/executions/" + h.execution.ID + "/original-access"
	for _, bad := range []originalRequest{{Purpose: "", Records: []string{"envelope"}}, {Purpose: " padded ", Records: []string{"envelope"}}, {Purpose: "line\nbreak", Records: []string{"envelope"}}, {Purpose: "review", Records: []string{"envelope", "script"}}, {Purpose: "review", Records: []string{"unknown"}}} {
		h.json(t, "POST", path+"/preview", h.token, bad, 400)
	}
	preview := h.preview(t, "Fresh proof", "envelope")
	h.json(t, "POST", path, h.token, originalRequest{Purpose: "Fresh proof", Records: []string{"envelope"}, Digest: preview.Digest}, 403)
	proof := h.proof(t, "Fresh proof", "envelope", preview)
	h.clock.Advance(5 * time.Minute)
	h.json(t, "POST", path, h.token, originalRequest{Purpose: "Fresh proof", Records: []string{"envelope"}, Digest: preview.Digest, StepupProof: proof}, 403)
	token, hash, _, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if err = h.s.store.CreateAPIToken(&model.APIToken{ID: "original-api-token", UserID: "original-reader", Name: "synthetic-automation", TokenHash: hash, CreatedAt: h.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	h.json(t, "POST", path+"/preview", token, originalRequest{Purpose: "review", Records: []string{"envelope"}}, 403)
	h.json(t, "POST", path+"/step-up", token, originalRequest{Purpose: "review", Records: []string{"envelope"}, Digest: preview.Digest, Code: "123456"}, 403)
	h.json(t, "GET", "/api/audit-originals/"+strings.Repeat("a", 64), token, nil, 403)
	h.json(t, "GET", "/api/executions", token, nil, 200)
}

func TestOriginalRESTUnpreparedExecutionDoesNotInventRootIdentity(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	e := &model.Execution{ID: "denied-unprepared", ActorID: "original-reader", NodeID: "node", CommandSHA256: strings.Repeat("a", 64), CommandLength: 1, Enhanced: true, PolicyVersion: "2", PolicySHA256: h.execution.PolicySHA256}
	if err := h.s.store.CreateExecution(e); err != nil {
		t.Fatal(err)
	}
	if err := h.s.store.FinishExecution(e.ID, "denied", nil, "", "SYNTHETIC_DENIAL_ERROR_CANARY"); err != nil {
		t.Fatal(err)
	}
	raw := h.json(t, "GET", "/api/executions/"+e.ID, h.token, nil, 200)
	if !strings.Contains(string(raw), `"preparation":null`) || strings.Contains(string(raw), `"uid":0`) || strings.Contains(string(raw), "SYNTHETIC_DENIAL_ERROR_CANARY") {
		t.Fatalf("unprepared identity:%s", raw)
	}
	h.json(t, "POST", "/api/executions/"+e.ID+"/original-access/preview", h.token, originalRequest{Purpose: "review", Records: []string{"envelope"}}, 403)
	// Filters refer to prepared OS identity, so this denied row cannot match UID/user fiction.
	raw = h.json(t, "GET", "/api/executions?os_user=synthetic-os-user&limit=1", h.token, nil, 200)
	if !strings.Contains(string(raw), `"total":1`) || strings.Contains(string(raw), e.ID) {
		t.Fatal("prepared OS-user filter included an unprepared denial")
	}
	h.json(t, "GET", "/api/executions?unknown=value", h.token, nil, 400)
}

func TestOriginalRESTLostRepliesReconcileExactIntentWithoutRetryingRead(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	h.fixture.SetFault("lose-original_read.intent")
	issued := h.handle(t, "Lost reply investigation", "envelope")
	h.fixture.SetFault("lose-original_read.result")
	response := h.request(t, "GET", issued.DownloadURL, h.token, nil)
	raw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(raw) != string(h.raw) {
		t.Fatal("lost evidence reply blocked already preserved exact intent")
	}
	h.awaitAccess(t, issued.Handle, "completed", "confirmed")
	h.fixture.SetFault("")
	h.json(t, "GET", issued.DownloadURL, h.token, nil, 403)
}

func TestOriginalRESTClosedArchiveConsumesHandleWithoutReleasingBytes(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	issued := h.handle(t, "Closed archive investigation", "envelope")
	h.fixture.Originals.SetFailed(true)
	h.json(t, "GET", issued.DownloadURL, h.token, nil, 503)
	a := h.access(t, issued.Handle)
	if a.ConsumedAt == nil || a.State != "unconfirmed" || a.BytesWritten != 0 {
		t.Fatal("closed archive reopened permit or fabricated delivery")
	}
	h.fixture.Originals.SetFailed(false)
	h.json(t, "GET", issued.DownloadURL, h.token, nil, 403)
}

func awaitInterruptedOriginal(t *testing.T, h *originalHTTP, handle string) model.OriginalAccess {
	t.Helper()
	deadline := time.Now().Add(9 * time.Second)
	for {
		a := h.access(t, handle)
		if a.State == "interrupted" && a.EvidenceState == "confirmed" {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream did not stop within write bound: state=%s evidence=%s", a.State, a.EvidenceState)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOriginalRESTClientAbortTruthfullyArchivesInterruptedDelivery(t *testing.T) {
	script := []byte(strings.Repeat("SYNTHETIC_ABORT_CANARY\n", 700000)) // below16MiB; larger than TCP buffers.
	h := newOriginalHTTP(t, script)
	issued := h.handle(t, "Aborted investigation", "script")
	response := h.request(t, "GET", issued.DownloadURL, h.token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("download did not start")
	}
	var first [128]byte
	if _, err := io.ReadFull(response.Body, first[:]); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	a := awaitInterruptedOriginal(t, h, issued.Handle)
	if a.BytesWritten <= 0 || a.BytesWritten >= int64(len(script)) {
		t.Fatal("abort reported full completion or lost known byte count")
	}
	h.json(t, "GET", issued.DownloadURL, h.token, nil, 403)
}

func TestOriginalRESTSlowConsumerHasBoundedWriteWithoutWriterGoroutine(t *testing.T) {
	script := []byte(strings.Repeat("SYNTHETIC_SLOW_CANARY\n", 700000))
	h := newOriginalHTTP(t, script)
	issued := h.handle(t, "Slow consumer investigation", "script")
	u, err := url.Parse(h.api.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err = tcp.SetReadBuffer(1024); err != nil {
			t.Fatal(err)
		}
	}
	started := time.Now()
	if _, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", issued.DownloadURL, u.Host, h.token); err != nil {
		t.Fatal(err)
	}
	// Deliberately never read the socket. The underlying write deadline must
	// release the handler, rather than a cancellation goroutine leaking a writer.
	a := awaitInterruptedOriginal(t, h, issued.Handle)
	if elapsed := time.Since(started); elapsed > 8*time.Second {
		t.Fatalf("write remained blocked:%s", elapsed)
	}
	if a.BytesWritten >= int64(len(script)) {
		t.Fatal("slow unread consumer reported completion")
	}
	if a.ConsumedAt == nil {
		t.Fatal("bounded failed stream did not consume handle")
	}
	h.s.recoverOriginalEvidence(context.Background())
}
