package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

type originalFaultSource struct {
	reader auditgate.OriginalReader
	mode   string
	data   []byte
	closed *atomic.Int32
}

func (f originalFaultSource) ReadOriginal(ctx context.Context, ref auditrecord.ObjectRef, token string) (io.ReadCloser, error) {
	if f.mode == "open-error" {
		return nil, errors.New("SYNTHETIC_UPSTREAM_SECRET_CANARY")
	}
	upstream, err := f.reader.ReadOriginal(ctx, ref, token)
	if err != nil {
		return nil, err
	}
	return &originalFaultBody{ReadCloser: upstream, mode: f.mode, data: append([]byte(nil), f.data...), closed: f.closed}, nil
}

type originalFaultBody struct {
	io.ReadCloser
	mode   string
	data   []byte
	closed *atomic.Int32
}

func (b *originalFaultBody) Read(p []byte) (int, error) {
	if b.mode == "empty" {
		return 0, nil
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	if len(b.data) == 0 {
		if b.mode == "read-error" {
			return n, errors.New("SYNTHETIC_UPSTREAM_SECRET_CANARY")
		}
		return n, io.EOF
	}
	return n, nil
}

func (b *originalFaultBody) Close() error { b.closed.Add(1); return b.ReadCloser.Close() }

func TestOriginalRESTSourceFaultsKeepTruthfulCountsAndNeverRenewHandles(t *testing.T) {
	script := []byte("synthetic-original-input\n")
	h := newOriginalHTTP(t, script)
	for _, tc := range []struct {
		name string
		data []byte
		want int64
	}{
		{"open-error", nil, 0},
		{"empty", nil, 0},
		{"read-error", script[:3], 3},
		{"short-eof", script[:4], 4},
		{"oversize", append(append([]byte(nil), script...), 'x'), 0},
		{"wrong-hash", bytes.Repeat([]byte{'x'}, len(script)), int64(len(script))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issued := h.handle(t, "Investigate source "+tc.name, "script")
			var closed atomic.Int32
			h.setReader(func(reader auditgate.OriginalReader) auditgate.OriginalReader {
				return originalFaultSource{reader: reader, mode: tc.name, data: tc.data, closed: &closed}
			})
			response := h.request(t, "GET", issued.DownloadURL, h.token, nil)
			raw, _ := io.ReadAll(response.Body) // short Content-Length must surface EOF to callers.
			response.Body.Close()
			if tc.name == "open-error" && (response.StatusCode != 503 || bytes.Contains(raw, []byte("SECRET_CANARY"))) {
				t.Fatal("upstream error escaped or became successful download")
			}
			a := h.awaitAccess(t, issued.Handle, "interrupted", "confirmed")
			if a.BytesWritten != tc.want || a.ConsumedAt == nil {
				t.Fatalf("source failure claimed wrong delivery count: state=%s bytes=%d", a.State, a.BytesWritten)
			}
			if tc.name != "open-error" && closed.Load() != 1 {
				t.Fatal("upstream body was not closed exactly once")
			}
			h.json(t, "GET", issued.DownloadURL, h.token, nil, 403)
			h.setReader(nil)
		})
	}
}

type originalFaultWriter struct {
	*httptest.ResponseRecorder
	mode      string
	deadlines int
}

func (w *originalFaultWriter) SetWriteDeadline(time.Time) error {
	w.deadlines++
	if w.mode == "deadline" && w.deadlines == 2 {
		return errors.New("connection deadline unavailable")
	}
	return nil
}
func (w *originalFaultWriter) Write(p []byte) (int, error) {
	if w.mode == "short-write" {
		return w.ResponseRecorder.Write(p[:2])
	}
	return w.ResponseRecorder.Write(p)
}
func (w *originalFaultWriter) FlushError() error {
	if w.mode == "flush" {
		return io.ErrClosedPipe
	}
	w.ResponseRecorder.Flush()
	return nil
}

func TestOriginalDownloadWriterFailuresConsumeBeforeBytesAndArchiveOutcome(t *testing.T) {
	h := newOriginalHTTP(t, []byte("synthetic-write-test\n"))
	for _, tc := range []struct {
		mode string
		want int64
	}{
		{"unsupported", 0}, {"deadline", 0}, {"short-write", 2}, {"flush", int64(len(h.script))},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			issued := h.handle(t, "Investigate writer "+tc.mode, "script")
			request := httptest.NewRequest("GET", issued.DownloadURL, nil)
			request.SetPathValue("handle", issued.Handle)
			request.Header.Set("Authorization", "Bearer "+h.token)
			base := httptest.NewRecorder()
			var writer http.ResponseWriter = base
			if tc.mode != "unsupported" {
				writer = &originalFaultWriter{ResponseRecorder: base, mode: tc.mode}
			}
			// Use the normal access-token middleware and live recorded session;
			// only the downstream writer's failure is injected here.
			h.s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(h.s.handleOriginalDownload)).ServeHTTP(writer, request)
			a := h.awaitAccess(t, issued.Handle, "interrupted", "confirmed")
			if a.BytesWritten != tc.want || a.ConsumedAt == nil {
				t.Fatal("writer error reported false completion or lost one-use claim")
			}
			if tc.mode == "unsupported" && (base.Code != 503 || bytes.Contains(base.Body.Bytes(), h.script)) {
				t.Fatal("unsupported bounded writer released original bytes")
			}
			h.json(t, "GET", issued.DownloadURL, h.token, nil, 403)
		})
	}
}

func TestOriginalRESTMetadataAndMFARejectMalformedOrStaleState(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	for _, query := range []string{"node_id=a&node_id=b", "actor_id=" + strings.Repeat("a", 257)} {
		h.json(t, "GET", "/api/executions?"+query, h.token, nil, 400)
	}
	h.json(t, "GET", "/api/executions?limit=200", h.token, nil, 200)
	h.json(t, "GET", "/api/executions/absent", h.token, nil, 404)
	h.json(t, "GET", "/api/audit-originals/bad", h.token, nil, 403)
	path := "/api/executions/" + h.execution.ID + "/original-access"
	preview := h.preview(t, "Malformed step-up", "envelope")
	h.json(t, "POST", path+"/preview", h.token, originalRequest{Purpose: "Malformed step-up", Records: []string{"envelope"}, Digest: preview.Digest}, 400)
	h.clock.Advance(61 * time.Second) // honor the real shared MFA rate limiter.
	h.json(t, "POST", path+"/step-up", h.token, originalRequest{Purpose: "Malformed step-up", Records: []string{"envelope"}, Digest: strings.Repeat("0", 64), Code: "123456"}, 403)
	h.clock.Advance(61 * time.Second)
	h.json(t, "POST", path+"/step-up", h.token, originalRequest{Purpose: "Malformed step-up", Records: []string{"envelope"}, Digest: preview.Digest, Code: "not-a-code"}, 403)
	h.exec(t, "UPDATE users SET totp_secret=NULL WHERE id='original-reader'")
	h.clock.Advance(61 * time.Second)
	h.json(t, "POST", path+"/step-up", h.token, originalRequest{Purpose: "Malformed step-up", Records: []string{"envelope"}, Digest: preview.Digest, Code: "123456"}, 403)
	h.exec(t, "UPDATE users SET totp_secret='corrupt-private-ciphertext' WHERE id='original-reader'")
	h.clock.Advance(61 * time.Second)
	h.json(t, "POST", path+"/step-up", h.token, originalRequest{Purpose: "Malformed step-up", Records: []string{"envelope"}, Digest: preview.Digest, Code: "123456"}, 403)
	h.exec(t, "DELETE FROM user_roles WHERE user_id='original-reader'")
	h.json(t, "GET", "/api/executions", h.token, nil, 401)
	h.json(t, "GET", "/api/executions/"+h.execution.ID, h.token, nil, 401)
}

func TestOriginalRESTHistoricalTrustFailuresReturnOpaqueErrorsWithoutHandles(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	path := "/api/executions/" + h.execution.ID + "/original-access/preview"
	request := originalRequest{Purpose: "Historical evidence", Records: []string{"envelope"}}
	for _, tc := range []struct{ column, value string }{
		{"policy_version", "not-a-version"}, {"policy_sha256", strings.Repeat("0", 64)}, {"admission_receipt", "SYNTHETIC_RECEIPT_CANARY"},
	} {
		t.Run(tc.column, func(t *testing.T) {
			var previous string
			if err := h.s.store.DB().QueryRow("SELECT "+tc.column+" FROM executions WHERE id=?", h.execution.ID).Scan(&previous); err != nil {
				t.Fatal(err)
			}
			h.exec(t, "UPDATE executions SET "+tc.column+"=? WHERE id=?", tc.value, h.execution.ID)
			raw := h.json(t, "POST", path, h.token, request, 503)
			if bytes.Contains(raw, []byte("CANARY")) {
				t.Fatal("private upstream trust material leaked")
			}
			h.exec(t, "UPDATE executions SET "+tc.column+"=? WHERE id=?", previous, h.execution.ID)
		})
	}
	h.clock.Advance(49 * time.Hour)
	if _, err := h.s.selectOriginal(context.Background(), h.execution.ID, request); err == nil {
		t.Fatal("expired immutable retention became readable")
	}
}

type originalBoundaryPreserver struct {
	preserver auditgate.Preserver
	after     func(auditrecord.Envelope)
}

func (p originalBoundaryPreserver) Preserve(ctx context.Context, raw []byte, inputs []auditgate.AttachmentInput) (auditrecord.Receipt, error) {
	r, err := p.preserver.Preserve(ctx, raw, inputs)
	if err == nil {
		var e auditrecord.Envelope
		if auditrecord.Decode(raw, &e, auditrecord.MaxEnvelopeBytes) == nil {
			p.after(e)
		}
	}
	return r, err
}

func TestOriginalRESTIntentAuthorityChangeNeverReturnsUsableHandle(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	h.s.stopOriginalRecovery() // mutate this fixture config with no active worker.
	preview := h.preview(t, "Role revoked during intent", "envelope")
	proof := h.proof(t, "Role revoked during intent", "envelope", preview)
	resolve := h.s.originalAccess.ResolveArchive
	h.s.originalAccess.ResolveArchive = func(ctx context.Context, p model.PolicyVersion) (auditgate.OriginalArchive, error) {
		archive, err := resolve(ctx, p)
		archive.Ingest = originalBoundaryPreserver{preserver: archive.Ingest, after: func(e auditrecord.Envelope) {
			if e.EventType == auditrecord.OriginalReadIntent {
				h.exec(t, "DELETE FROM user_roles WHERE user_id='original-reader'")
			}
		}}
		return archive, err
	}
	raw := h.json(t, "POST", "/api/executions/"+h.execution.ID+"/original-access", h.token, originalRequest{Purpose: "Role revoked during intent", Records: []string{"envelope"}, Digest: preview.Digest, StepupProof: proof}, 403)
	if bytes.Contains(raw, []byte(`"handle"`)) {
		t.Fatal("authority revoked during archival still returned a download handle")
	}
	var state string
	if err := h.s.store.DB().QueryRow("SELECT state FROM original_access").Scan(&state); err != nil || state != "pending" {
		t.Fatal("failed authority recheck left an authorized handle")
	}
	if len(h.fixture.Originals.Envelopes()) < 2 {
		t.Fatal("intent preservation did not occur before authority changed")
	}
}

func TestOriginalRESTExpiredDuringStartNeverOpensOriginalBody(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	issued := h.handle(t, "Expired during start archival", "envelope")
	h.s.stopOriginalRecovery()
	var reads atomic.Int32
	h.setReader(func(reader auditgate.OriginalReader) auditgate.OriginalReader {
		return countedOriginalReader{reader: reader, calls: &reads}
	})
	resolve := h.s.originalAccess.ResolveArchive
	h.s.originalAccess.ResolveArchive = func(ctx context.Context, p model.PolicyVersion) (auditgate.OriginalArchive, error) {
		archive, err := resolve(ctx, p)
		archive.Ingest = originalBoundaryPreserver{preserver: archive.Ingest, after: func(e auditrecord.Envelope) {
			if e.Details != nil && e.Details.State == "started" {
				h.clock.Advance(61 * time.Second)
			}
		}}
		return archive, err
	}
	h.json(t, "GET", issued.DownloadURL, h.token, nil, 403)
	a := h.awaitAccess(t, issued.Handle, "interrupted", "confirmed")
	if reads.Load() != 0 || a.BytesWritten != 0 || a.ConsumedAt == nil {
		t.Fatal("late start released bytes or restored a consumed permit")
	}
}

func TestOriginalRESTRecoveryKeepsPermanentGapWhenOldPolicyIsMissing(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	issued := h.handle(t, "Missing historical policy after crash", "envelope")
	h.s.stopOriginalRecovery()
	a := h.access(t, issued.Handle)
	h.exec(t, "UPDATE original_access SET policy_version=999 WHERE id=?", a.ID)
	h.clock.Advance(61 * time.Second)
	h.s.recoverOriginalEvidence(context.Background())
	a = h.access(t, issued.Handle)
	if a.State != "expired" || a.EvidenceState != "permanently_incomplete" || a.ConsumedAt != nil {
		t.Fatal("missing old policy fabricated delivery or revived permission")
	}
	h.json(t, "GET", issued.DownloadURL, h.token, nil, 403)
}
