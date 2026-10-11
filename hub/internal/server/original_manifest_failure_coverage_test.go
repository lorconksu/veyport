package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

type originalManifestFault struct {
	auditgate.OriginalMetadataClient
	mode  string
	after func()
}

func (f originalManifestFault) Manifest(ctx context.Context, event, hash string, ref auditrecord.ObjectRef) ([]byte, error) {
	raw, err := f.OriginalMetadataClient.Manifest(ctx, event, hash, ref)
	if err != nil {
		return raw, err
	}
	if f.after != nil {
		f.after()
	}
	switch f.mode {
	case "unavailable":
		return nil, errors.New("SYNTHETIC_MANIFEST_PRIVATE_CANARY")
	case "substituted":
		return append(raw, ' '), nil
	}
	return raw, nil
}

func TestOriginalRESTManifestAndMetadataFailuresNeverCreateReadAuthority(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	h.s.stopOriginalRecovery()
	path := "/api/executions/" + h.execution.ID + "/original-access/preview"
	request := originalRequest{Purpose: "Investigate exact manifest", Records: []string{"envelope"}}
	resolve := h.s.originalAccess.ResolveArchive
	var opens atomic.Int32
	h.setReader(func(reader auditgate.OriginalReader) auditgate.OriginalReader {
		return countedOriginalReader{reader: reader, calls: &opens}
	})
	for _, mode := range []string{"unavailable", "substituted", "missing-reader"} {
		t.Run(mode, func(t *testing.T) {
			h.s.originalAccess.ResolveArchive = func(ctx context.Context, p model.PolicyVersion) (auditgate.OriginalArchive, error) {
				a, err := resolve(ctx, p)
				a.Admin = originalManifestFault{OriginalMetadataClient: a.Admin, mode: mode}
				if mode == "missing-reader" {
					a.Reader = nil
				}
				return a, err
			}
			raw := h.json(t, "POST", path, h.token, request, 503)
			if bytes.Contains(raw, []byte("CANARY")) || bytes.Contains(raw, []byte(`"handle"`)) {
				t.Fatal("untrusted metadata returned a secret or original-read authority")
			}
		})
	}
	h.s.originalAccess.ResolveArchive = resolve
	h.json(t, "POST", path, h.token, originalRequest{Purpose: "No script was admitted", Records: []string{"script"}}, 403)
	if opens.Load() != 0 {
		t.Fatal("a metadata failure opened original bytes")
	}
	var proofs, accesses int
	if err := h.s.store.DB().QueryRow("SELECT COUNT(*) FROM stepup_proofs").Scan(&proofs); err != nil {
		t.Fatal(err)
	}
	if err := h.s.store.DB().QueryRow("SELECT COUNT(*) FROM original_access").Scan(&accesses); err != nil || proofs != 0 || accesses != 0 {
		t.Fatal("failed metadata minted a proof or handle")
	}
	// A corrupt locally stored preparation must fail both redacted APIs rather
	// than inventing a root identity or returning a partially decoded row.
	h.exec(t, "UPDATE executions SET preparation='not JSON' WHERE id=?", h.execution.ID)
	h.json(t, "GET", "/api/executions", h.token, nil, 400)
	h.json(t, "GET", "/api/executions/"+h.execution.ID, h.token, nil, 404)
}

func TestOriginalRESTFreshViewerSessionCannotReadExecutionAuditMetadata(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	h.exec(t, "DELETE FROM user_roles WHERE user_id='other-reader' AND role='original-reader'")
	var primary model.LoginResponse
	decodeResult(t, h.json(t, "POST", "/api/auth/login", "", model.LoginRequest{Username: "other-reader", Password: "Synthetic-Original-Access1!"}, 202), &primary)
	u, err := h.s.store.GetUserByID("other-reader")
	if err != nil || u.TOTPSecret == nil {
		t.Fatal("missing ordinary viewer MFA setup")
	}
	secret, err := h.s.decryptTOTPSecret(*u.TOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(61 * time.Second)
	code, _ := totp.GenerateCode(secret, h.clock.Now())
	var signedIn model.AuthResponse
	decodeResult(t, h.json(t, "POST", "/api/auth/login/totp", "", model.LoginTOTPRequest{TOTPToken: primary.TOTPToken, Code: code}, 200), &signedIn)
	// These are fresh, normally issued credentials, so refusal comes from the
	// actual audit capability check rather than a stale token-revision check.
	h.json(t, "GET", "/api/executions", signedIn.AccessToken, nil, 403)
	h.json(t, "GET", "/api/executions/"+h.execution.ID, signedIn.AccessToken, nil, 403)
	h.json(t, "POST", "/api/executions/"+h.execution.ID+"/original-access/preview", signedIn.AccessToken, originalRequest{Purpose: "Viewer investigation", Records: []string{"envelope"}}, 403)
}

func TestOriginalRESTMFAPersistenceFailureRequiresAnotherFreshCodeAndAtomicHandleWrite(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	h.s.stopOriginalRecovery()
	purpose := "Investigate durable proof and permit"
	preview := h.preview(t, purpose, "envelope")
	path := "/api/executions/" + h.execution.ID + "/original-access"
	h.exec(t, `CREATE TRIGGER original_proof_fault BEFORE INSERT ON stepup_proofs BEGIN SELECT RAISE(ABORT,'SYNTHETIC_PRIVATE_PROOF_CANARY'); END`)
	h.clock.Advance(61 * time.Second) // move the two real login MFA requests outside the shared limiter window.
	code, _ := totp.GenerateCode(h.secret, h.clock.Now())
	req := originalRequest{Purpose: purpose, Records: []string{"envelope"}, Digest: preview.Digest, Code: code}
	raw := h.json(t, "POST", path+"/step-up", h.token, req, 400)
	if bytes.Contains(raw, []byte("CANARY")) || bytes.Contains(raw, []byte(`"proof"`)) {
		t.Fatal("failed proof persistence returned proof authority or private SQL error")
	}
	h.exec(t, "DROP TRIGGER original_proof_fault")
	h.json(t, "POST", path+"/step-up", h.token, req, 403) // validated codes cannot be replayed after persistence failure.
	h.clock.Advance(61 * time.Second)
	code, _ = totp.GenerateCode(h.secret, h.clock.Now())
	req.Code = code
	var proven struct {
		Proof string `json:"proof"`
	}
	decodeResult(t, h.json(t, "POST", path+"/step-up", h.token, req, 200), &proven)
	h.exec(t, `CREATE TRIGGER original_access_fault BEFORE INSERT ON original_access BEGIN SELECT RAISE(ABORT,'SYNTHETIC_PRIVATE_HANDLE_CANARY'); END`)
	access := originalRequest{Purpose: purpose, Records: []string{"envelope"}, Digest: preview.Digest, StepupProof: proven.Proof}
	raw = h.json(t, "POST", path, h.token, access, 400)
	if bytes.Contains(raw, []byte("CANARY")) || bytes.Contains(raw, []byte(`"handle"`)) {
		t.Fatal("failed access transaction returned a handle or private SQL error")
	}
	var consumed any
	if err := h.s.store.DB().QueryRow("SELECT consumed_at FROM stepup_proofs WHERE hash=?", auditrecord.Hash([]byte(proven.Proof))).Scan(&consumed); err != nil || consumed != nil {
		t.Fatal("rolled-back handle creation consumed the operation-bound proof")
	}
	h.exec(t, "DROP TRIGGER original_access_fault")
	var issued struct{ Handle string }
	decodeResult(t, h.json(t, "POST", path, h.token, access, 201), &issued)
	if a := h.access(t, issued.Handle); a.State != "authorized" || a.ConsumedAt != nil {
		t.Fatal("repair did not create exactly one unconsumed permit")
	}
	h.json(t, "POST", path, h.token, access, 403)
}

type originalReadBoundary struct {
	reader    auditgate.OriginalReader
	afterRead func()
	closed    *atomic.Int32
}

func (r originalReadBoundary) ReadOriginal(ctx context.Context, ref auditrecord.ObjectRef, token string) (io.ReadCloser, error) {
	body, err := r.reader.ReadOriginal(ctx, ref, token)
	if err != nil {
		return body, err
	}
	return &originalReadBoundaryBody{ReadCloser: body, afterRead: r.afterRead, closed: r.closed}, nil
}

type originalReadBoundaryBody struct {
	io.ReadCloser
	afterRead func()
	closed    *atomic.Int32
}

func (b *originalReadBoundaryBody) Read(p []byte) (int, error) {
	// Force multiple bounded reads while retaining the actual archived body.
	if len(p) > 3 {
		p = p[:3]
	}
	n, err := b.ReadCloser.Read(p)
	if n > 0 && b.afterRead != nil {
		b.afterRead()
		b.afterRead = nil
	}
	return n, err
}
func (b *originalReadBoundaryBody) Close() error { b.closed.Add(1); return b.ReadCloser.Close() }

func TestOriginalRESTRevocationWhileOriginalReadBlocksDiscardsNewBytes(t *testing.T) {
	h := newOriginalHTTP(t, []byte("SYNTHETIC_BLOCKED_READ_CANARY\n"))
	issued := h.handle(t, "Revoked during upstream body read", "script")
	var closed atomic.Int32
	h.setReader(func(reader auditgate.OriginalReader) auditgate.OriginalReader {
		return originalReadBoundary{reader: reader, closed: &closed, afterRead: func() {
			h.exec(t, "UPDATE users SET security_revision=security_revision+1 WHERE id='original-reader'")
		}}
	})
	response := h.request(t, "GET", issued.DownloadURL, h.token, nil)
	raw, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if len(raw) != 0 || readErr == nil {
		t.Fatal("authority changed during read but newly obtained original bytes escaped")
	}
	a := h.awaitAccess(t, issued.Handle, "interrupted", "confirmed")
	if a.BytesWritten != 0 || a.ConsumedAt == nil || closed.Load() != 1 {
		t.Fatal("read-boundary revocation lost consumption, fabricated delivery, or leaked the body")
	}
}

type originalAfterWrite struct {
	*httptest.ResponseRecorder
	after func()
}

func (w *originalAfterWrite) SetWriteDeadline(time.Time) error { return nil }
func (w *originalAfterWrite) FlushError() error                { w.ResponseRecorder.Flush(); return nil }
func (w *originalAfterWrite) Write(p []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(p)
	if w.after != nil {
		w.after()
		w.after = nil
	}
	return n, err
}

func TestOriginalDownloadCancellationAndRevocationKeepOnlyPreviouslyWrittenBytes(t *testing.T) {
	for _, mode := range []string{"cancel", "revoke"} {
		t.Run(mode, func(t *testing.T) {
			h := newOriginalHTTP(t, []byte("SYNTHETIC_PARTIAL_ORIGINAL_CANARY\n"))
			issued := h.handle(t, "Partial response "+mode, "script")
			var closed atomic.Int32
			h.setReader(func(reader auditgate.OriginalReader) auditgate.OriginalReader {
				return originalReadBoundary{reader: reader, closed: &closed}
			})
			// Only the downstream transport is injected. Authentication, live
			// session, one-use claim, mTLS archive read and receipts are actual.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			request := httptest.NewRequest("GET", issued.DownloadURL, nil).WithContext(ctx)
			request.SetPathValue("handle", issued.Handle)
			request.Header.Set("Authorization", "Bearer "+h.token)
			writer := &originalAfterWrite{ResponseRecorder: httptest.NewRecorder(), after: func() {
				if mode == "cancel" {
					cancel()
				} else {
					h.exec(t, "UPDATE users SET security_revision=security_revision+1 WHERE id='original-reader'")
				}
			}}
			h.s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(h.s.handleOriginalDownload)).ServeHTTP(writer, request)
			a := h.awaitAccess(t, issued.Handle, "interrupted", "confirmed")
			if a.BytesWritten != 3 || !bytes.Equal(writer.Body.Bytes(), h.script[:3]) || a.ConsumedAt == nil || closed.Load() != 1 {
				t.Fatal("cancel/revoke released subsequent bytes or fabricated rollback/completion")
			}
		})
	}
}
