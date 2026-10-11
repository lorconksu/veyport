package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auditruntime"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/testaudit"
)

type originalRuntime interface {
	ResolveOriginalArchive(context.Context, model.PolicyVersion) (auditgate.OriginalArchive, error)
}
type originalHTTP struct {
	readerMu                       sync.RWMutex
	wrapReader                     func(auditgate.OriginalReader) auditgate.OriginalReader
	s                              *Server
	api                            *httptest.Server
	fixture                        *testaudit.Fixture
	clock                          *testaudit.Clock
	archive                        auditgate.OriginalArchive
	token, otherToken, secret, sid string
	execution                      *model.Execution
	raw, script                    []byte
}

func newOriginalHTTP(t *testing.T, script []byte) *originalHTTP {
	t.Helper()
	// The durable HTTP contract uses the same file-backed WAL database as
	// production, rather than SQLite's different shared-cache memory locking.
	st, err := store.New(filepath.Join(t.TempDir(), "original-http.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	jwtSecret, err := InitJWTSecret(st)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Addr: ":0", Store: st, JWTSecret: jwtSecret, IsDev: true})
	clock := testaudit.NewClock()
	s.SetClock(clock.Now)
	f := testaudit.New(t, clock)
	runtime, err := auditruntime.Load(f.ConfigFile(t), auditruntime.Options{Store: s.store, ResolveSecret: s.resolveSecuritySecret, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	resolver, ok := any(runtime).(originalRuntime)
	if !ok {
		t.Fatal("production original-reader runtime resolver is required")
	}
	credential, _ := json.Marshal(f.Credential)
	secretRaw, _ := json.Marshal(map[string]string{"kind": "destination", "value": string(credential)})
	encrypted, err := auth.Encrypt(secretRaw, auth.DeriveKey(s.storageKey))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.store.SaveSecuritySecret("secret:original-tests", encrypted, "synthetic-operator", clock.Now()); err != nil {
		t.Fatal(err)
	}
	policy := model.AuditPolicy{Profile: "enhanced", Actors: []string{}, Nodes: []string{"node"}, RuntimeSeconds: 60, RetentionHours: 24, Destination: f.Config.Endpoint, CredentialRef: "secret:original-tests", TrustKeyIDs: []string{"fixture-key"}, QualificationSHA256: f.Config.QualificationSHA256}
	policyRaw, _ := json.Marshal(policy)
	if _, err = s.store.DB().Exec("INSERT INTO audit_policy_versions(version,payload,digest) VALUES(2,?,?)", policyRaw, auditrecord.Hash(policyRaw)); err != nil {
		t.Fatal(err)
	}
	p, err := s.store.GetPolicyVersion(2)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := resolver.ResolveOriginalArchive(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	h := &originalHTTP{s: s, clock: clock, fixture: f, archive: archive, script: script}
	s.originalAccess = OriginalAccessConfig{ResolveArchive: func(ctx context.Context, p model.PolicyVersion) (auditgate.OriginalArchive, error) {
		a, err := resolver.ResolveOriginalArchive(ctx, p)
		h.readerMu.RLock()
		wrap := h.wrapReader
		h.readerMu.RUnlock()
		if wrap != nil {
			a.Reader = wrap(a.Reader)
		}
		return a, err
	}}
	// Set the immutable config before starting the dedicated worker and listener.
	s.startOriginalRecovery()
	h.api = httptest.NewServer(s.routes())
	t.Cleanup(h.api.Close)
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	password := "Synthetic-Original-Access1!"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"original-reader", "other-reader"} {
		key, err := auth.GenerateTOTPSecret(id, "synthetic-original-tests")
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := s.encryptTOTPSecret(key.Secret())
		if err != nil {
			t.Fatal(err)
		}
		u := &model.User{ID: id, Username: id, Email: id + "@synthetic.test.invalid", Role: model.RoleViewer, PasswordHash: hash, TOTPSecret: &encoded, TOTPEnabled: true, AuthProvider: model.AuthProviderLocal}
		if err = s.store.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		if _, err = s.store.DB().Exec("INSERT INTO user_roles(user_id,role) VALUES(?,'original-reader')", id); err != nil {
			t.Fatal(err)
		}
		login := h.json(t, "POST", "/api/auth/login", "", model.LoginRequest{Username: id, Password: password}, 202)
		var primary model.LoginResponse
		decodeResult(t, login, &primary)
		code, _ := totp.GenerateCode(key.Secret(), clock.Now())
		var signedIn model.AuthResponse
		decodeResult(t, h.json(t, "POST", "/api/auth/login/totp", "", model.LoginTOTPRequest{TOTPToken: primary.TOTPToken, Code: code}, 200), &signedIn)
		if id == "original-reader" {
			h.token = signedIn.AccessToken
			h.secret = key.Secret()
		} else {
			h.otherToken = signedIn.AccessToken
		}
	}
	claims, err := auth.ValidateToken(s.jwtSecret, h.token)
	if err != nil {
		t.Fatal(err)
	}
	h.sid = claims.SessionID
	person, err := s.store.PersonForUser("original-reader")
	if err != nil {
		t.Fatal(err)
	}
	command := []byte("printf SYNTHETIC_COMMAND_CANARY_avoid_metadata --token=synthetic-secret")
	if script != nil {
		command = []byte("sh -s")
	}
	e := &model.Execution{ID: "synthetic-execution", Enhanced: true, ActorID: "original-reader", ActorName: "original-reader", ActorPersonID: person, ActorProvider: "local", NodeID: "node", NodeName: "synthetic-node", RequestedUser: "synthetic-os-user", CommandSHA256: auditrecord.Hash(command), CommandLength: len(command), PolicyVersion: "2", PolicySHA256: p.SHA256}
	if err = s.store.CreateExecution(e); err != nil {
		t.Fatal(err)
	}
	e.Preparation = model.ExecutionPreparation{PreparationID: "synthetic-preparation", BootID: "synthetic-boot", ExpiresUnixMilli: clock.Now().Add(time.Minute).UnixMilli(), Identity: model.ExecutionIdentity{Username: "synthetic-os-user", UID: 1001, GID: 1001, Groups: []uint32{1001}, GroupsSHA256: auditrecord.Hash([]byte("groups")), IdentitySHA256: auditrecord.Hash([]byte("identity")), Home: "/home/synthetic", Shell: "/bin/sh", Cwd: "/home/synthetic"}, Limits: model.ExecutionLimits{MaxFrameBytes: 65536, MaxBufferBytes: 2097152, RuntimeSeconds: 60, TermGraceSeconds: 3, BlockedConsumerSeconds: 30}}
	if err = s.store.PrepareExecution(e.ID, e.Preparation); err != nil {
		t.Fatal(err)
	}
	if script != nil {
		e.ScriptSHA256 = auditrecord.Hash(script)
		e.ScriptLength = int64(len(script))
	}
	e.AdmissionEventID = e.ID + ".admission"
	expected := executionExpected(e, 2)
	envelope := auditrecord.Envelope{SchemaVersion: 1, EventID: e.AdmissionEventID, EventType: auditrecord.ExecutionAdmission, Actor: auditrecord.Actor{UserID: e.ActorID, PersonID: person, Name: e.ActorName, Provider: e.ActorProvider}, Execution: expected.Execution, PolicyVersion: 2, PolicySHA256: p.SHA256, OccurredAt: clock.Now(), Command: command}
	var inputs []auditgate.AttachmentInput
	if script != nil {
		envelope.Attachments = []auditrecord.Attachment{{ID: "script", SHA256: e.ScriptSHA256, Bytes: e.ScriptLength}}
		inputs = []auditgate.AttachmentInput{{ID: "script", Reader: bytes.NewReader(script)}}
	}
	raw, _ := json.Marshal(envelope)
	e.AdmissionRecordSHA256 = auditrecord.Hash(raw)
	receipt, err := archive.Ingest.Preserve(context.Background(), raw, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.store.SetExecutionSubmission(e.ID, e.ScriptSHA256, e.ScriptLength, e.AdmissionEventID, e.AdmissionRecordSHA256); err != nil {
		t.Fatal(err)
	}
	if err = s.store.SaveExecutionReceipt(e.ID, receipt.Token); err != nil {
		t.Fatal(err)
	}
	code := int32(0)
	if err = s.store.FinishExecution(e.ID, "exited", &code, "", "SYNTHETIC_ERROR_CANARY_omit_reason"); err != nil {
		t.Fatal(err)
	}
	e.AdmissionReceipt = receipt.Token
	h.execution = e
	h.raw = raw
	return h
}

func (h *originalHTTP) request(t *testing.T, method, path, token string, body any) *http.Response {
	t.Helper()
	var raw []byte
	if body != nil {
		raw = mustMarshal(t, body)
	}
	req, err := http.NewRequest(method, h.api.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := h.api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func (h *originalHTTP) json(t *testing.T, method, path, token string, body any, want int) []byte {
	t.Helper()
	response := h.request(t, method, path, token, body)
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.StatusCode, want, raw)
	}
	return raw
}
func (h *originalHTTP) preview(t *testing.T, purpose, kind string) model.OriginalPreview {
	t.Helper()
	var preview model.OriginalPreview
	decodeResult(t, h.json(t, "POST", "/api/executions/"+h.execution.ID+"/original-access/preview", h.token, model.OriginalAccessRequest{Purpose: purpose, Records: []string{kind}}, 200), &preview)
	return preview
}
func (h *originalHTTP) proof(t *testing.T, purpose, kind string, preview model.OriginalPreview) string {
	t.Helper()
	h.clock.Advance(35 * time.Second)
	code, _ := totp.GenerateCode(h.secret, h.clock.Now())
	var result struct {
		Proof string `json:"proof"`
	}
	decodeResult(t, h.json(t, "POST", "/api/executions/"+h.execution.ID+"/original-access/step-up", h.token, originalRequest{Purpose: purpose, Records: []string{kind}, Digest: preview.Digest, Code: code}, 200), &result)
	return result.Proof
}
func (h *originalHTTP) handle(t *testing.T, purpose, kind string) struct {
	Handle      string
	ExpiresAt   time.Time `json:"expires_at"`
	DownloadURL string    `json:"download_url"`
} {
	t.Helper()
	preview := h.preview(t, purpose, kind)
	proof := h.proof(t, purpose, kind, preview)
	var result struct {
		Handle      string
		ExpiresAt   time.Time `json:"expires_at"`
		DownloadURL string    `json:"download_url"`
	}
	decodeResult(t, h.json(t, "POST", "/api/executions/"+h.execution.ID+"/original-access", h.token, originalRequest{Purpose: purpose, Records: []string{kind}, Digest: preview.Digest, StepupProof: proof}, 201), &result)
	if len(result.Handle) != 64 || result.ExpiresAt.After(h.clock.Now().Add(time.Minute)) || result.DownloadURL != "/api/audit-originals/"+result.Handle {
		t.Fatal("invalid bounded handle response")
	}
	return result
}
func (h *originalHTTP) access(t *testing.T, handle string) model.OriginalAccess {
	t.Helper()
	var id string
	if err := h.s.store.DB().QueryRow("SELECT id FROM original_access WHERE handle_sha256=?", auditrecord.Hash([]byte(handle))).Scan(&id); err != nil {
		t.Fatal(err)
	}
	a, err := h.s.store.GetOriginalAccess(id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (h *originalHTTP) setReader(wrap func(auditgate.OriginalReader) auditgate.OriginalReader) {
	h.readerMu.Lock()
	h.wrapReader = wrap
	h.readerMu.Unlock()
}
func (h *originalHTTP) awaitAccess(t *testing.T, handle, state, evidence string) model.OriginalAccess {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a := h.access(t, handle)
		if a.State == state && a.EvidenceState == evidence {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("access did not settle: state=%s evidence=%s", a.State, a.EvidenceState)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type originalLogBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (h *originalHTTP) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := h.s.store.DB().Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func (b *originalLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}
func (b *originalLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func TestOriginalRESTExactDownloadRedactedMetadataAndOneUse(t *testing.T) {
	var captured originalLogBuffer
	old := log.Writer()
	log.SetOutput(&captured)
	defer log.SetOutput(old)
	h := newOriginalHTTP(t, []byte("printf SYNTHETIC_SCRIPT_CANARY_never_metadata\n"))
	for _, path := range []string{"/api/executions", "/api/executions/" + h.execution.ID} {
		raw := h.json(t, "GET", path, h.token, nil, 200)
		for _, canary := range []string{string(h.script), base64.StdEncoding.EncodeToString(h.script), h.execution.AdmissionReceipt, "SYNTHETIC_ERROR_CANARY"} {
			if bytes.Contains(raw, []byte(canary)) {
				t.Fatal("ordinary metadata exposed original/token/error")
			}
		}
	}
	for _, kind := range []string{"script", "envelope"} {
		issued := h.handle(t, "Incident 42 investigation", kind)
		a := h.access(t, issued.Handle)
		if a.State != "authorized" || a.ConsumedAt != nil {
			t.Fatal("handle issued before intent/authority")
		}
		response := h.request(t, "GET", issued.DownloadURL, h.token, nil)
		raw, err := io.ReadAll(response.Body)
		response.Body.Close()
		want := h.script
		if kind == "envelope" {
			want = h.raw
		}
		if err != nil || response.StatusCode != 200 || !bytes.Equal(raw, want) || !strings.Contains(response.Header.Get("Cache-Control"), "no-store") || response.Header.Get("Content-Disposition") == "" {
			t.Fatalf("exact %s download failed:%d %v", kind, response.StatusCode, err)
		}
		a = h.awaitAccess(t, issued.Handle, "completed", "confirmed")
		if a.State != "completed" || a.ConsumedAt == nil || a.BytesWritten != int64(len(want)) || a.EvidenceState != "confirmed" {
			t.Fatalf("truthful result:%+v", a)
		}
		h.json(t, "GET", issued.DownloadURL, h.token, nil, 403)
		if strings.Contains(captured.String(), issued.Handle) {
			t.Fatal("one-use handle leaked into request logs")
		}
	}
	if strings.Contains(captured.String(), "SYNTHETIC_SCRIPT_CANARY") {
		t.Fatal("original leaked into ordinary logs")
	}
	if !strings.Contains(captured.String(), "/api/audit-originals/{handle} status=200") {
		t.Fatal("sanitized request metadata not logged")
	}
}

func TestOriginalRESTPermissionSessionExpiryAndProofBindings(t *testing.T) {
	for _, mutation := range []string{"role", "revision", "session", "expiry", "other-user"} {
		t.Run(mutation, func(t *testing.T) {
			h := newOriginalHTTP(t, nil)
			issued := h.handle(t, "Review incident", "envelope")
			token := h.token
			switch mutation {
			case "role":
				h.exec(t, "DELETE FROM user_roles WHERE user_id='original-reader' AND role='original-reader'")
			case "revision":
				h.exec(t, "UPDATE users SET security_revision=security_revision+1 WHERE id='original-reader'")
			case "session":
				if _, err := h.s.store.EndSession(h.sid, model.SessionEndRevokedSelf, nil, h.clock.Now()); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				h.clock.Advance(time.Minute)
			case "other-user":
				token = h.otherToken
			}
			response := h.request(t, "GET", issued.DownloadURL, token, nil)
			raw, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode == 200 || bytes.Equal(raw, h.raw) {
				t.Fatal("stale authority released original")
			}
		})
	}
	h := newOriginalHTTP(t, nil)
	preview := h.preview(t, "Bound purpose", "envelope")
	proof := h.proof(t, "Bound purpose", "envelope", preview)
	path := "/api/executions/" + h.execution.ID + "/original-access"
	h.json(t, "POST", path, h.token, originalRequest{Purpose: "Changed purpose", Records: []string{"envelope"}, Digest: preview.Digest, StepupProof: proof}, 403)
	issued := h.json(t, "POST", path, h.token, originalRequest{Purpose: "Bound purpose", Records: []string{"envelope"}, Digest: preview.Digest, StepupProof: proof}, 201)
	if len(issued) == 0 {
		t.Fatal("failed attempt consumed mismatched proof")
	}
	h.json(t, "POST", path, h.token, originalRequest{Purpose: "Bound purpose", Records: []string{"envelope"}, Digest: preview.Digest, StepupProof: proof}, 403)
}

type orderedOriginalReader struct {
	reader  auditgate.OriginalReader
	fixture *testaudit.Fixture
	startID string
	t       *testing.T
}

func (r orderedOriginalReader) ReadOriginal(ctx context.Context, ref auditrecord.ObjectRef, token string) (io.ReadCloser, error) {
	found := false
	for _, e := range r.fixture.Originals.Envelopes() {
		if e.EventID == r.startID && e.EventType == auditrecord.OriginalReadResult && e.Details.State == "started" {
			found = true
		}
	}
	if !found {
		r.t.Fatal("original opened before external started evidence")
	}
	return r.reader.ReadOriginal(ctx, ref, token)
}

func TestOriginalRESTRequiredAuditOutagesAndRecoveryOrdering(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	preview := h.preview(t, "Outage investigation", "envelope")
	proof := h.proof(t, "Outage investigation", "envelope", preview)
	h.fixture.SetFault("ingest")
	h.json(t, "POST", "/api/executions/"+h.execution.ID+"/original-access", h.token, originalRequest{Purpose: "Outage investigation", Records: []string{"envelope"}, Digest: preview.Digest, StepupProof: proof}, 503)
	var pending int
	if err := h.s.store.DB().QueryRow("SELECT COUNT(*) FROM original_access WHERE state='pending'").Scan(&pending); err != nil || pending != 1 {
		t.Fatal("failed intent was not durably recorded")
	}
	h.fixture.SetFault("")
	h.clock.Advance(2 * time.Minute)
	h.s.recoverOriginalEvidence(context.Background())
	var authorized int
	if err := h.s.store.DB().QueryRow("SELECT COUNT(*) FROM original_access WHERE state='authorized'").Scan(&authorized); err != nil || authorized != 0 {
		t.Fatal("recovery recreated read authority")
	}
	issued := h.handle(t, "Second independent investigation", "envelope")
	a := h.access(t, issued.Handle)
	startedID := a.ID + ".started"
	h.setReader(func(reader auditgate.OriginalReader) auditgate.OriginalReader {
		return orderedOriginalReader{reader: reader, fixture: h.fixture, startID: startedID, t: t}
	})
	response := h.request(t, "GET", issued.DownloadURL, h.token, nil)
	raw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(raw, h.raw) {
		t.Fatal("ordered original read failed")
	}
	// Close the archive after issuing another handle. Consumption is final,
	// even when required started evidence cannot be preserved.
	issued = h.handle(t, "Third independent investigation", "envelope")
	h.fixture.SetFault("ingest")
	h.json(t, "GET", issued.DownloadURL, h.token, nil, 503)
	a = h.access(t, issued.Handle)
	if a.ConsumedAt == nil || a.State != "unconfirmed" {
		t.Fatalf("outage lost consumed/unknown delivery state: state=%s evidence=%s consumed=%v", a.State, a.EvidenceState, a.ConsumedAt)
	}
	h.fixture.SetFault("")
	h.clock.Advance(2 * time.Minute)
	h.exec(t, "UPDATE original_read_evidence SET next_attempt_at=0 WHERE access_id=?", a.ID)
	h.s.recoverOriginalEvidence(context.Background())
	a = h.access(t, issued.Handle)
	if a.State != "unconfirmed" || a.EvidenceState != "confirmed" {
		t.Fatalf("recovery fabricated delivery:%+v", a)
	}
	h.json(t, "GET", issued.DownloadURL, h.token, nil, 403)
}

type blockingOriginalReader struct {
	reader  auditgate.OriginalReader
	opened  chan struct{}
	release chan struct{}
	once    *sync.Once
}

func (r blockingOriginalReader) ReadOriginal(ctx context.Context, ref auditrecord.ObjectRef, token string) (io.ReadCloser, error) {
	body, err := r.reader.ReadOriginal(ctx, ref, token)
	r.once.Do(func() { close(r.opened) })
	select {
	case <-r.release:
		return body, err
	case <-ctx.Done():
		if body != nil {
			body.Close()
		}
		return nil, ctx.Err()
	}
}

func TestOriginalRESTRevocationAfterUpstreamOpenBeforeBytes(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	issued := h.handle(t, "Live authority investigation", "envelope")
	opened, release := make(chan struct{}), make(chan struct{})
	once := &sync.Once{}
	h.setReader(func(reader auditgate.OriginalReader) auditgate.OriginalReader {
		return blockingOriginalReader{reader: reader, opened: opened, release: release, once: once}
	})
	type result struct {
		code int
		raw  []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest("GET", h.api.URL+issued.DownloadURL, nil)
		req.Header.Set("Authorization", "Bearer "+h.token)
		resp, err := h.api.Client().Do(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- result{code: resp.StatusCode, raw: raw, err: err}
	}()
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not open")
	}
	if _, err := h.s.store.EndSession(h.sid, model.SessionEndRevokedSelf, nil, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case r := <-done:
		if r.err != nil || r.code != 403 || bytes.Equal(r.raw, h.raw) {
			t.Fatalf("revoked stream:%+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked read did not finish")
	}
	a := h.access(t, issued.Handle)
	if a.State != "interrupted" || a.BytesWritten != 0 {
		t.Fatal("revocation reported delivery")
	}
}
