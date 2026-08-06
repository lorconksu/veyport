package commands

// Command tests for `vey ssh-cert` (specs/005-ssh-gateway/tasks.md T009,
// contracts/cli-commands.md `vey ssh-cert`, contracts/rest-api.md
// POST /api/ssh/certificates + GET /api/ssh/host-key).
//
// The behaviors pinned here are the contract's own rows: interactive-only
// issuance (an API token is refused *before* any request leaves the process),
// keypair reuse with certificate replacement on re-run (FR-004), the --json
// shape, and the exit-code mapping for the three failures the contract names
// (rate limit → 7, interactive-required refusal → 3 carrying the hub's
// message, connectivity → 6).

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

const (
	sshTestPrincipal   = "alice"
	sshTestExpiry      = "2026-08-07T09:00:00Z"
	sshTestFingerprint = "SHA256:t1Hq0K9c2xVb7mNp4Rj8sYw6Lz3Ae5Gd1Fh2Jk4Mn6P"
	sshTestHostKey     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyPlaceholder gateway"
	sshTestPort        = 2222
)

// errNoKeyringForSSHTests forces the file credential backend, so what the
// command stores is inspectable from the test's own temp config dir rather
// than landing in the developer's real OS keyring.
var errNoKeyringForSSHTests = errors.New("mock: keyring unavailable (ssh-cert tests)")

// sshHub is the stub hub for these tests: it records every public key posted
// to /api/ssh/certificates, mints a distinguishable certificate per request,
// and counts *every* request that reaches it — including the refresh call —
// so a test can assert that no request happened at all.
type sshHub struct {
	srv *httptest.Server

	mu         sync.Mutex
	requests   int
	postedKeys []string
	issued     int

	// certStatus/certError, when set, make POST /api/ssh/certificates answer
	// with that status and {"error": certError} instead of a certificate.
	certStatus int
	certError  string
	// expiresAt is the expiry the hub reports; a test can make it malformed.
	expiresAt string
	// hostKeySparse makes GET /api/ssh/host-key answer with an empty
	// document, so the fallback to the issuance response is observable.
	hostKeySparse bool

	// beforeIssue, when set, runs inside the host-key handler — after the
	// command has read the credential store and before it writes it back.
	beforeIssue func()
}

func newSSHHub(t *testing.T) *sshHub {
	t.Helper()
	t.Setenv("VEYPORT_TOKEN", "")
	keyring.MockInitWithError(errNoKeyringForSSHTests)

	h := &sshHub{expiresAt: sshTestExpiry}

	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("GET /api/ssh/host-key", h.handleHostKey)
	mux.HandleFunc("POST /api/ssh/certificates", h.handleCertificates)

	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.requests++
		h.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *sshHub) URL() string { return h.srv.URL }

func (h *sshHub) handleHostKey(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	sparse, hook := h.hostKeySparse, h.beforeIssue
	h.mu.Unlock()

	if hook != nil {
		hook()
	}
	if sparse {
		writeSSHJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeSSHJSON(w, http.StatusOK, map[string]any{
		"fingerprint": sshTestFingerprint,
		"public_key":  sshTestHostKey,
		"port":        sshTestPort,
	})
}

func (h *sshHub) handleCertificates(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PublicKey string `json:"public_key"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	h.mu.Lock()
	h.postedKeys = append(h.postedKeys, body.PublicKey)
	status, msg, expiry := h.certStatus, h.certError, h.expiresAt
	if status == 0 {
		h.issued++
	}
	issued := h.issued
	h.mu.Unlock()

	if status != 0 {
		writeSSHJSON(w, status, map[string]string{"error": msg})
		return
	}
	writeSSHJSON(w, http.StatusOK, map[string]any{
		"certificate":          sshTestCertificate(issued),
		"principal":            sshTestPrincipal,
		"expires_at":           expiry,
		"host_key_fingerprint": sshTestFingerprint,
		"gateway_port":         sshTestPort,
	})
}

// sshTestCertificate makes each issuance distinguishable, so "the certificate
// was replaced" is observable rather than assumed.
func sshTestCertificate(n int) string {
	return "ssh-ed25519-cert-v01@openssh.com AAAAissued-" + string(rune('0'+n)) + " " + sshTestPrincipal
}

func writeSSHJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// postedKey returns the n-th public key posted to the hub.
func (h *sshHub) postedKey(t *testing.T, n int) string {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.postedKeys) <= n {
		t.Fatalf("hub received %d certificate request(s), want at least %d", len(h.postedKeys), n+1)
	}
	return h.postedKeys[n]
}

func (h *sshHub) requestCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.requests
}

// seedSSHSession puts configDir in session mode for the stub hub.
func seedSSHSession(t *testing.T, configDir, hubURL string) {
	t.Helper()
	seedSession(t, configDir, hubURL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     sshTestPrincipal,
		Role:         "admin",
		ObtainedAt:   time.Now().UTC(),
	})
}

// loadSSHMaterial reads back what the command persisted for hubURL.
func loadSSHMaterial(t *testing.T, configDir, hubURL string) (auth.StoredSSH, bool) {
	t.Helper()
	store, err := auth.NewStore(configDir, nil)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	m, ok, err := store.LoadSSH(hubURL)
	if err != nil {
		t.Fatalf("LoadSSH: %v", err)
	}
	return m, ok
}

// assertEd25519AuthorizedKey fails unless key is a parseable ed25519 public
// key in authorized_keys form — what contracts/rest-api.md says the hub is
// handed.
func assertEd25519AuthorizedKey(t *testing.T, key string) {
	t.Helper()
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		t.Fatalf("posted public key is not an authorized_keys line: %v (key=%q)", err, key)
	}
	if parsed.Type() != ssh.KeyAlgoED25519 {
		t.Errorf("posted key type = %q, want %q", parsed.Type(), ssh.KeyAlgoED25519)
	}
}

// --- session mode: the happy path -----------------------------------------

// TestSSHCert_SessionMode_IssuesStoresAndReports covers the contract's
// Behavior row end to end: host key fetched, generated public key posted,
// certificate + expiry + fingerprint + key stored, expiry reported on stdout,
// exit 0.
func TestSSHCert_SessionMode_IssuesStoresAndReports(t *testing.T) {
	hub := newSSHHub(t)
	configDir := t.TempDir()
	seedSSHSession(t, configDir, hub.URL())

	ctx, stdout, stderr := newCmdContext(hub.URL(), configDir, false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}

	posted := hub.postedKey(t, 0)
	assertEd25519AuthorizedKey(t, posted)

	out := stdout.String()
	if !strings.Contains(out, "cert for "+sshTestPrincipal) {
		t.Errorf("stdout = %q, want it to name the principal", out)
	}
	if !strings.Contains(out, "valid until "+sshTestExpiry) {
		t.Errorf("stdout = %q, want it to report the expiry %q", out, sshTestExpiry)
	}

	material, ok := loadSSHMaterial(t, configDir, hub.URL())
	if !ok {
		t.Fatal("no SSH material stored after a successful issuance")
	}
	if material.Certificate != sshTestCertificate(1) {
		t.Errorf("stored certificate = %q, want %q", material.Certificate, sshTestCertificate(1))
	}
	if material.HostFingerprint != sshTestFingerprint {
		t.Errorf("stored host fingerprint = %q, want %q", material.HostFingerprint, sshTestFingerprint)
	}
	wantExpiry, err := time.Parse(time.RFC3339, sshTestExpiry)
	if err != nil {
		t.Fatalf("parsing the test expiry: %v", err)
	}
	if !material.CertExpiresAt.Equal(wantExpiry) {
		t.Errorf("stored expiry = %v, want %v", material.CertExpiresAt, wantExpiry)
	}

	// The stored private key must be the one whose public half was posted,
	// and must never have been printed.
	signer, err := ssh.ParsePrivateKey([]byte(material.PrivateKey))
	if err != nil {
		t.Fatalf("stored private key does not parse: %v", err)
	}
	if got := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))); got != posted {
		t.Errorf("stored key's public half = %q, want the posted key %q", got, posted)
	}
	if strings.Contains(out, material.PrivateKey) || strings.Contains(stderr.String(), material.PrivateKey) {
		t.Error("the SSH private key reached stdout/stderr")
	}
}

// TestSSHCert_ReusesKeypairAndReplacesCertificate covers FR-004 / the
// Idempotent row: a second run posts the *same* public key and stores the
// newly signed certificate over the old one.
func TestSSHCert_ReusesKeypairAndReplacesCertificate(t *testing.T) {
	hub := newSSHHub(t)
	configDir := t.TempDir()
	seedSSHSession(t, configDir, hub.URL())

	for i := 0; i < 2; i++ {
		ctx, stdout, stderr := newCmdContext(hub.URL(), configDir, false, nil)
		if code := RunSSHCert(ctx); code != cmdutil.ExitOK {
			t.Fatalf("run %d: exit code = %d, want %d; stdout=%q stderr=%q", i+1, code, cmdutil.ExitOK, stdout.String(), stderr.String())
		}
	}

	first, second := hub.postedKey(t, 0), hub.postedKey(t, 1)
	if first != second {
		t.Errorf("second run posted a different public key; the stored keypair must be reused (FR-004)")
	}

	material, ok := loadSSHMaterial(t, configDir, hub.URL())
	if !ok {
		t.Fatal("no SSH material stored after re-issuance")
	}
	if material.Certificate != sshTestCertificate(2) {
		t.Errorf("stored certificate = %q, want the re-issued %q", material.Certificate, sshTestCertificate(2))
	}
}

// TestSSHCert_JSONShape pins the --json document:
// {principal, expires_at, host_key_fingerprint, gateway_port}.
func TestSSHCert_JSONShape(t *testing.T) {
	hub := newSSHHub(t)
	configDir := t.TempDir()
	seedSSHSession(t, configDir, hub.URL())

	ctx, stdout, stderr := newCmdContext(hub.URL(), configDir, true, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}

	got := decodeJSON(t, stdout)
	want := map[string]any{
		"principal":            sshTestPrincipal,
		"expires_at":           sshTestExpiry,
		"host_key_fingerprint": sshTestFingerprint,
		"gateway_port":         float64(sshTestPort),
	}
	for field, value := range want {
		if got[field] != value {
			t.Errorf("%s = %#v, want %#v", field, got[field], value)
		}
	}
	for field := range got {
		if _, expected := want[field]; !expected {
			t.Errorf("--json document carries an undocumented field %q", field)
		}
	}
	if strings.Contains(stdout.String(), "PRIVATE KEY") {
		t.Error("the --json document carries private key material")
	}
}

// --- refusals -------------------------------------------------------------

// TestSSHCert_APITokenMode_RefusedBeforeAnyRequest covers the Auth row: an
// API token is refused with exit 3, and — the part that matters for SC-004 —
// the refusal happens locally, so the hub never sees the request at all.
func TestSSHCert_APITokenMode_RefusedBeforeAnyRequest(t *testing.T) {
	hub := newSSHHub(t)
	t.Setenv("VEYPORT_TOKEN", "adt_1234567890abcdef")

	ctx, stdout, stderr := newCmdContext(hub.URL(), t.TempDir(), false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitAuth {
		t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
	}
	if n := hub.requestCount(); n != 0 {
		t.Errorf("hub received %d request(s); an API-token invocation must be refused before any network call", n)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty on the refusal path", stdout.String())
	}
	if !strings.Contains(stderr.String(), "vey login") {
		t.Errorf("stderr = %q, want guidance to run vey login", stderr.String())
	}
}

// TestSSHCert_NotSignedIn_RefusedBeforeAnyRequest is the ModeNone
// counterpart: nothing to issue against, exit 3, no request.
func TestSSHCert_NotSignedIn_RefusedBeforeAnyRequest(t *testing.T) {
	hub := newSSHHub(t)

	ctx, stdout, stderr := newCmdContext(hub.URL(), t.TempDir(), false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitAuth {
		t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
	}
	if n := hub.requestCount(); n != 0 {
		t.Errorf("hub received %d request(s) with no credential at all, want 0", n)
	}
}

// TestSSHCert_InteractiveRequired_ExitAuth covers the Errors row: the hub's
// 403 for a non-interactive caller maps to exit 3 (not the generic exit 4)
// and carries the hub's own message.
func TestSSHCert_InteractiveRequired_ExitAuth(t *testing.T) {
	hub := newSSHHub(t)
	hub.certStatus, hub.certError = http.StatusForbidden, "interactive login required"

	configDir := t.TempDir()
	seedSSHSession(t, configDir, hub.URL())

	ctx, stdout, stderr := newCmdContext(hub.URL(), configDir, false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitAuth {
		t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "interactive login required") {
		t.Errorf("stderr = %q, want the hub's refusal message surfaced", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty on an error path", stdout.String())
	}
	if _, ok := loadSSHMaterial(t, configDir, hub.URL()); ok {
		t.Error("SSH material was stored despite a refused issuance")
	}
}

// TestSSHCert_RateLimited_ExitRateLimited covers the hub's 10/minute issuance
// limiter (contracts/rest-api.md): 429 → exit 7, no client retry.
func TestSSHCert_RateLimited_ExitRateLimited(t *testing.T) {
	hub := newSSHHub(t)
	hub.certStatus, hub.certError = http.StatusTooManyRequests, "rate limit exceeded"

	configDir := t.TempDir()
	seedSSHSession(t, configDir, hub.URL())

	ctx, stdout, stderr := newCmdContext(hub.URL(), configDir, false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitRateLimited {
		t.Fatalf("exit code = %d, want %d (ExitRateLimited); stdout=%q stderr=%q", code, cmdutil.ExitRateLimited, stdout.String(), stderr.String())
	}
	if n := len(hub.postedKeys); n != 1 {
		t.Errorf("hub received %d certificate request(s), want exactly 1 (a rate limit is never retried)", n)
	}
}

// TestSSHCert_Unreachable_ExitConn covers the connectivity row: nothing is
// listening, so the very first call fails with exit 6.
func TestSSHCert_Unreachable_ExitConn(t *testing.T) {
	hub := newSSHHub(t)
	hubURL := hub.URL()
	configDir := t.TempDir()
	seedSSHSession(t, configDir, hubURL)
	hub.srv.Close() // every round trip now fails to connect

	ctx, stdout, stderr := newCmdContext(hubURL, configDir, false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitConn {
		t.Fatalf("exit code = %d, want %d (ExitConn); stdout=%q stderr=%q", code, cmdutil.ExitConn, stdout.String(), stderr.String())
	}
	if _, ok := loadSSHMaterial(t, configDir, hubURL); ok {
		t.Error("SSH material was stored despite never reaching the hub")
	}
}

// TestSSHCert_MalformedExpiry_ExitError covers the one response field the CLI
// must parse: an expiry it cannot read is a hub-contract violation, reported
// as a generic failure with nothing persisted (a certificate whose lifetime
// vey cannot check is worse than none).
func TestSSHCert_MalformedExpiry_ExitError(t *testing.T) {
	hub := newSSHHub(t)
	hub.expiresAt = "next tuesday"

	configDir := t.TempDir()
	seedSSHSession(t, configDir, hub.URL())

	ctx, stdout, stderr := newCmdContext(hub.URL(), configDir, false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitError {
		t.Fatalf("exit code = %d, want %d (ExitError); stdout=%q stderr=%q", code, cmdutil.ExitError, stdout.String(), stderr.String())
	}
	if _, ok := loadSSHMaterial(t, configDir, hub.URL()); ok {
		t.Error("SSH material was stored despite an unusable expiry")
	}
}

// TestSSHCert_UnreadableStoredKey_RegeneratesWithWarning covers the recovery
// path: a stored key vey cannot parse is unusable (the certificate signed for
// it is worthless too), so the command says so and mints a replacement rather
// than dead-ending, and the unreadable material never appears in the warning.
func TestSSHCert_UnreadableStoredKey_RegeneratesWithWarning(t *testing.T) {
	hub := newSSHHub(t)
	configDir := t.TempDir()
	seedSSHSession(t, configDir, hub.URL())

	const garbage = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-key-9f8e7d\n-----END OPENSSH PRIVATE KEY-----\n"
	store, err := auth.NewStore(configDir, nil)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if err := store.SaveSSH(hub.URL(), auth.StoredSSH{PrivateKey: garbage}); err != nil {
		t.Fatalf("SaveSSH: %v", err)
	}

	ctx, stdout, stderr := newCmdContext(hub.URL(), configDir, false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}
	assertEd25519AuthorizedKey(t, hub.postedKey(t, 0))
	if !strings.Contains(stderr.String(), "warning") {
		t.Errorf("stderr = %q, want a warning that the stored key was replaced", stderr.String())
	}
	if strings.Contains(stderr.String(), garbage) || strings.Contains(stdout.String(), garbage) {
		t.Error("the unreadable key material was echoed back to the user")
	}

	material, ok := loadSSHMaterial(t, configDir, hub.URL())
	if !ok || material.PrivateKey == garbage {
		t.Error("the unreadable key was not replaced")
	}
}

// TestSSHCert_RejectsArguments pins the usage contract: `vey ssh-cert` takes
// no arguments, and a mistyped invocation is exit 2 with no network call.
func TestSSHCert_RejectsArguments(t *testing.T) {
	hub := newSSHHub(t)
	configDir := t.TempDir()
	seedSSHSession(t, configDir, hub.URL())

	for _, args := range [][]string{{"srv-1"}, {"--nope"}} {
		ctx, stdout, stderr := newCmdContext(hub.URL(), configDir, false, args)
		if code := RunSSHCert(ctx); code != cmdutil.ExitUsage {
			t.Errorf("args %v: exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", args, code, cmdutil.ExitUsage, stdout.String(), stderr.String())
		}
	}
	if n := hub.requestCount(); n != 0 {
		t.Errorf("hub received %d request(s) for a usage error, want 0", n)
	}
}

// TestSSHCert_HostKeyFallsBackToIssuanceResponse pins the documented
// precedence: GET /api/ssh/host-key is the pinning source, and the issuance
// response fills in what it leaves out.
func TestSSHCert_HostKeyFallsBackToIssuanceResponse(t *testing.T) {
	hub := newSSHHub(t)
	hub.hostKeySparse = true

	configDir := t.TempDir()
	seedSSHSession(t, configDir, hub.URL())

	ctx, stdout, stderr := newCmdContext(hub.URL(), configDir, true, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d; stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}

	got := decodeJSON(t, stdout)
	if got["host_key_fingerprint"] != sshTestFingerprint {
		t.Errorf("host_key_fingerprint = %#v, want the issuance response's %q", got["host_key_fingerprint"], sshTestFingerprint)
	}
	if got["gateway_port"] != float64(sshTestPort) {
		t.Errorf("gateway_port = %#v, want the issuance response's %d", got["gateway_port"], sshTestPort)
	}
	material, ok := loadSSHMaterial(t, configDir, hub.URL())
	if !ok || material.HostFingerprint != sshTestFingerprint {
		t.Errorf("stored host fingerprint = %q, want %q", material.HostFingerprint, sshTestFingerprint)
	}
}

// TestSSHCert_StoreConstructionFailure_ExitError covers the shared
// newAuthContext failure branch: with no config directory there is nowhere to
// put a key, and the command must fail before generating one.
func TestSSHCert_StoreConstructionFailure_ExitError(t *testing.T) {
	hub := newSSHHub(t)

	ctx, stdout, stderr := newCmdContext(hub.URL(), "", false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitError {
		t.Fatalf("exit code = %d, want %d (ExitError); stdout=%q stderr=%q", code, cmdutil.ExitError, stdout.String(), stderr.String())
	}
	if n := hub.requestCount(); n != 0 {
		t.Errorf("hub received %d request(s) with no usable credential store, want 0", n)
	}
}

// TestSSHCert_PersistFailure_ExitError covers the last failure the command
// can hit: the certificate is signed, but it cannot be stored. The credential
// file is made world-readable mid-invocation (the store refuses to write over
// an exposed file rather than silently repairing it), which is exactly the
// hostile race that check exists for.
func TestSSHCert_PersistFailure_ExitError(t *testing.T) {
	hub := newSSHHub(t)
	configDir := t.TempDir()
	seedSSHSession(t, configDir, hub.URL())

	credentials := filepath.Join(configDir, auth.CredentialsFileName)
	if _, err := os.Stat(credentials); err != nil {
		t.Skipf("credential store is not the file backend here: %v", err)
	}
	hub.beforeIssue = func() {
		if err := os.Chmod(credentials, 0o644); err != nil {
			t.Errorf("chmod: %v", err)
		}
	}

	ctx, stdout, stderr := newCmdContext(hub.URL(), configDir, false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitError {
		t.Fatalf("exit code = %d, want %d (ExitError); stdout=%q stderr=%q", code, cmdutil.ExitError, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty when the certificate could not be stored", stdout.String())
	}
	if !strings.Contains(stderr.String(), "chmod 600") {
		t.Errorf("stderr = %q, want the store's remediation guidance", stderr.String())
	}
}

// TestSSHCert_NoHub_ExitUsage covers the shared RequireHub branch: with no
// --hub, no VEYPORT_HUB, and no default_hub, there is nothing to ask.
func TestSSHCert_NoHub_ExitUsage(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")
	ctx, stdout, stderr := newCmdContext("", t.TempDir(), false, nil)
	if code := RunSSHCert(ctx); code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestSSHCert_IsRegistered guards the registry wiring: `vey ssh-cert` must be
// dispatchable from cmd/vey/main.go, not merely defined.
func TestSSHCert_IsRegistered(t *testing.T) {
	if _, ok := Registry["ssh-cert"]; !ok {
		t.Error(`Registry has no "ssh-cert" entry`)
	}
}
