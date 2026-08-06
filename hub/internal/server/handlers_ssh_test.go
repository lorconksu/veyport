package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/notify"
	"github.com/wyiu/veyport/hub/internal/sshconfig"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
)

const (
	testSSHCertPath      = "/api/ssh/certificates"
	testSSHHostKeyPath   = "/api/ssh/host-key"
	testSSHAdminUsername = "admin"
	testSSHGatewayPort   = 2222
	testSSHCertTTL       = 12 * time.Hour
	testSSHExpected403   = "expected 403, got %d: %s"
	testSSHExpected429   = "expected 429, got %d: %s"
	testSSHExpected503   = "expected 503, got %d: %s"
	testSSHParseCertErr  = "parse issued certificate: %v"
)

// testSSHServer builds a server with the SSH gateway wired up: a real user CA,
// a real host key, and the effective sshconfig resolved from the store. Any
// configure funcs run before the config is resolved so a test can flip
// `ssh_gateway_enabled` and friends.
func testSSHServer(t *testing.T, configure ...func(*testing.T, *store.Store)) (*Server, ssh.Signer) {
	t.Helper()

	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	t.Cleanup(func() { st.Close() })

	jwtSecret, err := InitJWTSecret(st)
	if err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}
	storageKey, err := InitStorageKey(st)
	if err != nil {
		t.Fatalf("init storage key: %v", err)
	}

	ca, err := userca.InitUserCA(st, storageKey)
	if err != nil {
		t.Fatalf("init user ca: %v", err)
	}
	hostKey, err := userca.InitHostKey(st, storageKey)
	if err != nil {
		t.Fatalf("init host key: %v", err)
	}

	for _, fn := range configure {
		fn(t, st)
	}

	notifier := notify.New(st)
	t.Cleanup(func() { notifier.Close() })

	s := New(Config{
		Addr:       ":0",
		Store:      st,
		JWTSecret:  jwtSecret,
		StorageKey: storageKey,
		IsDev:      true,
		Notifier:   notifier,
		UserCA:     ca,
		SSHHostKey: hostKey,
		SSHConfig:  sshconfig.Load(st, ""),
	})

	return s, hostKey
}

// testSSHClientPublicKey returns a fresh ed25519 public key in authorized_keys form.
func testSSHClientPublicKey(t *testing.T) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap ssh public key: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

// postSSHCert issues a certificate request against handler h with a Bearer token.
func postSSHCert(t *testing.T, h http.Handler, token string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest("POST", testSSHCertPath, mustJSON(t, body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// createAdminAPIToken creates an API token for the "admin" user and returns the raw token.
func createAdminAPIToken(t *testing.T, s *Server) string {
	t.Helper()

	user, err := s.store.GetUserByUsername(testSSHAdminUsername)
	if err != nil {
		t.Fatalf("get admin user: %v", err)
	}
	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if err := s.store.CreateAPIToken(&model.APIToken{
		ID:          uuid.NewString(),
		UserID:      user.ID,
		Name:        "automation",
		TokenHash:   hash,
		TokenPrefix: prefix,
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}
	return raw
}

// countSSHAuditAction returns how many audit entries exist for the given action.
func countSSHAuditAction(t *testing.T, s *Server, action string) int {
	t.Helper()

	entries, _, err := s.store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 100})
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}
	return len(entries)
}

func TestHandleIssueSSHCertificate_Success(t *testing.T) {
	s, hostKey := testSSHServer(t)
	token := registerAndGetAdminToken(t, s)

	rec := postSSHCert(t, s.routes(), token, map[string]string{"public_key": testSSHClientPublicKey(t)})
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp model.SSHCertificateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}

	if resp.Principal != testSSHAdminUsername {
		t.Fatalf("expected principal %q, got %q", testSSHAdminUsername, resp.Principal)
	}
	if resp.GatewayPort != testSSHGatewayPort {
		t.Fatalf("expected gateway_port %d, got %d", testSSHGatewayPort, resp.GatewayPort)
	}
	if want := ssh.FingerprintSHA256(hostKey.PublicKey()); resp.HostKeyFingerprint != want {
		t.Fatalf("expected host_key_fingerprint %q, got %q", want, resp.HostKeyFingerprint)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf(testSSHParseCertErr, err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("expected an *ssh.Certificate, got %T", parsed)
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("expected a user certificate, got cert type %d", cert.CertType)
	}
	if !s.userCA.IsUserAuthority(cert.SignatureKey) {
		t.Fatal("expected the certificate to be signed by the hub user CA")
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != testSSHAdminUsername {
		t.Fatalf("expected sole principal %q, got %v", testSSHAdminUsername, cert.ValidPrincipals)
	}

	validBefore := time.Unix(int64(cert.ValidBefore), 0).UTC()
	wantExpiry := time.Now().UTC().Add(testSSHCertTTL)
	if delta := validBefore.Sub(wantExpiry); delta > time.Minute || delta < -time.Minute {
		t.Fatalf("expected ValidBefore ≈ %s (configured TTL), got %s", wantExpiry, validBefore)
	}

	expiresAt, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at %q: %v", resp.ExpiresAt, err)
	}
	if !expiresAt.UTC().Equal(validBefore) {
		t.Fatalf("expected expires_at %s to match certificate ValidBefore %s", expiresAt.UTC(), validBefore)
	}

	if got := countSSHAuditAction(t, s, model.AuditSSHCertIssued); got != 1 {
		t.Fatalf("expected 1 %s audit entry, got %d", model.AuditSSHCertIssued, got)
	}
}

// TestHandleIssueSSHCertificate_PrincipalIsNotClientChosen pins that the caller
// cannot request a principal other than their own username.
func TestHandleIssueSSHCertificate_PrincipalIsNotClientChosen(t *testing.T) {
	s, _ := testSSHServer(t)
	token := registerAndGetAdminToken(t, s)

	rec := postSSHCert(t, s.routes(), token, map[string]string{
		"public_key": testSSHClientPublicKey(t),
		"principal":  "root",
		"username":   "root",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp model.SSHCertificateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	if resp.Principal != testSSHAdminUsername {
		t.Fatalf("expected principal %q, got %q", testSSHAdminUsername, resp.Principal)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf(testSSHParseCertErr, err)
	}
	cert := parsed.(*ssh.Certificate)
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != testSSHAdminUsername {
		t.Fatalf("expected sole principal %q, got %v", testSSHAdminUsername, cert.ValidPrincipals)
	}
}

// TestHandleIssueSSHCertificate_APITokenRefused is SC-004: a non-interactive
// (API-token) session must never obtain an SSH certificate, and the refusal is
// audited.
func TestHandleIssueSSHCertificate_APITokenRefused(t *testing.T) {
	s, _ := testSSHServer(t)
	registerAndGetAdminToken(t, s)
	apiToken := createAdminAPIToken(t, s)

	rec := postSSHCert(t, s.routes(), apiToken, map[string]string{"public_key": testSSHClientPublicKey(t)})
	if rec.Code != http.StatusForbidden {
		t.Fatalf(testSSHExpected403, rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "interactive login required") {
		t.Fatalf("expected the interactiveOnly refusal message, got %s", body)
	}

	if got := countSSHAuditAction(t, s, model.AuditSSHCertIssueRefused); got != 1 {
		t.Fatalf("expected 1 %s audit entry, got %d", model.AuditSSHCertIssueRefused, got)
	}
	if got := countSSHAuditAction(t, s, model.AuditSSHCertIssued); got != 0 {
		t.Fatalf("expected no %s audit entry, got %d", model.AuditSSHCertIssued, got)
	}
}

func TestHandleIssueSSHCertificate_InvalidPublicKey(t *testing.T) {
	s, _ := testSSHServer(t)
	token := registerAndGetAdminToken(t, s)

	// An SSH certificate is a valid authorized_keys line but is not an
	// acceptable subject key.
	clientPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testSSHClientPublicKey(t)))
	if err != nil {
		t.Fatalf("parse client public key: %v", err)
	}
	existingCert, err := s.userCA.SignUserCert(clientPub, testSSHAdminUsername, time.Hour)
	if err != nil {
		t.Fatalf("sign helper certificate: %v", err)
	}

	cases := []struct {
		name      string
		publicKey string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"garbage", "not-a-public-key"},
		{"non-ssh PEM", "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----"},
		{"truncated base64", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"},
		{"unsupported type: certificate", string(ssh.MarshalAuthorizedKey(existingCert))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postSSHCert(t, s.routes(), token, map[string]string{"public_key": tc.publicKey})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
			}
			if got := countSSHAuditAction(t, s, model.AuditSSHCertIssued); got != 0 {
				t.Fatalf("expected no %s audit entry, got %d", model.AuditSSHCertIssued, got)
			}
		})
	}
}

// TestHandleIssueSSHCertificate_GatewayDisabled covers FR-015: while the
// gateway is disabled the endpoint returns a clear error instead of issuing an
// unusable certificate.
func TestHandleIssueSSHCertificate_GatewayDisabled(t *testing.T) {
	s, _ := testSSHServer(t, func(t *testing.T, st *store.Store) {
		t.Helper()
		if err := st.SetConfig("ssh_gateway_enabled", "false"); err != nil {
			t.Fatalf("disable ssh gateway: %v", err)
		}
	})
	token := registerAndGetAdminToken(t, s)

	rec := postSSHCert(t, s.routes(), token, map[string]string{"public_key": testSSHClientPublicKey(t)})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf(testSSHExpected503, rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	if !strings.Contains(strings.ToLower(resp["error"]), "disabled") {
		t.Fatalf("expected a clear 'gateway disabled' error, got %q", resp["error"])
	}
	if _, ok := resp["certificate"]; ok {
		t.Fatal("expected no certificate in the disabled-gateway response")
	}
	if got := countSSHAuditAction(t, s, model.AuditSSHCertIssued); got != 0 {
		t.Fatalf("expected no %s audit entry, got %d", model.AuditSSHCertIssued, got)
	}
}

// TestHandleIssueSSHCertificate_RateLimited pins the 10-requests-per-minute
// issuance limit from contracts/rest-api.md.
func TestHandleIssueSSHCertificate_RateLimited(t *testing.T) {
	s, _ := testSSHServer(t)
	token := registerAndGetAdminToken(t, s)

	// The limiters are per-router instance, so reuse one handler.
	h := s.routes()
	publicKey := testSSHClientPublicKey(t)

	for i := 0; i < 10; i++ {
		rec := postSSHCert(t, h, token, map[string]string{"public_key": publicKey})
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: %s", i+1, rec.Body.String())
		}
	}

	rec := postSSHCert(t, h, token, map[string]string{"public_key": publicKey})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf(testSSHExpected429, rec.Code, rec.Body.String())
	}
}

// getSSHHostKey reads GET /api/ssh/host-key as an authenticated caller.
func getSSHHostKey(t *testing.T, h http.Handler, token string) model.SSHHostKeyResponse {
	t.Helper()

	req := httptest.NewRequest("GET", testSSHHostKeyPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	var resp model.SSHHostKeyResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	return resp
}

func TestHandleSSHHostKey_StableAndMatchesGatewayKey(t *testing.T) {
	s, hostKey := testSSHServer(t)
	token := registerAndGetAdminToken(t, s)
	h := s.routes()

	get := func() model.SSHHostKeyResponse { return getSSHHostKey(t, h, token) }

	first, second := get(), get()

	want := ssh.FingerprintSHA256(hostKey.PublicKey())
	if first.Fingerprint != want {
		t.Fatalf("expected fingerprint %q, got %q", want, first.Fingerprint)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("expected a stable fingerprint, got %q then %q", first.Fingerprint, second.Fingerprint)
	}
	if first.Port != testSSHGatewayPort {
		t.Fatalf("expected port %d, got %d", testSSHGatewayPort, first.Port)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(first.PublicKey))
	if err != nil {
		t.Fatalf("parse host public key: %v", err)
	}
	if string(parsed.Marshal()) != string(hostKey.PublicKey().Marshal()) {
		t.Fatal("expected the published host public key to match the gateway host key")
	}
}

// observeHostKeyOverTheWire returns the host key an SSH client actually sees
// through HostKeyCallback when it connects to a listener carrying signer.
//
// The listener is a stand-in for the gateway rather than the gateway itself:
// internal/sshgw imports internal/server (for AuthorizeTerminalExecution), so
// this package cannot import sshgw without an import cycle. What makes the
// stand-in sound is that it is handed the SAME *ssh.Signer instance that
// cmd/veyport/main.go passes to BOTH server.Config.SSHHostKey (what this API
// publishes) and sshgw.Config.HostKey (what the gateway presents) — one key
// object, two consumers. The real gateway's key is separately pinned end to end
// in internal/integration/ssh_gateway_test.go.
func observeHostKeyOverTheWire(t *testing.T, signer ssh.Signer) ssh.PublicKey {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = lis.Close() }()

	serverCfg := &ssh.ServerConfig{
		// The probe never authenticates; only the key exchange matters, and the
		// host key is presented during key exchange, before any auth attempt.
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("probe connection: authentication not attempted")
		},
	}
	serverCfg.AddHostKey(signer)

	go func() {
		conn, acceptErr := lis.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _, _, _ = ssh.NewServerConn(conn, serverCfg)
	}()

	var presented ssh.PublicKey
	client, dialErr := ssh.Dial("tcp", lis.Addr().String(), &ssh.ClientConfig{
		User: "probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			presented = key
			return nil
		},
		Timeout: 5 * time.Second,
	})
	if dialErr == nil {
		_ = client.Close()
	}
	if presented == nil {
		t.Fatalf("the client never observed a host key: %v", dialErr)
	}
	return presented
}

// TestHandleSSHHostKey_MatchesKeyPresentedToClients closes the "discoverable"
// half of FR-006: the fingerprint and public key published by
// GET /api/ssh/host-key must be the ones a connecting SSH client verifies
// against, or pre-pinning from the API buys the operator nothing. Restart
// stability of the key itself is covered by userca's tests.
func TestHandleSSHHostKey_MatchesKeyPresentedToClients(t *testing.T) {
	s, hostKey := testSSHServer(t)
	token := registerAndGetAdminToken(t, s)

	published := getSSHHostKey(t, s.routes(), token)
	presented := observeHostKeyOverTheWire(t, hostKey)

	if got := ssh.FingerprintSHA256(presented); got != published.Fingerprint {
		t.Fatalf("the API publishes fingerprint %q but a connecting client sees %q",
			published.Fingerprint, got)
	}
	if got := authorizedKeyLine(presented); got != published.PublicKey {
		t.Fatalf("the API publishes public key %q but a connecting client sees %q",
			published.PublicKey, got)
	}

	// The published line must also be directly usable as a known_hosts pin, so
	// verify it round-trips into the callback the CLI builds (FR-013).
	pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(published.PublicKey))
	if err != nil {
		t.Fatalf("parse published host public key: %v", err)
	}
	if err := ssh.FixedHostKey(pinned)("", nil, presented); err != nil {
		t.Fatalf("pinning the published key rejects the key the client is presented: %v", err)
	}
}

// TestHandleSSHHostKey_AllowsAPIToken pins that host-key material — public
// trust material — is readable by any authenticated caller, unlike issuance.
func TestHandleSSHHostKey_AllowsAPIToken(t *testing.T) {
	s, _ := testSSHServer(t)
	registerAndGetAdminToken(t, s)
	apiToken := createAdminAPIToken(t, s)

	req := httptest.NewRequest("GET", testSSHHostKeyPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+apiToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

func TestHandleSSHEndpoints_RequireAuthentication(t *testing.T) {
	s, _ := testSSHServer(t)
	h := s.routes()

	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, httptest.NewRequest("POST", testSSHCertPath, mustJSON(t, map[string]string{"public_key": testSSHClientPublicKey(t)})))
	if postRec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401Body, postRec.Code, postRec.Body.String())
	}

	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, httptest.NewRequest("GET", testSSHHostKeyPath, nil))
	if getRec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401Body, getRec.Code, getRec.Body.String())
	}
}
