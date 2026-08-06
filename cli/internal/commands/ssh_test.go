package commands

// Command tests for `vey ssh <server>` (specs/005-ssh-gateway/tasks.md T021,
// contracts/cli-commands.md `vey ssh`, contracts/ssh-gateway.md "Addressing
// the target server").
//
// Pinned here: the preflight cert check (missing/expired → exit 3 naming
// `vey ssh-cert`), server resolution parity with `vey servers get` (unique →
// resolves, ambiguous → exit 2 listing candidates, unknown → exit 5), the
// constructed ssh argv (identity file + auto-loaded cert, `-p <port>`,
// pinned host verification via a temp known_hosts + StrictHostKeyChecking,
// and the `user+server@host` destination), exit-status propagation from the
// ssh client, and the no-TTY / missing-binary environment failures.
//
// execSSH and sshStdinIsTTY are the two injectable seams (see ssh.go): no
// test in this file ever spawns a real ssh process.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

const (
	sshRunTestFingerprint = "SHA256:aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefg"
	sshRunTestHostKey     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyForSSHRunTests gateway"
	sshRunTestPort        = 2222
)

// errNoKeyringForSSHRunTests forces the file credential backend so seeded
// SSH material is inspectable/writable from the test's own temp config dir.
var errNoKeyringForSSHRunTests = errors.New("mock: keyring unavailable (ssh run tests)")

// makeTestUserCert mints a real, parseable ed25519 user certificate for
// principal, signed by a fresh throwaway CA, expiring at expiry. It mirrors
// the shape sshcert.go's own generateSSHKeypair produces (ed25519, PEM
// private key), so certPrincipal/knownHostsLine/writeSSHCredentialFiles are
// exercised against realistic input rather than fixture strings.
func makeTestUserCert(t *testing.T, principal string, expiry time.Time) (privatePEM, certLine string) {
	t.Helper()

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating test CA key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("building CA signer: %v", err)
	}

	userPub, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating test user key: %v", err)
	}
	sshUserPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatalf("wrapping user public key: %v", err)
	}

	cert := &ssh.Certificate{
		Key:             sshUserPub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           principal,
		ValidPrincipals: []string{principal},
		ValidAfter:      0,
		ValidBefore:     uint64(expiry.Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("signing test certificate: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(userPriv, "")
	if err != nil {
		t.Fatalf("marshaling test private key: %v", err)
	}

	return string(pem.EncodeToMemory(block)), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}

// seedForSSH wires up an httptest hub with /api/auth/refresh mounted and a
// seeded session, returning the mux (so a test can register its own
// /api/ssh/* and /api/servers* handlers), the server, and the configDir. The
// counterpart to servers_test.go's seedForServers.
func seedForSSH(t *testing.T, accessToken string) (*http.ServeMux, *httptest.Server, string) {
	t.Helper()
	t.Setenv("VEYPORT_TOKEN", "")
	keyring.MockInitWithError(errNoKeyringForSSHRunTests)

	mux := http.NewServeMux()
	mountRefresh(mux, accessToken, "refresh-2")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now(),
	})
	return mux, srv, configDir
}

// seedSSHMaterial stores a valid, unexpired certificate for principal in
// configDir's credential store for hubURL.
func seedSSHMaterial(t *testing.T, configDir, hubURL, principal string, expiry time.Time) {
	t.Helper()
	privatePEM, certLine := makeTestUserCert(t, principal, expiry)
	store, err := auth.NewStore(configDir, nil)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if err := store.SaveSSH(hubURL, auth.StoredSSH{
		PrivateKey:      privatePEM,
		Certificate:     certLine,
		CertExpiresAt:   expiry,
		HostFingerprint: sshRunTestFingerprint,
	}); err != nil {
		t.Fatalf("store.SaveSSH: %v", err)
	}
}

// mountSSHHostKey registers the GET /api/ssh/host-key stub every `vey ssh`
// test needs.
func mountSSHHostKey(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ssh/host-key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"fingerprint": sshRunTestFingerprint,
			"public_key":  sshRunTestHostKey,
			"port":        sshRunTestPort,
		})
	})
}

// mountSingleServer registers /api/servers/{id} (direct hit) and /api/servers
// (search fallback) so ref resolves uniquely to srv.
func mountSingleServer(mux *http.ServeMux, ref string, srv api.Server) {
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") == srv.ID {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(srv)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	})
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("search") == srv.Name {
			_ = json.NewEncoder(w).Encode(api.ServersPage{Servers: []api.Server{srv}, Total: 1})
			return
		}
		_ = json.NewEncoder(w).Encode(api.ServersPage{})
	})
}

// stubExecSSH replaces execSSH for the duration of the test with a recorder
// that never spawns a process; it captures the exact argv (binary prepended)
// vey constructed and delegates the (exitCode, err) decision to fn (nil
// means "succeed with exit 0"). Restored via t.Cleanup.
func stubExecSSH(t *testing.T, fn sshRunner) *[]string {
	t.Helper()
	orig := execSSH
	captured := new([]string)
	execSSH = func(binary string, argv []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		*captured = append([]string{binary}, argv...)
		if fn != nil {
			return fn(binary, argv, stdin, stdout, stderr)
		}
		return 0, nil
	}
	t.Cleanup(func() { execSSH = orig })
	return captured
}

// stubSSHTTY forces sshStdinIsTTY's result for the duration of the test.
func stubSSHTTY(t *testing.T, isTTY bool) {
	t.Helper()
	orig := sshStdinIsTTY
	sshStdinIsTTY = func() bool { return isTTY }
	t.Cleanup(func() { sshStdinIsTTY = orig })
}

// --- preflight: missing/expired certificate --------------------------------

// TestSSH_MissingCertificate_ExitAuth covers the Preflight row: no SSH
// material stored at all → exit 3, guidance names `vey ssh-cert`, no network
// call happens (there is nothing to resolve or connect with).
func TestSSH_MissingCertificate_ExitAuth(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	var serversCalled bool
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		serversCalled = true
		w.WriteHeader(http.StatusNotFound)
	})
	stubSSHTTY(t, true)
	captured := stubExecSSH(t, nil)

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"bastion1"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitAuth {
		t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "vey ssh-cert") {
		t.Errorf("stderr = %q, want guidance to run vey ssh-cert", stderr.String())
	}
	if serversCalled {
		t.Error("server resolution happened despite no usable certificate")
	}
	if *captured != nil {
		t.Errorf("ssh was exec'd despite the preflight failure: argv=%v", *captured)
	}
}

// TestSSH_ExpiredCertificate_ExitAuth covers the Preflight row's other half:
// a certificate whose *stored* expiry has already passed is treated exactly
// like a missing one — exit 3, same `vey ssh-cert` guidance — without ever
// parsing the certificate itself.
func TestSSH_ExpiredCertificate_ExitAuth(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	seedSSHMaterial(t, configDir, srv.URL, "alice", time.Now().Add(-1*time.Hour))
	var serversCalled bool
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		serversCalled = true
		w.WriteHeader(http.StatusNotFound)
	})
	stubSSHTTY(t, true)
	captured := stubExecSSH(t, nil)

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"bastion1"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitAuth {
		t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "vey ssh-cert") {
		t.Errorf("stderr = %q, want guidance to run vey ssh-cert", stderr.String())
	}
	if !strings.Contains(stderr.String(), "expired") {
		t.Errorf("stderr = %q, want it to say the certificate expired", stderr.String())
	}
	if serversCalled {
		t.Error("server resolution happened despite an expired certificate")
	}
	if *captured != nil {
		t.Errorf("ssh was exec'd despite the preflight failure: argv=%v", *captured)
	}
}

// --- server resolution parity with `vey servers get` ------------------------

// TestSSH_ServerResolution_UniqueName covers unique-name resolution and,
// end to end, the full argv construction: cert/identity file via -i, `-p
// <port>`, pinned host verification, and the user+server@host destination.
func TestSSH_ServerResolution_UniqueName(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	seedSSHMaterial(t, configDir, srv.URL, "alice", time.Now().Add(2*time.Hour))
	mountSSHHostKey(mux)
	mountSingleServer(mux, "bastion1", api.Server{ID: "s1", Name: "bastion1", Status: "online"})
	stubSSHTTY(t, true)

	// The temp credential files only exist between writeSSHCredentialFiles
	// and RunSSH's own deferred cleanup, which fires before RunSSH returns
	// to this test (execSSH is a stub, not a blocking real process) — so
	// their existence/contents must be captured from *inside* the execSSH
	// callback, while RunSSH still holds them open.
	var identityBytes, certBytes, knownHostsBytes []byte
	var readErr error
	captured := stubExecSSH(t, func(_ string, argv []string, _ io.Reader, _, _ io.Writer) (int, error) {
		var identityFile, knownHostsPath string
		for i, a := range argv {
			if a == "-i" && i+1 < len(argv) {
				identityFile = argv[i+1]
			}
			if strings.HasPrefix(a, "UserKnownHostsFile=") {
				knownHostsPath = strings.TrimPrefix(a, "UserKnownHostsFile=")
			}
		}
		identityBytes, readErr = os.ReadFile(identityFile)
		if readErr == nil {
			certBytes, readErr = os.ReadFile(identityFile + "-cert.pub")
		}
		if readErr == nil {
			knownHostsBytes, readErr = os.ReadFile(knownHostsPath)
		}
		return 0, nil
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"bastion1"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}
	if readErr != nil {
		t.Fatalf("reading vey's temp ssh credential files (from inside the exec callback): %v", readErr)
	}

	argv := *captured
	if argv == nil {
		t.Fatal("ssh was never exec'd")
	}
	if argv[0] != "ssh" {
		t.Errorf("argv[0] = %q, want %q", argv[0], "ssh")
	}

	hubHost, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing test hub URL: %v", err)
	}
	wantDestination := "alice+bastion1@" + hubHost.Hostname()
	if !slices.Contains(argv, wantDestination) {
		t.Errorf("argv = %v, want it to contain destination %q", argv, wantDestination)
	}
	if !slices.Contains(argv, "-p") || !slices.Contains(argv, "2222") {
		t.Errorf("argv = %v, want -p 2222", argv)
	}
	if !slices.Contains(argv, "-i") {
		t.Errorf("argv = %v, want an -i identity file flag", argv)
	}
	if !slices.Contains(argv, "StrictHostKeyChecking=yes") {
		t.Errorf("argv = %v, want -o StrictHostKeyChecking=yes", argv)
	}

	// The identity file and its paired certificate (ssh's own
	// "<key>-cert.pub" convention) held the material vey stored, and the
	// temp known_hosts pinned the gateway's key, while ssh was "running".
	if !strings.Contains(string(identityBytes), "PRIVATE KEY") {
		t.Errorf("identity file contents = %q, want it to hold a private key", string(identityBytes))
	}
	if !strings.Contains(string(certBytes), "cert-v01@openssh.com") {
		t.Errorf("cert file contents = %q, want an ssh certificate", string(certBytes))
	}
	// knownHostsLine keeps only the key type + base64 (drops the trailing
	// " gateway" comment), so check for that prefix rather than the full
	// public_key string the stub returned.
	wantKeyMaterial := strings.TrimSuffix(sshRunTestHostKey, " gateway")
	if !strings.Contains(string(knownHostsBytes), wantKeyMaterial) {
		t.Errorf("known_hosts contents = %q, want it to pin the gateway host key %q", string(knownHostsBytes), wantKeyMaterial)
	}
	if !strings.Contains(string(knownHostsBytes), hubHost.Hostname()) {
		t.Errorf("known_hosts contents = %q, want it to name the gateway host %q", string(knownHostsBytes), hubHost.Hostname())
	}

	// Cleanup must have removed the temp dir after RunSSH returns: find the
	// identity file's directory from argv and confirm it's gone.
	var identityFile string
	for i, a := range argv {
		if a == "-i" && i+1 < len(argv) {
			identityFile = argv[i+1]
		}
	}
	if _, err := os.Stat(filepath.Dir(identityFile)); !os.IsNotExist(err) {
		t.Errorf("temp ssh dir %q still exists after RunSSH returned (err=%v)", filepath.Dir(identityFile), err)
	}
}

// TestSSH_ServerResolution_ByID covers direct-ID resolution succeeding
// without any fallback search call.
func TestSSH_ServerResolution_ByID(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	seedSSHMaterial(t, configDir, srv.URL, "alice", time.Now().Add(2*time.Hour))
	mountSSHHostKey(mux)

	var searchCalls int
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "s1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.Server{ID: "s1", Name: "bastion1", Status: "online"})
	})
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		searchCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ServersPage{})
	})

	stubSSHTTY(t, true)
	stubExecSSH(t, nil)

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"s1"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}
	if searchCalls != 0 {
		t.Errorf("search calls = %d, want 0 (direct ID lookup should succeed without a fallback)", searchCalls)
	}
}

// TestSSH_ServerResolution_Ambiguous_ExitUsage covers "ambiguous → exit 2
// listing candidates."
func TestSSH_ServerResolution_Ambiguous_ExitUsage(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	seedSSHMaterial(t, configDir, srv.URL, "alice", time.Now().Add(2*time.Hour))
	mountSSHHostKey(mux)

	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ServersPage{
			Servers: []api.Server{
				{ID: "s1", Name: "web", Status: "online"},
				{ID: "s2", Name: "web", Status: "offline"},
			},
			Total: 2,
		})
	})
	stubSSHTTY(t, true)
	captured := stubExecSSH(t, nil)

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"web"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
	for _, want := range []string{"s1", "s2"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr = %q, want it to list candidate %q", stderr.String(), want)
		}
	}
	if *captured != nil {
		t.Errorf("ssh was exec'd despite ambiguous resolution: argv=%v", *captured)
	}
}

// TestSSH_ServerResolution_Unknown_ExitNotFound covers "unknown → exit 5."
func TestSSH_ServerResolution_Unknown_ExitNotFound(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	seedSSHMaterial(t, configDir, srv.URL, "alice", time.Now().Add(2*time.Hour))
	mountSSHHostKey(mux)

	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ServersPage{Servers: nil, Total: 0})
	})
	stubSSHTTY(t, true)
	captured := stubExecSSH(t, nil)

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"ghost"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitNotFound {
		t.Fatalf("exit code = %d, want %d (ExitNotFound); stdout=%q stderr=%q", code, cmdutil.ExitNotFound, stdout.String(), stderr.String())
	}
	if *captured != nil {
		t.Errorf("ssh was exec'd despite unknown server: argv=%v", *captured)
	}
}

// --- exit status propagation -------------------------------------------

// TestSSH_ExitStatusPropagated covers "the ssh client's exit status is
// propagated as vey's exit code" for an arbitrary non-zero status.
func TestSSH_ExitStatusPropagated(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	seedSSHMaterial(t, configDir, srv.URL, "alice", time.Now().Add(2*time.Hour))
	mountSSHHostKey(mux)
	mountSingleServer(mux, "bastion1", api.Server{ID: "s1", Name: "bastion1", Status: "online"})
	stubSSHTTY(t, true)
	stubExecSSH(t, func(string, []string, io.Reader, io.Writer, io.Writer) (int, error) {
		return 130, nil // e.g. ssh terminated by Ctrl-C
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"bastion1"})
	code := RunSSH(ctx)
	if code != 130 {
		t.Fatalf("exit code = %d, want 130 (propagated from the ssh client); stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

// TestSSH_ExitStatusPropagated_Zero covers the success case explicitly:
// exit 0 from ssh must not be reinterpreted as anything else.
func TestSSH_ExitStatusPropagated_Zero(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	seedSSHMaterial(t, configDir, srv.URL, "alice", time.Now().Add(2*time.Hour))
	mountSSHHostKey(mux)
	mountSingleServer(mux, "bastion1", api.Server{ID: "s1", Name: "bastion1", Status: "online"})
	stubSSHTTY(t, true)
	stubExecSSH(t, func(string, []string, io.Reader, io.Writer, io.Writer) (int, error) {
		return 0, nil
	})

	ctx, _, stderr := newCmdContext(srv.URL, configDir, false, []string{"bastion1"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}
}

// --- no TTY / missing ssh binary -------------------------------------------

// TestSSH_NoTTY_ExitError covers "no TTY → sensible error": vey ssh is
// interactive-shell-only, so a non-TTY stdin is refused with ExitError (1)
// before ever invoking execSSH — chosen over ExitConn(6) because this is a
// local environment problem, not a hub/gateway connectivity failure.
func TestSSH_NoTTY_ExitError(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	seedSSHMaterial(t, configDir, srv.URL, "alice", time.Now().Add(2*time.Hour))
	mountSSHHostKey(mux)
	mountSingleServer(mux, "bastion1", api.Server{ID: "s1", Name: "bastion1", Status: "online"})
	stubSSHTTY(t, false)
	captured := stubExecSSH(t, nil)

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"bastion1"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitError {
		t.Fatalf("exit code = %d, want %d (ExitError); stdout=%q stderr=%q", code, cmdutil.ExitError, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "TTY") {
		t.Errorf("stderr = %q, want it to mention the missing TTY", stderr.String())
	}
	if *captured != nil {
		t.Errorf("ssh was exec'd despite a non-TTY stdin: argv=%v", *captured)
	}
}

// TestSSH_MissingSSHBinary_ExitError covers "missing ssh binary → sensible
// error": execSSH reporting a local start failure (as runSSHClient does when
// exec.LookPath fails) maps to ExitError (1), and vey's exit code is not
// confused with any status ssh itself might have returned.
func TestSSH_MissingSSHBinary_ExitError(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	seedSSHMaterial(t, configDir, srv.URL, "alice", time.Now().Add(2*time.Hour))
	mountSSHHostKey(mux)
	mountSingleServer(mux, "bastion1", api.Server{ID: "s1", Name: "bastion1", Status: "online"})
	stubSSHTTY(t, true)
	stubExecSSH(t, func(string, []string, io.Reader, io.Writer, io.Writer) (int, error) {
		return 0, errors.New("ssh not found on PATH")
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"bastion1"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitError {
		t.Fatalf("exit code = %d, want %d (ExitError); stdout=%q stderr=%q", code, cmdutil.ExitError, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "not found") {
		t.Errorf("stderr = %q, want it to surface why ssh could not be started", stderr.String())
	}
}

// TestRunSSHClient_MissingBinary exercises execSSH's real, production
// implementation directly (not the test stub) against a binary name that
// cannot exist on PATH, pinning runSSHClient's own local-start-failure
// contract independent of the stubbing used everywhere else in this file.
func TestRunSSHClient_MissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // a PATH with nothing on it
	_, err := runSSHClient("vey-ssh-test-nonexistent-binary", nil, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("runSSHClient with a nonexistent binary returned a nil error, want a local-start failure")
	}
}

// --- buildSSHArgs (pure) -----------------------------------------------

// TestBuildSSHArgs_HappyPath pins the exact argv shape for a fully-resolved
// invocation, independent of any HTTP/filesystem plumbing.
func TestBuildSSHArgs_HappyPath(t *testing.T) {
	argv, err := buildSSHArgs(sshInvocation{
		identityFile:   "/tmp/x/id_ed25519",
		knownHostsFile: "/tmp/x/known_hosts",
		port:           2222,
		username:       "alice",
		server:         "bastion1",
		gatewayHost:    "hub.example.com",
	})
	if err != nil {
		t.Fatalf("buildSSHArgs: %v", err)
	}
	want := []string{
		"-i", "/tmp/x/id_ed25519",
		"-p", "2222",
		"-o", "UserKnownHostsFile=/tmp/x/known_hosts",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "IdentitiesOnly=yes",
		"alice+bastion1@hub.example.com",
	}
	if !slices.Equal(argv, want) {
		t.Errorf("argv = %v, want %v", argv, want)
	}
}

// TestBuildSSHArgs_UsernameWithPlus_Rejected covers the addressing scheme's
// documented limitation (contracts/ssh-gateway.md: "usernames containing +
// are not supported").
func TestBuildSSHArgs_UsernameWithPlus_Rejected(t *testing.T) {
	_, err := buildSSHArgs(sshInvocation{
		identityFile: "/tmp/x/id_ed25519", knownHostsFile: "/tmp/x/known_hosts",
		port: 2222, username: "a+b", server: "bastion1", gatewayHost: "hub.example.com",
	})
	if err == nil {
		t.Fatal("buildSSHArgs with a '+' in the username returned nil error, want a rejection")
	}
}

// TestBuildSSHArgs_MissingFields covers every "incomplete invocation"
// branch, so the guard clauses are not dead code.
func TestBuildSSHArgs_MissingFields(t *testing.T) {
	base := sshInvocation{
		identityFile: "id", knownHostsFile: "kh", port: 2222,
		username: "alice", server: "bastion1", gatewayHost: "hub.example.com",
	}
	cases := []struct {
		name   string
		modify func(*sshInvocation)
	}{
		{"identityFile", func(s *sshInvocation) { s.identityFile = "" }},
		{"knownHostsFile", func(s *sshInvocation) { s.knownHostsFile = "" }},
		{"port", func(s *sshInvocation) { s.port = 0 }},
		{"username", func(s *sshInvocation) { s.username = "" }},
		{"server", func(s *sshInvocation) { s.server = "" }},
		{"gatewayHost", func(s *sshInvocation) { s.gatewayHost = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base
			c.modify(&in)
			if _, err := buildSSHArgs(in); err == nil {
				t.Errorf("buildSSHArgs with empty %s returned nil error, want a rejection", c.name)
			}
		})
	}
}

// --- certPrincipal (pure) -----------------------------------------------

// TestCertPrincipal_ExtractsFromRealCertificate covers the happy path.
func TestCertPrincipal_ExtractsFromRealCertificate(t *testing.T) {
	_, certLine := makeTestUserCert(t, "alice", time.Now().Add(time.Hour))
	got, err := certPrincipal(certLine)
	if err != nil {
		t.Fatalf("certPrincipal: %v", err)
	}
	if got != "alice" {
		t.Errorf("certPrincipal = %q, want %q", got, "alice")
	}
}

// TestCertPrincipal_Garbage covers an unreadable stored certificate.
func TestCertPrincipal_Garbage(t *testing.T) {
	if _, err := certPrincipal("not a certificate"); err == nil {
		t.Fatal("certPrincipal on garbage returned nil error")
	}
}

// --- usage / plumbing --------------------------------------------------

// TestSSH_MissingServerArg_ExitUsage covers "vey ssh" with no argument.
func TestSSH_MissingServerArg_ExitUsage(t *testing.T) {
	_, srv, configDir := seedForSSH(t, "tok-1")
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, nil)
	code := RunSSH(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestSSH_TooManyArgs_ExitUsage covers "vey ssh a b".
func TestSSH_TooManyArgs_ExitUsage(t *testing.T) {
	_, srv, configDir := seedForSSH(t, "tok-1")
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"a", "b"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestSSH_NoHub_ExitUsage covers the shared RequireHub branch.
func TestSSH_NoHub_ExitUsage(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")
	ctx, stdout, stderr := newCmdContext("", t.TempDir(), false, []string{"bastion1"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestSSH_HostKeyFetchFailure covers a hub error on GET /api/ssh/host-key:
// the error's own mapped code is surfaced (here, a generic hub failure), and
// ssh is never exec'd.
func TestSSH_HostKeyFetchFailure(t *testing.T) {
	mux, srv, configDir := seedForSSH(t, "tok-1")
	seedSSHMaterial(t, configDir, srv.URL, "alice", time.Now().Add(2*time.Hour))
	mux.HandleFunc("GET /api/ssh/host-key", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mountSingleServer(mux, "bastion1", api.Server{ID: "s1", Name: "bastion1", Status: "online"})
	stubSSHTTY(t, true)
	captured := stubExecSSH(t, nil)

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"bastion1"})
	code := RunSSH(ctx)
	if code != cmdutil.ExitError {
		t.Fatalf("exit code = %d, want %d (ExitError); stdout=%q stderr=%q", code, cmdutil.ExitError, stdout.String(), stderr.String())
	}
	if *captured != nil {
		t.Errorf("ssh was exec'd despite a host-key fetch failure: argv=%v", *captured)
	}
}

// TestSSH_IsRegistered guards the registry wiring.
func TestSSH_IsRegistered(t *testing.T) {
	if _, ok := Registry["ssh"]; !ok {
		t.Error(`Registry has no "ssh" entry`)
	}
}
