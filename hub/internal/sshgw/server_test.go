package sshgw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	testCertTTL     = time.Hour
	fmtDialUnwanted = "ssh.Dial() unexpectedly succeeded for %s"
	fmtNewSession   = "NewSession() error: %v"
	fmtRequestPty   = "RequestPty() error: %v"
	fmtShell        = "Shell() error: %v"
)

// ---------------------------------------------------------------------------
// client helpers
// ---------------------------------------------------------------------------

// newClientKey returns a fresh Ed25519 client signer.
func newClientKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error: %v", err)
	}
	return signer
}

// certAuth mints a user certificate from ca for principal and wraps it as an
// SSH auth method, exactly as `vey ssh-cert` + `ssh -i` would.
func certAuth(t *testing.T, ca *userca.UserCA, principal string, ttl time.Duration) ssh.AuthMethod {
	t.Helper()
	client := newClientKey(t)
	cert, err := ca.SignUserCert(client.PublicKey(), principal, ttl)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, client)
	if err != nil {
		t.Fatalf("NewCertSigner() error: %v", err)
	}
	return ssh.PublicKeys(certSigner)
}

// foreignCA returns a user CA the gateway does not trust.
func foreignCA(t *testing.T) *userca.UserCA {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf(fmtStoreNew, err)
	}
	t.Cleanup(func() { st.Close() })
	ca, err := userca.InitUserCA(st, "a-completely-different-storage-key")
	if err != nil {
		t.Fatalf(fmtInitUserCA, err)
	}
	return ca
}

// banners collects the auth banners the gateway sends, which is how the
// gateway explains a refusal to a not-yet-authenticated client.
type banners struct {
	mu   sync.Mutex
	msgs []string
}

func (b *banners) callback(msg string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.msgs = append(b.msgs, msg)
	return nil
}

func (b *banners) joined() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(b.msgs, "\n")
}

func (f *fixture) dial(connUser string, auth ssh.AuthMethod, seen *banners) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            connUser,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.FixedHostKey(f.hostKey.PublicKey()),
		Timeout:         waitTimeout,
	}
	if seen != nil {
		cfg.BannerCallback = seen.callback
	}
	return ssh.Dial("tcp", f.srv.Addr(), cfg)
}

// mustDial connects as <username>+<server> with a freshly minted certificate.
func (f *fixture) mustDial(connUser string) *ssh.Client {
	f.t.Helper()
	client, err := f.dial(connUser, certAuth(f.t, f.ca, testUsername, testCertTTL), nil)
	if err != nil {
		f.t.Fatalf("ssh.Dial(%s) error: %v", connUser, err)
	}
	f.t.Cleanup(func() { _ = client.Close() })
	return client
}

// readWithTimeout performs one bounded read, returning "" if nothing arrives.
func readWithTimeout(r io.Reader, d time.Duration) string {
	type result struct {
		data string
	}
	out := make(chan result, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		out <- result{data: string(buf[:n])}
	}()
	select {
	case res := <-out:
		return res.data
	case <-time.After(d):
		return ""
	}
}

// ---------------------------------------------------------------------------
// T014 — gateway round-trip
// ---------------------------------------------------------------------------

// TestGatewayShellRoundTrip is the end-to-end happy path: a CA-signed
// certificate opens a real SSH connection, a PTY shell is bridged to a stubbed
// agent, data flows both ways, a resize is relayed, and the remote exit status
// reaches the client. Open and close are audited.
func TestGatewayShellRoundTrip(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	client := f.mustDial(testUsername + "+" + testServerName)
	sess, stdin, stdout := startPTYShell(t, client)

	sessionID := f.openSessionID()
	f.assertOpenRequestGeometry(t, 80, 24)
	f.assertAgentOutputReachesClient(t, sessionID, stdout)
	f.assertClientInputReachesAgent(t, stdin)
	f.assertWindowChangeReachesAgent(t, sess)
	f.assertRemoteExitStatus(t, sess, sessionID, 7)
	f.assertRoundTripAudits(t)
}

// startPTYShell opens a session, requests an 80x24 PTY and starts the shell,
// returning the session, its stdin pipe and the buffer collecting its stdout.
func startPTYShell(t *testing.T, client *ssh.Client) (*ssh.Session, io.WriteCloser, *lockedBuffer) {
	t.Helper()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf(fmtNewSession, err)
	}
	stdout := &lockedBuffer{}
	sess.Stdout = stdout
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error: %v", err)
	}
	if err := sess.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf(fmtRequestPty, err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf(fmtShell, err)
	}
	return sess, stdin, stdout
}

// assertOpenRequestGeometry pins the geometry and execution user the agent is
// asked to open the terminal with. A local admin authorizes with an EMPTY
// execution user — the agent's default RunAsUser — which is success, not a
// failure.
func (f *fixture) assertOpenRequestGeometry(t *testing.T, cols, rows uint32) {
	t.Helper()
	open := f.agent.waitForMessage(t, "TerminalOpenRequest", func(m *pb.HubMessage) bool {
		return m.GetTerminalOpenRequest() != nil
	}).GetTerminalOpenRequest()
	if open.Cols != cols || open.Rows != rows {
		t.Errorf("TerminalOpenRequest geometry = %dx%d, want %dx%d", open.Cols, open.Rows, cols, rows)
	}
	if open.RunAsUser != "" {
		t.Errorf("RunAsUser = %q, want empty for a local admin", open.RunAsUser)
	}
}

func (f *fixture) assertAgentOutputReachesClient(t *testing.T, sessionID string, stdout *lockedBuffer) {
	t.Helper()
	if !f.terminals.DeliverData(testServerID, sessionID, []byte("motd line\r\n")) {
		t.Fatal("DeliverData() dropped the payload")
	}
	waitFor(t, "agent output at the ssh client", func() bool {
		return strings.Contains(stdout.String(), "motd line")
	})
}

func (f *fixture) assertClientInputReachesAgent(t *testing.T, stdin io.Writer) {
	t.Helper()
	if _, err := stdin.Write([]byte("uptime\r")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	input := f.agent.waitForMessage(t, "TerminalInput", func(m *pb.HubMessage) bool {
		return m.GetTerminalInput() != nil
	}).GetTerminalInput()
	if string(input.Data) != "uptime\r" {
		t.Errorf("TerminalInput.Data = %q, want %q", input.Data, "uptime\r")
	}
}

func (f *fixture) assertWindowChangeReachesAgent(t *testing.T, sess *ssh.Session) {
	t.Helper()
	if err := sess.WindowChange(43, 132); err != nil {
		t.Fatalf("WindowChange() error: %v", err)
	}
	resize := f.agent.waitForMessage(t, "TerminalResize", func(m *pb.HubMessage) bool {
		return m.GetTerminalResize() != nil
	}).GetTerminalResize()
	if resize.Cols != 132 || resize.Rows != 43 {
		t.Errorf("TerminalResize = %dx%d, want 132x43", resize.Cols, resize.Rows)
	}
}

// assertRemoteExitStatus ends the terminal on the agent side and asserts the
// remote status reaches the SSH client verbatim.
func (f *fixture) assertRemoteExitStatus(t *testing.T, sess *ssh.Session, sessionID string, want int) {
	t.Helper()
	f.terminals.End(testServerID, sessionID, int32(want), "")
	err := sess.Wait()
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Wait() error = %v, want *ssh.ExitError", err)
	}
	if exitErr.ExitStatus() != want {
		t.Errorf("exit status = %d, want %d", exitErr.ExitStatus(), want)
	}
}

func (f *fixture) assertRoundTripAudits(t *testing.T) {
	t.Helper()
	opened := f.waitForAudit(model.AuditSSHSessionOpened)
	if opened.UserID == nil || *opened.UserID != testUserID {
		t.Errorf("ssh.session_opened user = %v, want %q", opened.UserID, testUserID)
	}
	if opened.Target == nil || *opened.Target != testServerID {
		t.Errorf("ssh.session_opened target = %v, want %q", opened.Target, testServerID)
	}
	f.waitForAudit(model.AuditSSHSessionClosed)
}

// TestGatewayRejectsCertificateFromAnotherCA is the load-bearing trust-root
// test (research R1a): ssh.CertChecker.CheckCert verifies a certificate against
// its own embedded SignatureKey and never consults IsUserAuthority, so a
// gateway that used CheckCert would accept a certificate minted by ANY CA.
// Only CertChecker.Authenticate enforces the trust root.
func TestGatewayRejectsCertificateFromAnotherCA(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	other := foreignCA(t)
	client, err := f.dial(testUsername+"+"+testServerName, certAuth(t, other, testUsername, testCertTTL), nil)
	if err == nil {
		_ = client.Close()
		t.Fatalf(fmtDialUnwanted, "a certificate signed by an untrusted CA")
	}
}

func TestGatewayRejectsExpiredCertificate(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	client, err := f.dial(testUsername+"+"+testServerName, certAuth(t, f.ca, testUsername, -time.Hour), nil)
	if err == nil {
		_ = client.Close()
		t.Fatalf(fmtDialUnwanted, "an expired certificate")
	}
}

func TestGatewayRejectsPrincipalMismatch(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	// The certificate's sole principal is "alice"; the connection claims "bob".
	client, err := f.dial("bob+"+testServerName, certAuth(t, f.ca, testUsername, testCertTTL), nil)
	if err == nil {
		_ = client.Close()
		t.Fatalf(fmtDialUnwanted, "a principal mismatch")
	}
}

func TestGatewayRejectsBarePublicKey(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	client, err := f.dial(testUsername+"+"+testServerName, ssh.PublicKeys(newClientKey(t)), nil)
	if err == nil {
		_ = client.Close()
		t.Fatalf(fmtDialUnwanted, "an uncertified public key")
	}
}

// TestGatewayRefusesUsernameWithoutSeparator pins FR-016.
func TestGatewayRefusesUsernameWithoutSeparator(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	seen := &banners{}
	client, err := f.dial(testUsername, certAuth(t, f.ca, testUsername, testCertTTL), seen)
	if err == nil {
		_ = client.Close()
		t.Fatalf(fmtDialUnwanted, "a username without a '+' separator")
	}
	got := seen.joined()
	if !strings.Contains(got, "+") || !strings.Contains(got, "veyport") {
		t.Errorf("banner = %q, want an explanation of the <user>+<server> form", got)
	}
}

// TestGatewaySplitsOnFirstSeparator pins the "split on the FIRST +" rule: the
// principal is the bare username and the remainder is the server name, even
// when the server name itself contains a '+'.
func TestGatewaySplitsOnFirstSeparator(t *testing.T) {
	const oddName = "edge+case"
	const oddID = "srv-2"
	f := newFixture(t, nil)
	if err := f.store.CreateServer(&model.Server{ID: oddID, Name: oddName, Status: "online", Labels: "{}"}); err != nil {
		t.Fatalf(fmtCreateServer, err)
	}
	oddAgent := newStubAgent(f.pending, oddID)
	f.connMgr.Register(oddID, oddAgent)
	f.start()

	client := f.mustDial(testUsername + "+" + oddName)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf(fmtNewSession, err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf(fmtRequestPty, err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf(fmtShell, err)
	}

	// The open request reaches the "edge+case" agent: the username split on the
	// FIRST '+' gave principal "alice" and target "edge+case".
	oddAgent.waitForMessage(t, "TerminalOpenRequest on the '+'-named server", func(m *pb.HubMessage) bool {
		return m.GetTerminalOpenRequest() != nil
	})
	if len(f.agent.messages()) != 0 {
		t.Error("the open request went to the wrong server")
	}
}

// TestGatewayUnknownServerFails pins FR-012's distinct failures.
func TestGatewayUnknownServerFails(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	stderr, exitStatus := f.runRefusedShell(testUsername + "+nosuchbox")
	if !strings.Contains(stderr, "unknown server") {
		t.Errorf("stderr = %q, want an unknown-server message", stderr)
	}
	if exitStatus == 0 {
		t.Error("refused session exited 0, want a non-zero status")
	}
	f.waitForAudit(model.AuditSSHSessionRefused)
}

func TestGatewayAmbiguousServerFails(t *testing.T) {
	// Server names are unique, so the only ambiguity is a token that is one
	// server's name and a different server's ID.
	const collide = "twins"
	f := newFixture(t, nil)
	if err := f.store.CreateServer(&model.Server{ID: collide, Name: "by-id", Status: "online", Labels: "{}"}); err != nil {
		t.Fatalf(fmtCreateServer, err)
	}
	if err := f.store.CreateServer(&model.Server{ID: "srv-3", Name: collide, Status: "online", Labels: "{}"}); err != nil {
		t.Fatalf(fmtCreateServer, err)
	}
	f.start()

	stderr, _ := f.runRefusedShell(testUsername + "+" + collide)
	if !strings.Contains(stderr, "ambiguous") {
		t.Errorf("stderr = %q, want an ambiguity message", stderr)
	}
	f.waitForAudit(model.AuditSSHSessionRefused)
}

func TestGatewayOfflineServerFails(t *testing.T) {
	f := newFixture(t, nil)
	// Deliberately no connectAgent(): the server exists but no agent is up.
	f.start()

	stderr, _ := f.runRefusedShell(testUsername + "+" + testServerName)
	if !strings.Contains(stderr, "unavailable") {
		t.Errorf("stderr = %q, want an unavailability message", stderr)
	}
	entry := f.waitForAudit(model.AuditSSHSessionRefused)
	if entry.Outcome != model.AuditOutcomeFailure {
		t.Errorf("audit outcome = %q, want %q", entry.Outcome, model.AuditOutcomeFailure)
	}
}

// TestGatewayUnauthorizedUserRefused asserts the shared authorization core is
// enforced on the SSH path too (FR-007).
func TestGatewayUnauthorizedUserRefused(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.store.CreateUser(&model.User{
		ID: testViewerID, Username: testViewerName, Email: "m@example.test",
		PasswordHash: "x", Role: model.RoleViewer,
	}); err != nil {
		t.Fatalf(fmtCreateUser, err)
	}
	f.connectAgent()
	f.start()

	client, err := f.dial(testViewerName+"+"+testServerName, certAuth(t, f.ca, testViewerName, testCertTTL), nil)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	defer func() { _ = client.Close() }()

	stderr, _ := runRefusedShellOn(t, client)
	if !strings.Contains(stderr, "terminal access") {
		t.Errorf("stderr = %q, want a permission message", stderr)
	}
	entry := f.waitForAudit(model.AuditSSHSessionRefused)
	if entry.UserID == nil || *entry.UserID != testViewerID {
		t.Errorf("audit user = %v, want %q", entry.UserID, testViewerID)
	}
}

// TestGatewayRefusesOutOfScopeCapabilities pins FR-010 / SC-006: exec,
// subsystem, direct-tcpip, remote forwarding and agent forwarding are each
// refused cleanly while a concurrent PTY session keeps working.
func TestGatewayRefusesOutOfScopeCapabilities(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	client := f.mustDial(testUsername + "+" + testServerName)

	// A live PTY session that must survive every refusal below.
	sess, _, stdout := startPTYShell(t, client)
	sessionID := f.openSessionID()

	t.Run("exec", func(t *testing.T) { assertExecRefused(t, client) })
	t.Run("subsystem", func(t *testing.T) { assertSubsystemRefused(t, client) })
	t.Run("direct-tcpip", func(t *testing.T) { assertDirectTCPIPRefused(t, client) })
	t.Run("remote-forward", func(t *testing.T) { assertRemoteForwardRefused(t, client) })
	t.Run("agent-forward", func(t *testing.T) { assertAgentForwardRefused(t, sess) })

	f.assertSessionStillRelaying(t, sessionID, stdout)

	f.terminals.End(testServerID, sessionID, 0, "")
	_ = sess.Wait()
}

// openRawSession opens a session channel and discards its replies, so a test
// can drive the exact channel requests the gateway sees.
func openRawSession(t *testing.T, client *ssh.Client) ssh.Channel {
	t.Helper()
	ch, reqs, err := client.OpenChannel(channelSession, nil)
	if err != nil {
		t.Fatalf("OpenChannel() error: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	t.Cleanup(func() { _ = ch.Close() })
	return ch
}

// sendChannelRequest sends one channel request and reports the gateway's reply.
func sendChannelRequest(t *testing.T, ch ssh.Channel, name string, payload []byte) bool {
	t.Helper()
	ok, err := ch.SendRequest(name, true, payload)
	if err != nil {
		t.Fatalf("SendRequest(%s) error: %v", name, err)
	}
	return ok
}

// assertExecRefused pins the client-visible exec refusal (FR-010). The
// request is ACCEPTED at the protocol level and then failed with a stderr
// explanation and exit-status 1, because a plain request-refusal is invisible
// to real clients: OpenSSH prints only its own "exec request failed on
// channel 0" and tears down before displaying stderr data racing the reply
// (observed 0/11 message deliveries against OpenSSH on the T026 staging run).
func assertExecRefused(t *testing.T, client *ssh.Client) {
	ch, reqs, err := client.OpenChannel(channelSession, nil)
	if err != nil {
		t.Fatalf("OpenChannel() error: %v", err)
	}
	t.Cleanup(func() { _ = ch.Close() })

	exitStatus := make(chan uint32, 1)
	go func() {
		for r := range reqs {
			if r.Type == reqExitStatus && len(r.Payload) >= 4 {
				exitStatus <- binary.BigEndian.Uint32(r.Payload[:4])
			}
		}
	}()

	ok, err := ch.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{Command: "id"}))
	if err != nil {
		t.Fatalf("SendRequest(exec) error: %v", err)
	}
	if !ok {
		t.Fatal("exec request was refused at the protocol level; want it accepted and then failed visibly (stderr + exit-status)")
	}
	if msg := readWithTimeout(ch.Stderr(), 2*time.Second); !strings.Contains(msg, "veyport") {
		t.Errorf("exec refusal message = %q, want an explanation", msg)
	}
	select {
	case code := <-exitStatus:
		if code == 0 {
			t.Error("exec exit-status = 0, want non-zero")
		}
	case <-time.After(2 * time.Second):
		t.Error("no exit-status request received after refused exec")
	}
}

func assertSubsystemRefused(t *testing.T, client *ssh.Client) {
	ch := openRawSession(t, client)
	if sendChannelRequest(t, ch, "subsystem", ssh.Marshal(struct{ Subsystem string }{Subsystem: "sftp"})) {
		t.Fatal("subsystem was accepted, want a clean refusal")
	}
}

func assertDirectTCPIPRefused(t *testing.T, client *ssh.Client) {
	conn, err := client.Dial("tcp", "192.0.2.10:80")
	if err == nil {
		_ = conn.Close()
		t.Fatal("direct-tcpip was accepted, want a clean refusal")
	}
	if !strings.Contains(err.Error(), "veyport") {
		t.Errorf("direct-tcpip refusal = %q, want an explanation", err)
	}
}

func assertRemoteForwardRefused(t *testing.T, client *ssh.Client) {
	lis, err := client.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		_ = lis.Close()
		t.Fatal("tcpip-forward was accepted, want a clean refusal")
	}
}

func assertAgentForwardRefused(t *testing.T, sess *ssh.Session) {
	ok, err := sess.SendRequest("auth-agent-req@openssh.com", true, nil)
	if err != nil {
		t.Fatalf("SendRequest(auth-agent-req) error: %v", err)
	}
	if ok {
		t.Fatal("agent forwarding was accepted, want a clean refusal")
	}
}

// assertSessionStillRelaying proves the concurrent PTY session survived every
// refusal: a rejected request must never disturb a live shell.
func (f *fixture) assertSessionStillRelaying(t *testing.T, sessionID string, stdout *lockedBuffer) {
	t.Helper()
	if !f.terminals.DeliverData(testServerID, sessionID, []byte("still here\r\n")) {
		t.Fatal("DeliverData() dropped the payload")
	}
	waitFor(t, "the concurrent PTY session to keep relaying", func() bool {
		return strings.Contains(stdout.String(), "still here")
	})
}

// TestGatewayDropsIdleUnauthenticatedConnection pins SC-009 / FR-014.
func TestGatewayDropsIdleUnauthenticatedConnection(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.HandshakeTimeout = 250 * time.Millisecond })
	f.start()

	conn, err := net.Dial("tcp", f.srv.Addr())
	if err != nil {
		t.Fatalf("net.Dial() error: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Never send a version string; the gateway must hang up on its own.
	if err := conn.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("SetReadDeadline() error: %v", err)
	}
	buf := make([]byte, 256)
	for {
		if _, err = conn.Read(buf); err != nil {
			break
		}
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("idle unauthenticated connection was not dropped within the handshake deadline")
	}
}

// TestGatewayCapsConcurrentConnections pins the FR-014 connection cap.
func TestGatewayCapsConcurrentConnections(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.MaxConns = 1 })
	f.start()

	first, err := net.Dial("tcp", f.srv.Addr())
	if err != nil {
		t.Fatalf("net.Dial() error: %v", err)
	}
	defer func() { _ = first.Close() }()
	waitFor(t, "the first connection to be tracked", func() bool { return f.srv.activeConns() == 1 })

	second, err := net.Dial("tcp", f.srv.Addr())
	if err != nil {
		t.Fatalf("net.Dial() error: %v", err)
	}
	defer func() { _ = second.Close() }()
	if err := second.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("SetReadDeadline() error: %v", err)
	}
	buf := make([]byte, 64)
	if _, err := second.Read(buf); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("second connection was not dropped at the cap (read err = %v)", err)
	}
}

// TestGatewayDisabledNeverListens pins FR-015.
func TestGatewayDisabledNeverListens(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.Enabled = false })

	if err := f.srv.Start(); err != nil {
		t.Fatalf("Start() error for a disabled gateway: %v", err)
	}
	if addr := f.srv.Addr(); addr != "" {
		t.Errorf("Addr() = %q, want no listener when disabled", addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	if err := f.srv.Stop(ctx); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
}

// TestGatewayUnusableHostKeyDisablesListener pins FR-006: the hub keeps
// serving, the SSH port is simply never opened, and the refusal is loud.
func TestGatewayUnusableHostKeyDisablesListener(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.HostKey = nil })

	if err := f.srv.Start(); err != nil {
		t.Fatalf("Start() error with unusable key material: %v", err)
	}
	if addr := f.srv.Addr(); addr != "" {
		t.Errorf("Addr() = %q, want no listener without a host key", addr)
	}
	entry := f.waitForAudit(model.AuditSSHSessionRefused)
	if entry.Outcome != model.AuditOutcomeFailure {
		t.Errorf("audit outcome = %q, want %q", entry.Outcome, model.AuditOutcomeFailure)
	}
	if entry.Detail == nil || !strings.Contains(*entry.Detail, "host key") {
		t.Errorf("audit detail = %v, want it to name the unusable host key", entry.Detail)
	}
}

func TestGatewayMissingUserCADisablesListener(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.UserCA = nil })

	if err := f.srv.Start(); err != nil {
		t.Fatalf("Start() error with unusable key material: %v", err)
	}
	if addr := f.srv.Addr(); addr != "" {
		t.Errorf("Addr() = %q, want no listener without a user CA", addr)
	}
	f.waitForAudit(model.AuditSSHSessionRefused)
}

// ---------------------------------------------------------------------------
// shared refusal helper
// ---------------------------------------------------------------------------

// runRefusedShell opens a shell that the gateway is expected to refuse after
// authentication, returning what the operator sees and the exit status.
func (f *fixture) runRefusedShell(connUser string) (string, int) {
	f.t.Helper()
	client := f.mustDial(connUser)
	return runRefusedShellOn(f.t, client)
}

func runRefusedShellOn(t *testing.T, client *ssh.Client) (string, int) {
	t.Helper()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf(fmtNewSession, err)
	}
	defer func() { _ = sess.Close() }()
	stderr := &lockedBuffer{}
	sess.Stderr = stderr
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf(fmtRequestPty, err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf(fmtShell, err)
	}
	waitErr := sess.Wait()
	status := 0
	var exitErr *ssh.ExitError
	if errors.As(waitErr, &exitErr) {
		status = exitErr.ExitStatus()
	}
	return stderr.String(), status
}
