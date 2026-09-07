package integration

// Cross-package integration test for the SSH gateway (feature 005-ssh-gateway,
// T018). Constitution Principle II requires cross-package behavior and gRPC
// contracts to be exercised here, with the REAL components wired together — no
// mock of the gRPC layer.
//
// What is real: the store (temp DB on disk), ca.InitCA, userca.InitUserCA /
// InitHostKey, connmgr.ConnManager, grpcserver.PendingRequests,
// grpcserver.TerminalSessions, a grpcserver listening on an ephemeral port with
// mTLS, and sshgw.Server listening on a second ephemeral port sharing those
// exact instances. The only stub is the AGENT, and even it speaks the real
// protobuf terminal protocol over a real mTLS gRPC stream obtained through the
// normal enrollment path (registration token → CSR → client cert → reconnect).
//
// Authorization setup: an LDAP user ("alice") with terminal_access plus a "/"
// path assignment on the target server — the non-trivial branch of
// server.AuthorizeTerminalExecution. It is preferred over the local-admin
// shortcut because it yields a NON-EMPTY execution user, which lets the test
// assert that RunAsUser actually crosses the gRPC boundary.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/wyiu/veyport/hub/internal/ca"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
	"github.com/wyiu/veyport/hub/internal/sshgw"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	sshGWUsername   = "alice"
	sshGWServerName = "web01"
	sshGWServerID   = "srv-ssh-gateway-integration"
	sshGWRegToken   = "ssh-gateway-integration-registration-token"

	// sshGWTimeout bounds every wait in this test. Nothing here sleeps as a
	// synchronization primitive; sleeps appear only inside bounded poll loops
	// for state that has no channel to wait on (the connection registry and
	// the audit table).
	sshGWTimeout = 10 * time.Second
	sshGWPoll    = 5 * time.Millisecond

	sshGWCols = 80
	sshGWRows = 24
	// Geometry requested by the window-change step.
	sshGWNewCols = 132
	sshGWNewRows = 43

	sshGWCertTTL  = time.Hour
	sshGWChanBuf  = 16
	sshGWShellCmd = "uptime\r"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// sshGWHarness owns the real hub components shared by the gRPC server and the
// SSH gateway, exactly as main.go shares them.
type sshGWHarness struct {
	store     *store.Store
	connMgr   *connmgr.ConnManager
	pending   *grpcserver.PendingRequests
	terminals *grpcserver.TerminalSessions
	userCA    *userca.UserCA
	hostKey   ssh.Signer
	caCert    *x509.Certificate
	caPin     string
	grpcAddr  string
	sshAddr   string
}

// startSSHGWHarness brings up a real gRPC server and a real SSH gateway on
// ephemeral ports over a temp-file store, sharing one ConnManager,
// PendingRequests and TerminalSessions.
func startSSHGWHarness(t *testing.T) *sshGWHarness {
	t.Helper()

	st, err := store.New(filepath.Join(t.TempDir(), "veyport.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	storageKey, err := server.InitStorageKey(st)
	if err != nil {
		st.Close()
		t.Fatalf("InitStorageKey: %v", err)
	}
	caCert, caKey, err := ca.InitCA(st, storageKey)
	if err != nil {
		st.Close()
		t.Fatalf("ca.InitCA: %v", err)
	}
	userCA, err := userca.InitUserCA(st, storageKey)
	if err != nil {
		st.Close()
		t.Fatalf("userca.InitUserCA: %v", err)
	}
	hostKey, err := userca.InitHostKey(st, storageKey)
	if err != nil {
		st.Close()
		t.Fatalf("userca.InitHostKey: %v", err)
	}

	grpcPort, sshPort := freePortPair(t)
	h := &sshGWHarness{
		store:     st,
		connMgr:   connmgr.New(),
		pending:   grpcserver.NewPendingRequests(),
		terminals: grpcserver.NewTerminalSessions(),
		userCA:    userCA,
		hostKey:   hostKey,
		caCert:    caCert,
		caPin:     fmt.Sprintf("%x", sha256.Sum256(caCert.Raw)),
		grpcAddr:  fmt.Sprintf("127.0.0.1:%d", grpcPort),
		sshAddr:   fmt.Sprintf("127.0.0.1:%d", sshPort),
	}

	gs := grpcserver.New(grpcserver.Config{
		Addr:                   h.grpcAddr,
		HeartbeatFlushInterval: time.Second,
		Store:                  st,
		ConnMgr:                h.connMgr,
		Pending:                h.pending,
		LogSessions:            grpcserver.NewLogSessions(),
		TerminalSessions:       h.terminals,
		CACert:                 caCert,
		CAKey:                  caKey,
		StorageKey:             storageKey,
	})
	go func() { _ = gs.Start() }()

	sshSrv := sshgw.New(sshgw.Config{
		Store:     st,
		UserCA:    userCA,
		HostKey:   hostKey,
		Terminals: h.terminals,
		ConnMgr:   h.connMgr,
		Pending:   h.pending,
		Addr:      h.sshAddr,
		Enabled:   true,
	})
	go func() { _ = sshSrv.Start() }()

	waitForPort(t, h.grpcAddr, sshGWTimeout)
	waitForPort(t, h.sshAddr, sshGWTimeout)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), sshGWTimeout)
		defer cancel()
		_ = sshSrv.Stop(ctx)
		gs.Stop()
		st.Close()
	})

	return h
}

// seedAuthorizedUser creates the target server plus an LDAP user carrying
// terminal_access and a root ("/") assignment on it — the ladder branch that
// server.AuthorizeTerminalExecution allows with a non-empty execution user.
func (h *sshGWHarness) seedAuthorizedUser(t *testing.T) string {
	t.Helper()

	tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(sshGWRegToken)))
	if err := h.store.CreateServer(&model.Server{
		ID:                sshGWServerID,
		Name:              sshGWServerName,
		Status:            "pending",
		Labels:            "{}",
		RegistrationToken: &tokenHash,
	}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	user := &model.User{
		ID:             uuid.NewString(),
		Username:       sshGWUsername,
		Email:          sshGWUsername + "@test.com",
		Role:           model.RoleViewer,
		AuthProvider:   model.AuthProviderLDAP,
		LDAPUsername:   sshGWUsername,
		LDAPDN:         "uid=" + sshGWUsername + ",ou=people,dc=example,dc=com",
		ExternalID:     "entry-" + sshGWUsername,
		TerminalAccess: true,
	}
	if err := h.store.CreateUser(user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := h.store.CreatePermission(user.ID, sshGWServerID, "/"); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	return user.ID
}

// ---------------------------------------------------------------------------
// stub agent over the real gRPC stream
// ---------------------------------------------------------------------------

// sshStubAgent speaks the real terminal protocol on a real mTLS gRPC stream:
// it acks TerminalOpenRequest, echoes TerminalInput back as UPPERCASED
// TerminalData (so the test can tell hub→agent from agent→hub), and records
// TerminalResize and TerminalClose.
type sshStubAgent struct {
	stream  pb.AgentService_ConnectClient
	opens   chan *pb.TerminalOpenRequest
	inputs  chan *pb.TerminalInput
	resizes chan *pb.TerminalResize
	closes  chan *pb.TerminalClose
	done    chan struct{}
}

func newSSHStubAgent(stream pb.AgentService_ConnectClient) *sshStubAgent {
	return &sshStubAgent{
		stream:  stream,
		opens:   make(chan *pb.TerminalOpenRequest, sshGWChanBuf),
		inputs:  make(chan *pb.TerminalInput, sshGWChanBuf),
		resizes: make(chan *pb.TerminalResize, sshGWChanBuf),
		closes:  make(chan *pb.TerminalClose, sshGWChanBuf),
		done:    make(chan struct{}),
	}
}

// run is the agent's receive loop. It exits when the stream ends, which is how
// the test guarantees the goroutine is not leaked.
func (a *sshStubAgent) run() {
	defer close(a.done)
	for {
		msg, err := a.stream.Recv()
		if err != nil {
			return
		}
		if err := a.handle(msg); err != nil {
			return
		}
	}
}

func (a *sshStubAgent) handle(msg *pb.HubMessage) error {
	switch {
	case msg.GetTerminalOpenRequest() != nil:
		open := msg.GetTerminalOpenRequest()
		offer(a.opens, open)
		return a.stream.Send(&pb.AgentMessage{Payload: &pb.AgentMessage_TerminalOpenAck{
			TerminalOpenAck: &pb.TerminalOpenAck{SessionId: open.SessionId, Success: true},
		}})
	case msg.GetTerminalInput() != nil:
		in := msg.GetTerminalInput()
		offer(a.inputs, in)
		return a.stream.Send(&pb.AgentMessage{Payload: &pb.AgentMessage_TerminalData{
			TerminalData: &pb.TerminalData{SessionId: in.SessionId, Data: bytes.ToUpper(in.Data)},
		}})
	case msg.GetTerminalResize() != nil:
		offer(a.resizes, msg.GetTerminalResize())
	case msg.GetTerminalClose() != nil:
		// "Stop": the stub abandons the session but keeps the stream up so the
		// test can still observe the hub-side teardown.
		offer(a.closes, msg.GetTerminalClose())
	}
	return nil
}

// offer records a value without ever blocking the receive loop.
func offer[T any](ch chan T, v T) {
	select {
	case ch <- v:
	default:
	}
}

// enrollStubAgent walks the normal enrollment path — bootstrap stream with the
// registration token and a CSR, then a fresh mTLS stream authenticated by the
// issued client certificate — and starts the stub's receive loop.
func (h *sshGWHarness) enrollStubAgent(t *testing.T) *sshStubAgent {
	t.Helper()

	key, csrDER := newAgentKeypair(t)
	clientCertDER := h.bootstrapRegister(t, csrDER)
	conn, stream := h.dialAgentMTLS(t, clientCertDER, key)

	agent := newSSHStubAgent(stream)
	go agent.run()
	t.Cleanup(func() {
		_ = conn.Close()
		<-agent.done
	})

	waitFor(t, "agent registered in ConnMgr", func() bool {
		return h.connMgr.GetConn(sshGWServerID) != nil
	})
	return agent
}

// newAgentKeypair returns a fresh agent key and the matching CSR.
func newAgentKeypair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: sshGWServerID}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return key, csrDER
}

// bootstrapRegister performs the CA-pinned, no-client-certificate registration
// handshake and returns the issued client certificate.
func (h *sshGWHarness) bootstrapRegister(t *testing.T, csrDER []byte) []byte {
	t.Helper()

	tlsCfg, err := buildBootstrapTLS(h.caPin)
	if err != nil {
		t.Fatalf("buildBootstrapTLS: %v", err)
	}
	conn, err := grpc.NewClient(h.grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatalf("dial hub gRPC (bootstrap): %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), sshGWTimeout)
	defer cancel()
	stream, err := pb.NewAgentServiceClient(conn).Connect(ctx)
	if err != nil {
		t.Fatalf("open bootstrap Connect stream: %v", err)
	}
	err = stream.Send(&pb.AgentMessage{Payload: &pb.AgentMessage_Register{
		Register: &pb.RegisterAgent{
			Token:        sshGWRegToken,
			Hostname:     sshGWServerName,
			IpAddress:    "10.0.0.9",
			Os:           "linux",
			AgentVersion: "0.0.0-test",
			Csr:          csrDER,
		},
	}})
	if err != nil {
		t.Fatalf("send RegisterAgent: %v", err)
	}

	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv RegisterAck: %v", err)
	}
	ack := msg.GetRegisterAck()
	if ack == nil || !ack.Success {
		t.Fatalf("registration refused: %+v", msg.Payload)
	}
	if ack.ServerId != sshGWServerID {
		t.Fatalf("RegisterAck server id = %q, want %q", ack.ServerId, sshGWServerID)
	}
	return ack.ClientCert
}

// dialAgentMTLS opens the authenticated stream the way a registered agent does:
// mTLS with the issued client certificate, Heartbeat as the first message.
func (h *sshGWHarness) dialAgentMTLS(t *testing.T, clientCertDER []byte, key *ecdsa.PrivateKey) (*grpc.ClientConn, pb.AgentService_ConnectClient) {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AddCert(h.caCert)
	conn, err := grpc.NewClient(h.grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{clientCertDER}, PrivateKey: key}},
	})))
	if err != nil {
		t.Fatalf("dial hub gRPC (mTLS): %v", err)
	}

	stream, err := pb.NewAgentServiceClient(conn).Connect(context.Background())
	if err != nil {
		conn.Close()
		t.Fatalf("open mTLS Connect stream: %v", err)
	}
	err = stream.Send(&pb.AgentMessage{Payload: &pb.AgentMessage_Heartbeat{
		Heartbeat: &pb.Heartbeat{ServerId: sshGWServerID, Timestamp: time.Now().Unix(), IpAddress: "10.0.0.9"},
	}})
	if err != nil {
		conn.Close()
		t.Fatalf("send Heartbeat: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		conn.Close()
		t.Fatalf("recv HeartbeatAck: %v", err)
	}
	if msg.GetHeartbeatAck() == nil {
		conn.Close()
		t.Fatalf("first hub message = %+v, want HeartbeatAck", msg.Payload)
	}
	return conn, stream
}

// ---------------------------------------------------------------------------
// ssh client
// ---------------------------------------------------------------------------

// dialSSH connects to the gateway as <user>+<server> with a certificate minted
// by the real user CA, pinning the real gateway host key.
func (h *sshGWHarness) dialSSH(t *testing.T) *ssh.Client {
	t.Helper()

	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	cert, err := h.userCA.SignUserCert(signer.PublicKey(), sshGWUsername, sshGWCertTTL)
	if err != nil {
		t.Fatalf("SignUserCert: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatalf("NewCertSigner: %v", err)
	}

	client, err := ssh.Dial("tcp", h.sshAddr, &ssh.ClientConfig{
		User:            sshGWUsername + "+" + sshGWServerName,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.FixedHostKey(h.hostKey.PublicKey()),
		Timeout:         sshGWTimeout,
	})
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// startPTYShell requests a PTY and a shell, returning the session, its stdin
// and a channel carrying stdout chunks.
func startPTYShell(t *testing.T, client *ssh.Client) (*ssh.Session, io.WriteCloser, <-chan []byte) {
	t.Helper()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := sess.RequestPty("xterm-256color", sshGWRows, sshGWCols, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	return sess, stdin, streamChunks(stdout)
}

// streamChunks pumps a reader into a channel until it fails, which happens when
// the session closes — so the goroutine always terminates.
func streamChunks(r io.Reader) <-chan []byte {
	out := make(chan []byte, sshGWChanBuf)
	go func() {
		defer close(out)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				out <- chunk
			}
			if err != nil {
				return
			}
		}
	}()
	return out
}

// ---------------------------------------------------------------------------
// waiting helpers (channels + deadlines, never sleeps as synchronization)
// ---------------------------------------------------------------------------

// await returns the next value on ch or fails the test.
func await[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(sshGWTimeout):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}

// awaitOutput accumulates ssh stdout until want appears.
func awaitOutput(t *testing.T, chunks <-chan []byte, want string) {
	t.Helper()
	var got []byte
	deadline := time.After(sshGWTimeout)
	for {
		select {
		case chunk, ok := <-chunks:
			if !ok {
				t.Fatalf("ssh stdout closed before %q arrived; got %q", want, got)
			}
			got = append(got, chunk...)
			if bytes.Contains(got, []byte(want)) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q on the ssh channel; got %q", want, got)
		}
	}
}

// waitFor polls cond until it holds. Used only for state with no channel to
// wait on (the connection registry, the terminal registry, the audit table).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(sshGWTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(sshGWPoll)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// awaitAudit polls the real store until the given action lands for
// (userID, serverID) and returns it.
func (h *sshGWHarness) awaitAudit(t *testing.T, action, userID string) model.AuditEntry {
	t.Helper()
	var found model.AuditEntry
	waitFor(t, "audit entry "+action, func() bool {
		entries, _, err := h.store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 50})
		if err != nil {
			return false
		}
		for _, e := range entries {
			if e.UserID != nil && *e.UserID == userID && e.Target != nil && *e.Target == sshGWServerID {
				found = e
				return true
			}
		}
		return false
	})
	return found
}

// ---------------------------------------------------------------------------
// assertions
// ---------------------------------------------------------------------------

func assertOpenRequest(t *testing.T, open *pb.TerminalOpenRequest) {
	t.Helper()
	if open.Cols != sshGWCols || open.Rows != sshGWRows {
		t.Errorf("TerminalOpenRequest geometry = %dx%d, want %dx%d",
			open.Cols, open.Rows, sshGWCols, sshGWRows)
	}
	// The LDAP execution user must survive the whole path: store → authz core
	// → gateway → gRPC → agent.
	if open.RunAsUser != sshGWUsername {
		t.Errorf("TerminalOpenRequest RunAsUser = %q, want %q", open.RunAsUser, sshGWUsername)
	}
	if open.SessionId == "" {
		t.Fatal("TerminalOpenRequest carried an empty session id")
	}
}

func assertAuditOutcome(t *testing.T, entry model.AuditEntry, action, sessionID string) {
	t.Helper()
	if entry.Outcome != model.AuditOutcomeSuccess {
		t.Errorf("%s outcome = %q, want %q", action, entry.Outcome, model.AuditOutcomeSuccess)
	}
	if entry.Detail == nil || !bytes.Contains([]byte(*entry.Detail), []byte(sessionID)) {
		t.Errorf("%s detail = %v, want it to mention session %s", action, entry.Detail, sessionID)
	}
}

// ---------------------------------------------------------------------------
// T018 — the cross-package test
// ---------------------------------------------------------------------------

// TestSSHGatewayEndToEndThroughRealGRPC drives the whole gateway path against
// real components: certificate auth → PTY + shell → input relayed to the agent
// over the real gRPC stream → echoed output back on the SSH channel → resize →
// close, with the terminal registry drained and both audit entries written.
func TestSSHGatewayEndToEndThroughRealGRPC(t *testing.T) {
	h := startSSHGWHarness(t)
	userID := h.seedAuthorizedUser(t)
	agent := h.enrollStubAgent(t)

	client := h.dialSSH(t)
	sess, stdin, stdout := startPTYShell(t, client)

	// 1. The agent sees the open request, with the geometry and execution user
	//    that crossed every package boundary.
	open := await(t, agent.opens, "TerminalOpenRequest")
	assertOpenRequest(t, open)
	sessionID := open.SessionId

	// 2. client → agent, then agent → client (uppercased, so direction is
	//    unambiguous).
	if _, err := stdin.Write([]byte(sshGWShellCmd)); err != nil {
		t.Fatalf("write ssh stdin: %v", err)
	}
	input := await(t, agent.inputs, "TerminalInput")
	if input.SessionId != sessionID {
		t.Errorf("TerminalInput session = %q, want %q", input.SessionId, sessionID)
	}
	if string(input.Data) != sshGWShellCmd {
		t.Errorf("TerminalInput data = %q, want %q", input.Data, sshGWShellCmd)
	}
	awaitOutput(t, stdout, "UPTIME")

	// 3. window-change → TerminalResize.
	if err := sess.WindowChange(sshGWNewRows, sshGWNewCols); err != nil {
		t.Fatalf("WindowChange: %v", err)
	}
	resize := await(t, agent.resizes, "TerminalResize")
	if resize.Cols != sshGWNewCols || resize.Rows != sshGWNewRows {
		t.Errorf("TerminalResize = %dx%d, want %dx%d",
			resize.Cols, resize.Rows, sshGWNewCols, sshGWNewRows)
	}

	// 4. Close: the registry drains and the agent is told to close.
	if err := sess.Close(); err != nil && err != io.EOF {
		t.Fatalf("Session.Close: %v", err)
	}
	closeMsg := await(t, agent.closes, "TerminalClose")
	if closeMsg.SessionId != sessionID {
		t.Errorf("TerminalClose session = %q, want %q", closeMsg.SessionId, sessionID)
	}
	waitFor(t, "terminal session registry to drain", func() bool {
		_, ok := h.terminals.Get(sshGWServerID, sessionID)
		return !ok
	})

	// 5. Both audit entries landed in the real store for the right principal
	//    and target.
	assertAuditOutcome(t, h.awaitAudit(t, model.AuditSSHSessionOpened, userID),
		model.AuditSSHSessionOpened, sessionID)
	assertAuditOutcome(t, h.awaitAudit(t, model.AuditSSHSessionClosed, userID),
		model.AuditSSHSessionClosed, sessionID)
}
