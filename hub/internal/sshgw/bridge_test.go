package sshgw

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/metadata"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	testStorageKey  = "sshgw-test-storage-key-0123456789"
	testServerID    = "srv-1"
	testServerName  = "web01"
	testUserID      = "user-admin"
	testUsername    = "alice"
	testViewerID    = "user-viewer"
	testViewerName  = "mallory"
	waitTimeout     = 5 * time.Second
	pollInterval    = 2 * time.Millisecond
	fmtStoreNew     = "store.New() error: %v"
	fmtInitUserCA   = "InitUserCA() error: %v"
	fmtInitHostKey  = "InitHostKey() error: %v"
	fmtCreateUser   = "CreateUser() error: %v"
	fmtCreateServer = "CreateServer() error: %v"
)

// ---------------------------------------------------------------------------
// stub agent
// ---------------------------------------------------------------------------

// stubAgent implements pb.AgentService_ConnectServer. It records every
// HubMessage the hub sends and, unless silenced, answers a TerminalOpenRequest
// by delivering a TerminalOpenAck through the real PendingRequests registry —
// exactly the path the gRPC handler takes for a real agent.
type stubAgent struct {
	mu         sync.Mutex
	sent       []*pb.HubMessage
	pending    *grpcserver.PendingRequests
	serverID   string
	ackSuccess bool
	ackError   string
	silent     bool
	sendErr    error
}

func newStubAgent(pending *grpcserver.PendingRequests, serverID string) *stubAgent {
	return &stubAgent{pending: pending, serverID: serverID, ackSuccess: true}
}

func (a *stubAgent) Send(msg *pb.HubMessage) error {
	a.mu.Lock()
	if a.sendErr != nil {
		err := a.sendErr
		a.mu.Unlock()
		return err
	}
	a.sent = append(a.sent, msg)
	silent, success, ackErr := a.silent, a.ackSuccess, a.ackError
	a.mu.Unlock()

	if open := msg.GetTerminalOpenRequest(); open != nil && !silent {
		a.pending.Deliver(a.serverID, open.SessionId, &pb.TerminalOpenAck{
			SessionId: open.SessionId,
			Success:   success,
			Error:     ackErr,
		})
	}
	return nil
}

func (a *stubAgent) Recv() (*pb.AgentMessage, error)   { return nil, io.EOF }
func (a *stubAgent) Context() context.Context          { return context.Background() }
func (a *stubAgent) SendMsg(any) error                 { return nil }
func (a *stubAgent) RecvMsg(any) error                 { return nil }
func (a *stubAgent) SetHeader(metadata.MD) error       { return nil }
func (a *stubAgent) SendHeader(metadata.MD) error      { return nil }
func (a *stubAgent) SetTrailer(metadata.MD)            {}
func (a *stubAgent) SendAndClose(*pb.HubMessage) error { return nil }

func (a *stubAgent) messages() []*pb.HubMessage {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*pb.HubMessage, len(a.sent))
	copy(out, a.sent)
	return out
}

// waitForMessage polls the recorded messages until match succeeds.
func (a *stubAgent) waitForMessage(t *testing.T, what string, match func(*pb.HubMessage) bool) *pb.HubMessage {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		for _, msg := range a.messages() {
			if match(msg) {
				return msg
			}
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("agent never received %s", what)
	return nil
}

func (a *stubAgent) setSilent(silent bool) {
	a.mu.Lock()
	a.silent = silent
	a.mu.Unlock()
}

func (a *stubAgent) setAck(success bool, ackErr string) {
	a.mu.Lock()
	a.ackSuccess, a.ackError = success, ackErr
	a.mu.Unlock()
}

// ---------------------------------------------------------------------------
// fake ssh.Channel
// ---------------------------------------------------------------------------

type recordedRequest struct {
	name      string
	wantReply bool
	payload   []byte
}

// lockedBuffer is a race-safe bytes.Buffer.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Read(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeChannel is an in-memory ssh.Channel: the bridge writes agent output to
// it, reads client input from a pipe the test drives, and records the SSH
// requests it sends (notably exit-status).
type fakeChannel struct {
	mu     sync.Mutex
	out    bytes.Buffer
	reqs   []recordedRequest
	closed bool

	inR    *io.PipeReader
	inW    *io.PipeWriter
	errBuf *lockedBuffer
}

func newFakeChannel() *fakeChannel {
	r, w := io.Pipe()
	return &fakeChannel{inR: r, inW: w, errBuf: &lockedBuffer{}}
}

func (c *fakeChannel) Read(p []byte) (int, error) { return c.inR.Read(p) }

func (c *fakeChannel) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	return c.out.Write(p)
}

func (c *fakeChannel) Close() error {
	c.mu.Lock()
	already := c.closed
	c.closed = true
	c.mu.Unlock()
	if already {
		return io.ErrClosedPipe
	}
	_ = c.inW.Close()
	_ = c.inR.Close()
	return nil
}

func (c *fakeChannel) CloseWrite() error { return nil }

func (c *fakeChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false, io.ErrClosedPipe
	}
	c.reqs = append(c.reqs, recordedRequest{name: name, wantReply: wantReply, payload: payload})
	return true, nil
}

func (c *fakeChannel) Stderr() io.ReadWriter { return c.errBuf }

// clientWrite feeds bytes to the bridge as if typed by the SSH client.
func (c *fakeChannel) clientWrite(t *testing.T, data string) {
	t.Helper()
	if _, err := c.inW.Write([]byte(data)); err != nil {
		t.Fatalf("write client input: %v", err)
	}
}

func (c *fakeChannel) output() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.String()
}

func (c *fakeChannel) requests() []recordedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]recordedRequest, len(c.reqs))
	copy(out, c.reqs)
	return out
}

func (c *fakeChannel) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *fakeChannel) exitStatus(t *testing.T) uint32 {
	t.Helper()
	for _, req := range c.requests() {
		if req.name != "exit-status" {
			continue
		}
		var payload struct{ Status uint32 }
		if err := ssh.Unmarshal(req.payload, &payload); err != nil {
			t.Fatalf("unmarshal exit-status payload: %v", err)
		}
		return payload.Status
	}
	t.Fatalf("channel never received an exit-status request (got %v)", c.requests())
	return 0
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

type fixture struct {
	t         *testing.T
	store     *store.Store
	ca        *userca.UserCA
	hostKey   ssh.Signer
	terminals *grpcserver.TerminalSessions
	pending   *grpcserver.PendingRequests
	connMgr   *connmgr.ConnManager
	agent     *stubAgent
	srv       *Server
	startErr  chan error
	gone      chan struct{}
}

func newFixture(t *testing.T, mutate func(*Config)) *fixture {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf(fmtStoreNew, err)
	}
	t.Cleanup(func() { st.Close() })

	ca, err := userca.InitUserCA(st, testStorageKey)
	if err != nil {
		t.Fatalf(fmtInitUserCA, err)
	}
	hostKey, err := userca.InitHostKey(st, testStorageKey)
	if err != nil {
		t.Fatalf(fmtInitHostKey, err)
	}

	if err := st.CreateUser(&model.User{
		ID: testUserID, Username: testUsername, Email: "alice@example.test",
		PasswordHash: "x", Role: model.RoleAdmin,
	}); err != nil {
		t.Fatalf(fmtCreateUser, err)
	}
	if err := st.CreateServer(&model.Server{
		ID: testServerID, Name: testServerName, Status: "online", Labels: "{}",
	}); err != nil {
		t.Fatalf(fmtCreateServer, err)
	}

	f := &fixture{
		t:         t,
		store:     st,
		ca:        ca,
		hostKey:   hostKey,
		terminals: grpcserver.NewTerminalSessions(),
		pending:   grpcserver.NewPendingRequests(),
		connMgr:   connmgr.New(),
		startErr:  make(chan error, 1),
	}
	f.agent = newStubAgent(f.pending, testServerID)

	cfg := Config{
		Store:     st,
		UserCA:    ca,
		HostKey:   hostKey,
		Terminals: f.terminals,
		ConnMgr:   f.connMgr,
		Pending:   f.pending,
		Addr:      "127.0.0.1:0",
		Enabled:   true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	f.srv = New(cfg)
	return f
}

// connectAgent marks the target server as having a live agent stream.
func (f *fixture) connectAgent() {
	f.connMgr.Register(testServerID, f.agent)
}

// start runs the gateway listener and waits for it to bind.
func (f *fixture) start() {
	f.t.Helper()
	go func() { f.startErr <- f.srv.Start() }()
	select {
	case <-f.srv.ready:
	case <-time.After(waitTimeout):
		f.t.Fatal("gateway did not become ready")
	}
	if f.srv.Addr() == "" {
		f.t.Fatalf("gateway is not listening: %v", <-f.startErr)
	}
	f.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		defer cancel()
		if err := f.srv.Stop(ctx); err != nil {
			f.t.Errorf("Stop() error: %v", err)
		}
	})
}

func (f *fixture) startBridge(ch ssh.Channel, mutate func(*bridgeParams)) (<-chan struct{}, chan windowSize) {
	win := make(chan windowSize, 4)
	f.gone = make(chan struct{})
	p := bridgeParams{
		serverID:      testServerID,
		serverName:    testServerName,
		userID:        testUserID,
		username:      testUsername,
		executionUser: "",
		remoteIP:      "127.0.0.1",
		cols:          80,
		rows:          24,
		win:           win,
		clientGone:    f.gone,
	}
	if mutate != nil {
		mutate(&p)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.srv.bridge(ch, p)
	}()
	return done, win
}

// disconnect simulates the SSH client going away: the session channel is
// finished and the transport is torn down.
func (f *fixture) disconnect(ch *fakeChannel) {
	close(f.gone)
	_ = ch.Close()
}

// openSessionID returns the session ID from the TerminalOpenRequest the bridge
// sent to the agent.
func (f *fixture) openSessionID() string {
	f.t.Helper()
	msg := f.agent.waitForMessage(f.t, "TerminalOpenRequest", func(m *pb.HubMessage) bool {
		return m.GetTerminalOpenRequest() != nil
	})
	return msg.GetTerminalOpenRequest().SessionId
}

func (f *fixture) auditEntries(action string) []model.AuditEntry {
	f.t.Helper()
	entries, _, err := f.store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 100})
	if err != nil {
		f.t.Fatalf("ListAuditLogs(%s) error: %v", action, err)
	}
	return entries
}

func (f *fixture) waitForAudit(action string) model.AuditEntry {
	f.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if entries := f.auditEntries(action); len(entries) > 0 {
			return entries[0]
		}
		time.Sleep(pollInterval)
	}
	f.t.Fatalf("audit entry %q never appeared", action)
	return model.AuditEntry{}
}

// ---------------------------------------------------------------------------
// generic waiters
// ---------------------------------------------------------------------------

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func waitForDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(waitTimeout):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// assertNoGoroutineLeak waits for the goroutine count to settle back to base.
func assertNoGoroutineLeak(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= base {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("goroutine leak: started at %d, now %d", base, runtime.NumGoroutine())
}

// ---------------------------------------------------------------------------
// T013 — bridge tests
// ---------------------------------------------------------------------------

// TestBridgeOpenRequestCarriesExecutionUser pins the open handshake: the bridge
// registers the session, sends TerminalOpenRequest with the PTY geometry and
// the resolved execution user, and waits for the ack.
func TestBridgeOpenRequestCarriesExecutionUser(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, func(p *bridgeParams) {
		p.executionUser = "ldapalice"
		p.cols, p.rows = 132, 43
	})

	msg := f.agent.waitForMessage(t, "TerminalOpenRequest", func(m *pb.HubMessage) bool {
		return m.GetTerminalOpenRequest() != nil
	})
	open := msg.GetTerminalOpenRequest()
	if open.RunAsUser != "ldapalice" {
		t.Errorf("RunAsUser = %q, want %q", open.RunAsUser, "ldapalice")
	}
	if open.Cols != 132 || open.Rows != 43 {
		t.Errorf("geometry = %dx%d, want 132x43", open.Cols, open.Rows)
	}

	f.disconnect(ch)
	waitForDone(t, done, "bridge teardown")
}

// TestBridgeAgentDataReachesClient covers the agent→client direction.
func TestBridgeAgentDataReachesClient(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()

	waitFor(t, "session attach", func() bool {
		info, ok := f.terminals.Get(testServerID, sessionID)
		return ok && !info.Closed
	})
	if !f.terminals.DeliverData(testServerID, sessionID, []byte("hello from agent")) {
		t.Fatal("DeliverData() dropped the payload")
	}
	waitFor(t, "agent output on the ssh channel", func() bool {
		return strings.Contains(ch.output(), "hello from agent")
	})

	f.disconnect(ch)
	waitForDone(t, done, "bridge teardown")
}

// TestBridgeClientInputReachesAgent covers the client→agent direction.
func TestBridgeClientInputReachesAgent(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()

	ch.clientWrite(t, "whoami\r")
	msg := f.agent.waitForMessage(t, "TerminalInput", func(m *pb.HubMessage) bool {
		return m.GetTerminalInput() != nil
	})
	input := msg.GetTerminalInput()
	if input.SessionId != sessionID {
		t.Errorf("TerminalInput.SessionId = %q, want %q", input.SessionId, sessionID)
	}
	if string(input.Data) != "whoami\r" {
		t.Errorf("TerminalInput.Data = %q, want %q", input.Data, "whoami\r")
	}

	f.disconnect(ch)
	waitForDone(t, done, "bridge teardown")
}

// TestBridgeWindowChangeBecomesResize covers FR-008 resize relaying.
func TestBridgeWindowChangeBecomesResize(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, win := f.startBridge(ch, nil)
	sessionID := f.openSessionID()

	win <- windowSize{cols: 200, rows: 60}
	msg := f.agent.waitForMessage(t, "TerminalResize", func(m *pb.HubMessage) bool {
		return m.GetTerminalResize() != nil
	})
	resize := msg.GetTerminalResize()
	if resize.SessionId != sessionID || resize.Cols != 200 || resize.Rows != 60 {
		t.Errorf("TerminalResize = %+v, want session %q 200x60", resize, sessionID)
	}

	f.disconnect(ch)
	waitForDone(t, done, "bridge teardown")
}

// TestBridgeAgentExitSendsExitStatus asserts a clean remote exit becomes an SSH
// exit-status request plus a channel close, and is audited.
func TestBridgeAgentExitSendsExitStatus(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitFor(t, "session attach", func() bool {
		_, ok := f.terminals.Get(testServerID, sessionID)
		return ok
	})

	if !f.terminals.End(testServerID, sessionID, 3, "") {
		t.Fatal("End() did not close the terminal session")
	}
	waitForDone(t, done, "bridge teardown after agent exit")

	if got := ch.exitStatus(t); got != 3 {
		t.Errorf("exit-status = %d, want 3", got)
	}
	if !ch.isClosed() {
		t.Error("ssh channel was not closed after the remote shell exited")
	}
	entry := f.waitForAudit(model.AuditSSHSessionClosed)
	if entry.Target == nil || *entry.Target != testServerID {
		t.Errorf("audit target = %v, want %q", entry.Target, testServerID)
	}
}

// TestBridgeAgentDisconnectClosesClient pins FR-011: an agent that drops
// mid-session must produce an explicit client-visible close, never a freeze.
func TestBridgeAgentDisconnectClosesClient(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitFor(t, "session attach", func() bool {
		_, ok := f.terminals.Get(testServerID, sessionID)
		return ok
	})

	// This is exactly what grpcserver.Handler does when an agent stream dies.
	f.terminals.EndAll(testServerID, -1, "agent disconnected")
	waitForDone(t, done, "bridge teardown after agent disconnect")

	if !ch.isClosed() {
		t.Error("ssh channel was not closed after the agent disconnected")
	}
	if got := ch.errBuf.String(); !strings.Contains(got, "agent disconnected") {
		t.Errorf("stderr = %q, want it to explain the agent disconnect", got)
	}
	if got := ch.exitStatus(t); got == 0 {
		t.Error("exit-status = 0, want a non-zero status for an aborted session")
	}
}

// TestBridgeDrainsContinuouslyAt256Boundary pins the drain requirement:
// TerminalSessions.DeliverData drops on a full 256-slot buffer, so the relay
// must never stall. The warm-up event proves the pump is running and the
// buffer is empty, after which exactly cap(256) deliveries must all be
// accepted and all must reach the channel in order.
func TestBridgeDrainsContinuouslyAt256Boundary(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()

	if !f.terminals.DeliverData(testServerID, sessionID, []byte("warmup\n")) {
		t.Fatal("warm-up DeliverData() was dropped")
	}
	waitFor(t, "warm-up byte to be drained", func() bool {
		return strings.Contains(ch.output(), "warmup\n")
	})

	const burst = 256 // == cap of the terminal event channel
	var want strings.Builder
	want.WriteString("warmup\n")
	for i := 0; i < burst; i++ {
		payload := fmt.Sprintf("line-%03d\n", i)
		if !f.terminals.DeliverData(testServerID, sessionID, []byte(payload)) {
			t.Fatalf("DeliverData() dropped payload %d: the relay stopped draining", i)
		}
		want.WriteString(payload)
	}
	waitFor(t, "the full burst to reach the ssh channel", func() bool {
		return len(ch.output()) >= want.Len()
	})
	if got := ch.output(); got != want.String() {
		t.Errorf("relayed output mismatch: got %d bytes, want %d bytes (ordering or loss)", len(got), want.Len())
	}

	f.disconnect(ch)
	waitForDone(t, done, "bridge teardown")
}

// TestBridgeOpenAckFailureRefusesCleanly asserts a rejected open is reported to
// the client and leaves no session registered.
func TestBridgeOpenAckFailureRefusesCleanly(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.agent.setAck(false, "pty allocation failed")

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitForDone(t, done, "bridge refusal")

	if got := ch.errBuf.String(); !strings.Contains(got, "pty allocation failed") {
		t.Errorf("stderr = %q, want the agent's reason", got)
	}
	if _, ok := f.terminals.Get(testServerID, sessionID); ok {
		t.Error("terminal session was left registered after a failed open")
	}
	entry := f.waitForAudit(model.AuditSSHSessionRefused)
	if entry.Outcome != model.AuditOutcomeFailure {
		t.Errorf("audit outcome = %q, want %q", entry.Outcome, model.AuditOutcomeFailure)
	}
	if len(f.auditEntries(model.AuditSSHSessionOpened)) != 0 {
		t.Error("a failed open must not be audited as ssh.session_opened")
	}
}

// TestBridgeOpenTimeoutRefusesCleanly covers an agent that never acks.
func TestBridgeOpenTimeoutRefusesCleanly(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.OpenTimeout = 100 * time.Millisecond })
	f.connectAgent()
	f.agent.setSilent(true)

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitForDone(t, done, "bridge open timeout")

	if got := ch.errBuf.String(); !strings.Contains(got, "timed out") {
		t.Errorf("stderr = %q, want a timeout explanation", got)
	}
	if _, ok := f.terminals.Get(testServerID, sessionID); ok {
		t.Error("terminal session was left registered after an open timeout")
	}
	f.waitForAudit(model.AuditSSHSessionRefused)
}

// TestBridgeClientDisconnectTearsDownSession asserts the hub-initiated path:
// the session is removed and the agent is told to close the terminal.
func TestBridgeClientDisconnectTearsDownSession(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitFor(t, "session attach", func() bool {
		_, ok := f.terminals.Get(testServerID, sessionID)
		return ok
	})

	f.disconnect(ch)
	waitForDone(t, done, "bridge teardown after client disconnect")

	f.agent.waitForMessage(t, "TerminalClose", func(m *pb.HubMessage) bool {
		return m.GetTerminalClose() != nil && m.GetTerminalClose().SessionId == sessionID
	})
	if _, ok := f.terminals.Get(testServerID, sessionID); ok {
		t.Error("terminal session was left registered after the client disconnected")
	}
	f.waitForAudit(model.AuditSSHSessionClosed)
}

// TestBridgeAgentExitSuppressesRedundantClose asserts the agent-initiated path
// does not send a redundant TerminalClose.
func TestBridgeAgentExitSuppressesRedundantClose(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitFor(t, "session attach", func() bool {
		_, ok := f.terminals.Get(testServerID, sessionID)
		return ok
	})

	f.terminals.End(testServerID, sessionID, 0, "")
	waitForDone(t, done, "bridge teardown after agent exit")

	for _, msg := range f.agent.messages() {
		if msg.GetTerminalClose() != nil {
			t.Error("TerminalClose was sent even though the agent already reported the exit")
		}
	}
}

// TestBridgeNoGoroutineLeak asserts a full session leaves nothing running.
func TestBridgeNoGoroutineLeak(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	base := runtime.NumGoroutine()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitFor(t, "session attach", func() bool {
		_, ok := f.terminals.Get(testServerID, sessionID)
		return ok
	})
	ch.clientWrite(t, "echo hi\r")
	f.agent.waitForMessage(t, "TerminalInput", func(m *pb.HubMessage) bool {
		return m.GetTerminalInput() != nil
	})
	f.terminals.End(testServerID, sessionID, 0, "")
	waitForDone(t, done, "bridge teardown")

	assertNoGoroutineLeak(t, base)
}

// TestBridgeAgentSendFailureRefuses covers a stream that breaks between the
// liveness check and the open request.
func TestBridgeAgentSendFailureRefuses(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.agent.mu.Lock()
	f.agent.sendErr = errors.New("stream closed")
	f.agent.mu.Unlock()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	waitForDone(t, done, "bridge refusal")

	if got := ch.errBuf.String(); !strings.Contains(got, "veyport:") {
		t.Errorf("stderr = %q, want a veyport-prefixed explanation", got)
	}
	f.waitForAudit(model.AuditSSHSessionRefused)
}
