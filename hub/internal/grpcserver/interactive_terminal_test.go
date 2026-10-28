package grpcserver

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestConcurrentInteractiveRegistrationAndRevocation(t *testing.T) {
	st, cm, ts, _ := interactiveFixture(t)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			ts.EndByUser("actor", 1, "revoked")
			runtime.Gosched()
		}
	}()
	for i := range 1000 {
		id := fmt.Sprint(i)
		if _, _, err := ts.RegisterInteractive(st, cm, "node", id, "actor", func() (string, error) { return "", nil }, WithCredentialGeneration(0, false)); err != nil {
			t.Fatal(err)
		}
		ts.mu.Lock()
		watchDone := ts.sessions[makeKey("node", id)].credentialWatchDone
		ts.mu.Unlock()
		ts.Remove("node", id)
		select {
		case <-watchDone:
		case <-time.After(time.Second):
			t.Fatalf("credential watcher leaked for registration %s", id)
		}
	}
	close(stop)
	<-done
}

func TestForcedInteractiveEndClosesCapturedAgentWithoutAttachedTransport(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []RegisterOption
		end  func(*TerminalSessions) bool
	}{
		{name: "one", end: func(ts *TerminalSessions) bool { return ts.EndOne("node", "shell", 1, "revoked") }},
		{name: "user", end: func(ts *TerminalSessions) bool { return ts.EndByUser("actor", 1, "revoked") == 1 }},
		{name: "owning session", opts: []RegisterOption{WithSessionID("owning")}, end: func(ts *TerminalSessions) bool { return ts.EndBySession("owning", 1, "revoked") == 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, cm, ts, stream := interactiveFixture(t)
			if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", func() (string, error) { return "", nil }, tc.opts...); err != nil {
				t.Fatal(err)
			}
			defer ts.Remove("node", "shell")
			if !tc.end(ts) {
				t.Fatal("forced end did not close registration")
			}
			select {
			case msg := <-stream.messages:
				if msg.GetTerminalClose() == nil {
					t.Fatalf("expected TerminalClose, got %T", msg.Payload)
				}
			case <-time.After(time.Second):
				t.Fatal("forced end left the captured agent shell running")
			}
		})
	}
}

type orderedTerminalStream struct {
	pb.AgentService_ConnectServer
	messages    chan *pb.HubMessage
	openEntered chan struct{}
	releaseOpen chan struct{}
}

type contextBlockedTerminalStream struct {
	pb.AgentService_ConnectServer
	ctx     context.Context
	entered chan struct{}
	once    sync.Once
}

func (s *contextBlockedTerminalStream) Context() context.Context { return s.ctx }
func (s *contextBlockedTerminalStream) Send(msg *pb.HubMessage) error {
	if msg.GetTerminalOpenRequest() != nil {
		s.once.Do(func() { close(s.entered) })
	}
	<-s.ctx.Done()
	return s.ctx.Err()
}

func (s *orderedTerminalStream) Send(m *pb.HubMessage) error {
	s.messages <- m
	if m.GetTerminalOpenRequest() != nil && s.releaseOpen != nil {
		close(s.openEntered)
		<-s.releaseOpen
	}
	return nil
}
func (s *orderedTerminalStream) Context() context.Context { return context.Background() }
func interactiveFixture(t *testing.T) (*store.Store, *connmgr.ConnManager, *TerminalSessions, *orderedTerminalStream) {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cm := connmgr.New()
	ts := NewTerminalSessions()
	stream := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}
	cm.Register("node", stream)
	t.Cleanup(func() { cm.Unregister("node") })
	return st, cm, ts, stream
}
func interactiveValidate(st *store.Store) func() (string, error) {
	return func() (string, error) { return "", authorization.New(st).GuardInteractive("actor", "node") }
}
func terminalOpen() *pb.HubMessage {
	return &pb.HubMessage{Payload: &pb.HubMessage_TerminalOpenRequest{TerminalOpenRequest: &pb.TerminalOpenRequest{SessionId: "shell"}}}
}

func TestTerminalSendTimeoutReturnsBeforeDurableDisconnectBookkeeping(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "timeout-cycle.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	cm, ts := connmgr.New(), NewTerminalSessions()
	streamCtx, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()
	stream := &contextBlockedTerminalStream{ctx: streamCtx, entered: make(chan struct{})}
	conn := cm.Register("node", stream)
	if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", func() (string, error) { return "", nil }); err != nil {
		t.Fatal(err)
	}
	h := &Handler{store: st, connMgr: cm, terminals: ts}
	disconnected := make(chan struct{})
	go func() {
		<-conn.Done()
		h.onAgentDisconnected("node", stream)
		// gRPC cancels Stream.Context only after Connect and its defer return.
		cancelStream()
		close(disconnected)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- ts.SendInteractive(ctx, "node", "shell", terminalOpen()) }()
	select {
	case <-stream.entered:
	case <-time.After(time.Second):
		t.Fatal("terminal send did not reach the transport")
	}
	select {
	case <-result:
	case <-time.After(time.Second):
		cancelStream()
		t.Fatal("terminal send remained blocked behind durable disconnect bookkeeping")
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("Connect cleanup did not return to cancel the transport")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		server, err := st.GetServerByID("node")
		if err == nil && server.Status == "offline" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("asynchronous disconnect bookkeeping did not finish")
}
func waitTerminalMessage(t *testing.T, s *orderedTerminalStream) *pb.HubMessage {
	t.Helper()
	select {
	case m := <-s.messages:
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("missing ordered terminal message")
		return nil
	}
}
func TestInteractiveRegistrationSerializesPolicyInvalidation(t *testing.T) {
	st, cm, ts, stream := interactiveFixture(t)
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	registered := make(chan error, 1)
	go func() {
		_, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", func() (string, error) { once.Do(func() { close(entered) }); <-resume; return interactiveValidate(st)() }, WithKind(TerminalKindSSH))
		registered <- err
	}()
	<-entered
	changed := make(chan error, 1)
	go func() { changed <- st.RequirePolicyRecovery() }()
	close(resume)
	if err := <-registered; err != nil {
		t.Fatal(err)
	}
	if err := <-changed; err != nil {
		t.Fatal(err)
	}
	info, ok := ts.Get("node", "shell")
	if !ok || !info.Closed {
		t.Fatal("policy mutation missed the overlapping registration")
	}
	if err := ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()); !errors.Is(err, ErrInteractiveSessionClosed) {
		t.Fatalf("closed shell open: %v", err)
	}
	if m := waitTerminalMessage(t, stream); m.GetTerminalClose() == nil {
		t.Fatal("expected close only, no open")
	}
}
func TestInteractivePolicyRevocationOrdersAfterInflightSend(t *testing.T) {
	st, cm, ts, stream := interactiveFixture(t)
	stream.openEntered = make(chan struct{})
	stream.releaseOpen = make(chan struct{})
	_, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", interactiveValidate(st))
	if err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() { sent <- ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()) }()
	<-stream.openEntered
	changed := make(chan error, 1)
	go func() { changed <- st.RequirePolicyRecovery() }()
	select {
	case err := <-changed:
		t.Fatalf("policy revocation crossed an in-flight send: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	info, _ := ts.Get("node", "shell")
	if info.Closed {
		t.Fatal("terminal was marked revoked before the earlier send completed")
	}
	close(stream.releaseOpen)
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if err := <-changed; err != nil {
		t.Fatal(err)
	}
	info, _ = ts.Get("node", "shell")
	if !info.Closed {
		t.Fatal("policy revocation did not close the terminal after the send")
	}
	if waitTerminalMessage(t, stream).GetTerminalOpenRequest() == nil {
		t.Fatal("first message must be the already admitted open")
	}
	if waitTerminalMessage(t, stream).GetTerminalClose() == nil {
		t.Fatal("close must follow open")
	}
	if err := ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()); err == nil {
		t.Fatal("open after shutdown accepted")
	}
	select {
	case m := <-stream.messages:
		t.Fatalf("unexpected message after close: %T", m.Payload)
	default:
	}
}

func TestInteractiveExternalRevocationCannotCommitAcrossSend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	st, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	writer, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := st.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", Role: model.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	cm, ts := connmgr.New(), NewTerminalSessions()
	stream := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10), openEntered: make(chan struct{}), releaseOpen: make(chan struct{})}
	cm.Register("node", stream)
	defer cm.Unregister("node")
	if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", interactiveValidate(st)); err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() { sent <- ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()) }()
	<-stream.openEntered
	changed := make(chan error, 1)
	go func() { changed <- writer.RequirePolicyRecovery() }()
	select {
	case err := <-changed:
		t.Fatalf("external revocation committed before the admitted send: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(stream.releaseOpen)
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if err := <-changed; err != nil {
		t.Fatal(err)
	}
	if err := ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()); err == nil {
		t.Fatal("send after external revocation succeeded")
	}
}

func TestInteractiveForcedEndWaitsForInflightSend(t *testing.T) {
	st, cm, ts, stream := interactiveFixture(t)
	stream.openEntered, stream.releaseOpen = make(chan struct{}), make(chan struct{})
	if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", interactiveValidate(st)); err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() { sent <- ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()) }()
	<-stream.openEntered
	ended := make(chan bool, 1)
	go func() { ended <- ts.EndOne("node", "shell", 1, "revoked") }()
	select {
	case <-ended:
		t.Fatal("forced revocation crossed an in-flight send")
	case <-time.After(100 * time.Millisecond):
	}
	close(stream.releaseOpen)
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if !<-ended {
		t.Fatal("forced revocation did not close the terminal")
	}
}
func TestInteractiveReconnectCannotRedirectOldShell(t *testing.T) {
	st, cm, ts, old := interactiveFixture(t)
	_, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", interactiveValidate(st))
	if err != nil {
		t.Fatal(err)
	}
	replacement := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}
	cm.Register("node", replacement)
	if err := ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()); err == nil {
		t.Fatal("old registration reached replacement")
	}
	ts.CloseInteractive("node", "shell")
	ts.Remove("node", "shell")
	select {
	case m := <-replacement.messages:
		t.Fatalf("old open/cleanup redirected: %T", m.Payload)
	default:
	}
	select {
	case m := <-old.messages:
		t.Fatalf("closed connection received request: %T", m.Payload)
	default:
	}
}

func TestIdleInteractiveShellClosesOnConnectionReplacement(t *testing.T) {
	st, cm, ts, old := interactiveFixture(t)
	if err := st.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", Role: model.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", interactiveValidate(st), WithCredentialGeneration(0, false)); err != nil {
		t.Fatal(err)
	}
	ts.mu.Lock()
	shell := ts.sessions[makeKey("node", "shell")]
	ts.mu.Unlock()
	replacement := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}
	cm.Register("node", replacement)
	select {
	case <-shell.credentialWatchDone:
	case <-time.After(2 * time.Second):
		t.Fatal("idle terminal survived captured connection replacement")
	}
	info, _ := ts.Get("node", "shell")
	if !info.Closed || ts.DeliverData("node", "shell", []byte("stale private output")) {
		t.Fatal("replaced connection retained a live terminal output gate")
	}
	select {
	case msg := <-replacement.messages:
		t.Fatalf("old terminal cleanup reached replacement connection: %T", msg.Payload)
	default:
	}
	select {
	case msg := <-old.messages:
		t.Fatalf("closed old connection received cleanup: %T", msg.Payload)
	default:
	}
}
func TestInteractiveCapturedCleanupCannotCloseReplacementRegistration(t *testing.T) {
	st, cm, ts, old := interactiveFixture(t)
	_, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", interactiveValidate(st))
	if err != nil {
		t.Fatal(err)
	}
	closeOld, removed := ts.RemoveUnattachedWithClose("node", "shell")
	if !removed || closeOld == nil {
		t.Fatal("exact unattached cleanup capture failed")
	}
	replacement := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}
	cm.Register("node", replacement)
	_, _, err = ts.RegisterInteractive(st, cm, "node", "shell", "actor", interactiveValidate(st))
	if err != nil {
		t.Fatal(err)
	}
	closeOld()
	if err := ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()); err != nil {
		t.Fatal(err)
	}
	if waitTerminalMessage(t, replacement).GetTerminalOpenRequest() == nil {
		t.Fatal("replacement lost its open")
	}
	info, _ := ts.Get("node", "shell")
	if info.Closed {
		t.Fatal("old cleanup closed replacement registry object")
	}
	select {
	case m := <-old.messages:
		t.Fatalf("closed old connection received request: %T", m.Payload)
	default:
	}
}
func TestInteractiveStandardSuccessAndChangedIdentityRejection(t *testing.T) {
	st, cm, ts, stream := interactiveFixture(t)
	executionUser := "first"
	_, actual, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", func() (string, error) { return executionUser, nil })
	if err != nil || actual != "first" {
		t.Fatalf("register: %q %v", actual, err)
	}
	if err := ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()); err != nil {
		t.Fatal(err)
	}
	if waitTerminalMessage(t, stream).GetTerminalOpenRequest() == nil {
		t.Fatal("standard open missing")
	}
	executionUser = "changed"
	if err := ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()); !errors.Is(err, ErrInteractiveSessionClosed) {
		t.Fatalf("changed identity allowed: %v", err)
	}
	if waitTerminalMessage(t, stream).GetTerminalClose() == nil {
		t.Fatal("changed identity did not close shell")
	}
}

func TestInteractiveAdmissionRefusesRecoveryAndUnavailableCapacity(t *testing.T) {
	t.Run("recovery", func(t *testing.T) {
		st, cm, ts, stream := interactiveFixture(t)
		if err := st.RequirePolicyRecovery(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", interactiveValidate(st)); !errors.Is(err, authorization.ErrRecovery) {
			t.Fatalf("recovery admission: %v", err)
		}
		if _, ok := ts.Get("node", "shell"); ok {
			t.Fatal("rejected admission left registry entry")
		}
		select {
		case m := <-stream.messages:
			t.Fatalf("rejected admission sent %T", m.Payload)
		default:
		}
	})
	t.Run("capacity", func(t *testing.T) {
		st, cm, ts, _ := interactiveFixture(t)
		for _, id := range []string{"1", "2", "3", "4", "5", "6", "7", "8"} {
			if _, ok := ts.Register("node", id, "actor", ""); !ok {
				t.Fatal("fixture reservation failed")
			}
		}
		if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", interactiveValidate(st)); !errors.Is(err, ErrInteractiveRegistration) {
			t.Fatalf("capacity admission: %v", err)
		}
	})
	t.Run("disconnected", func(t *testing.T) {
		st, cm, ts, _ := interactiveFixture(t)
		cm.Unregister("node")
		if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", interactiveValidate(st)); !errors.Is(err, ErrInteractiveAgentNotConnected) {
			t.Fatalf("disconnected admission: %v", err)
		}
	})
}

func TestInteractiveFinalGuardRejectsQueuedOpenAfterGrantRevocation(t *testing.T) {
	st, cm, ts, stream := interactiveFixture(t)
	var revoked atomic.Bool
	_, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", func() (string, error) {
		if revoked.Load() {
			return "", errors.New("local fixture revoked grant")
		}
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	conn := cm.GetConn("node")
	conn.SendMu.Lock()
	result := make(chan error, 1)
	go func() { result <- ts.SendInteractive(context.Background(), "node", "shell", terminalOpen()) }()
	revoked.Store(true)
	conn.SendMu.Unlock()
	if err := <-result; err == nil {
		t.Fatal("queued open bypassed the final live grant check")
	}
	if m := waitTerminalMessage(t, stream); m.GetTerminalClose() == nil {
		t.Fatalf("expected close without an open, got %T", m.Payload)
	}
	info, _ := ts.Get("node", "shell")
	if !info.Closed {
		t.Fatal("grant revocation left registration live")
	}
}
