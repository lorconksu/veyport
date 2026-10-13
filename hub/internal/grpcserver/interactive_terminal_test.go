package grpcserver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

type orderedTerminalStream struct {
	pb.AgentService_ConnectServer
	messages    chan *pb.HubMessage
	openEntered chan struct{}
	releaseOpen chan struct{}
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
func TestInteractivePolicyDoesNotHoldNetworkAndOrdersCloseAfterOpen(t *testing.T) {
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
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(stream.releaseOpen)
		t.Fatal("policy mutation waited for network I/O")
	}
	info, _ := ts.Get("node", "shell")
	if !info.Closed {
		t.Fatal("covered open was not invalidated")
	}
	close(stream.releaseOpen)
	if err := <-sent; err != nil {
		t.Fatal(err)
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
