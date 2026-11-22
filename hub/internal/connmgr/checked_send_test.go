package connmgr

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestSendToConnectionCheckedRejectsWithoutSending(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	conn := cm.Register("node", stream)
	denied := errors.New("local fixture authorization revoked")
	if err := cm.SendToConnectionChecked(context.Background(), conn, &pb.HubMessage{}, func() error { return denied }); !errors.Is(err, denied) {
		t.Fatalf("final guard: %v", err)
	}
	if len(stream.sent) != 0 {
		t.Fatal("denied message reached stream")
	}
	if err := cm.SendToConnectionChecked(context.Background(), nil, &pb.HubMessage{}, nil); err == nil {
		t.Fatal("missing connection accepted")
	}
	replacement := &mockStream{}
	cm.Register("node", replacement)
	if err := cm.SendToConnectionChecked(context.Background(), conn, &pb.HubMessage{}, nil); err == nil {
		t.Fatal("disconnected generation accepted")
	}
	if len(replacement.sent) != 0 {
		t.Fatal("checked send was redirected")
	}
}
func TestSendToConnectionCheckedPreservesSuccessfulOrder(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	conn := cm.Register("node", stream)
	var checked atomic.Bool
	msg := &pb.HubMessage{}
	if err := cm.SendToConnectionChecked(context.Background(), conn, msg, func() error { checked.Store(true); return nil }); err != nil {
		t.Fatal(err)
	}
	if !checked.Load() || len(stream.sent) != 1 || stream.sent[0] != msg {
		t.Fatal("successful final check/send missing")
	}
	if err := cm.SendToAgentContext(context.Background(), "node", msg); err != nil {
		t.Fatal(err)
	}
}

type blockedCheckedStream struct {
	*mockStream
	entered, release, finished chan struct{}
}

type contextBlockedStream struct {
	*mockStream
	ctx     context.Context
	entered chan struct{}
}

func (s *contextBlockedStream) Context() context.Context { return s.ctx }
func (s *contextBlockedStream) Send(*pb.HubMessage) error {
	close(s.entered)
	<-s.ctx.Done()
	return s.ctx.Err()
}

func TestCancelledSendLetsDisconnectRetireGeneration(t *testing.T) {
	cm := New()
	streamCtx, finishHandler := context.WithCancel(context.Background())
	stream := &contextBlockedStream{mockStream: &mockStream{}, ctx: streamCtx, entered: make(chan struct{})}
	conn := cm.Register("node", stream)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- cm.SendToConnectionChecked(ctx, conn, &pb.HubMessage{}, nil) }()
	<-stream.entered
	disconnected := make(chan struct{})
	go func() {
		<-conn.Done()
		cm.UnregisterIfCurrent("node", stream)
		finishHandler()
		close(disconnected)
	}()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled send: %v", err)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("disconnect cleanup waited on the blocked send generation")
	}
}

func (s *blockedCheckedStream) Send(*pb.HubMessage) error {
	close(s.entered)
	<-s.release
	close(s.finished)
	return nil
}
func TestSendToConnectionCheckedCancellationClosesExactConnection(t *testing.T) {
	cm := New()
	stream := &blockedCheckedStream{mockStream: &mockStream{}, entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	conn := cm.Register("node", stream)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- cm.SendToConnectionChecked(ctx, conn, &pb.HubMessage{}, nil) }()
	<-stream.entered
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked send did not cancel")
	}
	select {
	case <-conn.Done():
	default:
		t.Fatal("cancelled control connection remained live")
	}
	close(stream.release)
	<-stream.finished
}

func TestGuardedSendAndConnectionReplacementHaveOneOrder(t *testing.T) {
	cm := New()
	stream := &blockedCheckedStream{mockStream: &mockStream{}, entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	conn := cm.Register("node", stream)
	sent := make(chan error, 1)
	go func() { sent <- cm.SendToConnectionChecked(context.Background(), conn, &pb.HubMessage{}, nil) }()
	<-stream.entered
	replaced := make(chan *AgentConn, 1)
	go func() { replaced <- cm.Register("node", &mockStream{}) }()
	select {
	case <-replaced:
		t.Fatal("connection replacement crossed an in-flight guarded send")
	case <-time.After(100 * time.Millisecond):
	}
	close(stream.release)
	// Replacement retires the old generation immediately, so the caller may
	// observe disconnection even though the already-entered Send finishes first.
	<-sent
	if current := <-replaced; cm.GetConn("node") != current {
		t.Fatal("replacement did not become the current generation")
	}
	select {
	case <-conn.Done():
	default:
		t.Fatal("replaced generation remained live")
	}
}

func TestSendToAgentAndConnectionReplacementHaveOneOrder(t *testing.T) {
	cm := New()
	stream := &blockedCheckedStream{mockStream: &mockStream{}, entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	old := cm.Register("node", stream)
	sent := make(chan error, 1)
	go func() { sent <- cm.SendToAgent("node", &pb.HubMessage{}) }()
	<-stream.entered
	replaced := make(chan *AgentConn, 1)
	go func() { replaced <- cm.Register("node", &mockStream{}) }()
	select {
	case <-replaced:
		t.Fatal("connection replacement crossed an in-flight generic send")
	case <-time.After(100 * time.Millisecond):
	}
	close(stream.release)
	<-sent
	current := <-replaced
	if cm.GetConn("node") != current || current == old {
		t.Fatal("replacement did not install a distinct current generation")
	}
}

func TestDisconnectRetiresOnlyAfterAdmittedGuardLeavesGeneration(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	conn := cm.Register("node", stream)
	guarded, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- cm.SendToConnectionGuarded(context.Background(), conn, &pb.HubMessage{}, func(send func() error) error {
			close(guarded)
			<-release
			return send()
		})
	}()
	<-guarded
	cm.Unregister("node")
	if cm.GetConn("node") != nil {
		t.Fatal("closing generation remained available to callers")
	}
	cm.mu.RLock()
	installed, retiring := cm.streams["node"], cm.retiring["node"]
	cm.mu.RUnlock()
	if installed != conn || retiring != conn {
		t.Fatal("generation retired before its admitted guard drained")
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("closing generation sent after disconnect")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		cm.mu.RLock()
		installed, retiring = cm.streams["node"], cm.retiring["node"]
		cm.mu.RUnlock()
		if installed == nil && retiring == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("drained generation was not retired")
}

func TestInboundDeliveryAndConnectionReplacementHaveOneOrder(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	conn := cm.Register("node", stream)
	entered := make(chan struct{})
	release := make(chan struct{})
	delivered := make(chan bool, 1)
	go func() {
		delivered <- cm.WithCurrentGeneration("node", stream, func(*AgentConn) {
			close(entered)
			<-release
		})
	}()
	<-entered

	replaced := make(chan *AgentConn, 1)
	go func() { replaced <- cm.Register("node", &mockStream{}) }()
	select {
	case <-replaced:
		t.Fatal("connection replacement crossed an in-flight inbound delivery")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if !<-delivered {
		t.Fatal("current generation delivery was rejected")
	}
	if current := <-replaced; cm.GetConn("node") != current {
		t.Fatal("replacement did not become the current generation")
	}
	if cm.WithCurrentGeneration("node", stream, func(*AgentConn) { t.Fatal("stale callback ran") }) {
		t.Fatal("replaced generation was accepted")
	}
	select {
	case <-conn.Done():
	default:
		t.Fatal("replaced generation remained live")
	}
}

type blockedFileStopStream struct {
	*mockStream
	generationDone             <-chan struct{}
	entered, release, finished chan struct{}
}

func (s *blockedFileStopStream) Send(msg *pb.HubMessage) error {
	if msg.GetFileReadCancel() == nil {
		return s.mockStream.Send(msg)
	}
	close(s.entered)
	defer close(s.finished)
	select {
	case <-s.release:
		return nil
	case <-s.generationDone:
		return context.Canceled
	}
}

func startBlockedFileStop(t *testing.T) (*ConnManager, *AgentConn, *blockedFileStopStream, *Activity) {
	t.Helper()
	cm := New()
	stream := &blockedFileStopStream{
		mockStream: &mockStream{},
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
		finished:   make(chan struct{}),
	}
	conn := cm.Register("node", stream)
	stream.generationDone = conn.Done()

	msg := &pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{
		FileReadRequest: &pb.FileReadRequest{RequestId: "read"},
	}}
	activity, err := cm.BeginRequest(conn, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := activity.Send(t.Context(), msg); err != nil {
		t.Fatal(err)
	}

	stopCtx, cancelStop := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancelStop()
	stopReturned := make(chan struct{})
	go func() {
		activity.TryCancelFileRead(stopCtx)
		close(stopReturned)
	}()
	<-stream.entered
	<-stopReturned
	return cm, conn, stream, activity
}

func TestInFlightFileStopDeadlinePreservesConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm, conn, stream, activity := startBlockedFileStop(t)
		defer conn.Close()
		if cm.GetConn("node") != conn {
			t.Fatal("in-flight best-effort stop disconnected the control stream")
		}

		// A duplicate stop must skip this writer, and another preview
		// waiting for its turn may expire without retiring the generation.
		activity.TryCancelFileRead(t.Context())
		queuedCtx, cancelQueued := context.WithTimeout(t.Context(), time.Second)
		defer cancelQueued()
		msg := &pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{
			RequestId: "read", Mode: pb.FileReadMode_FILE_READ_MODE_IMAGE,
		}}}
		if err := activity.SendImageRead(queuedCtx, msg, 10*time.Second); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued preview send: %v", err)
		}
		if cm.GetConn("node") != conn || len(stream.sent) != 1 {
			t.Fatal("queued send affected the generation or crossed the active stop")
		}

		close(stream.release)
		<-stream.finished
		if err := cm.SendToConnectionChecked(t.Context(), conn, &pb.HubMessage{}, nil); err != nil {
			t.Fatalf("control writer did not recover: %v", err)
		}
		time.Sleep(30 * time.Second)
		if cm.GetConn("node") != conn {
			t.Fatal("resolved stop left a watchdog that disconnected the control stream")
		}
	})
}

func TestInFlightFileStopHealthDeadlineRetiresOnlyStalledGeneration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm, conn, stream, _ := startBlockedFileStop(t)
		defer conn.Close()
		cleaned := make(chan struct{})
		go func() {
			<-conn.Done()
			cm.UnregisterIfCurrent("node", stream)
			close(cleaned)
		}()
		queued := make(chan error, 1)
		go func() {
			queued <- cm.SendToConnectionChecked(t.Context(), conn, &pb.HubMessage{}, nil)
		}()
		maintenance := make(chan error, 1)
		go func() {
			maintenance <- cm.ReserveMaintenance(conn, "old", func() error {
				return nil
			})
		}()

		// The caller waited two seconds. Let the write reach the end of
		// its independent 30-second health window.
		time.Sleep(28*time.Second - time.Nanosecond)
		if cm.GetConn("node") != conn {
			t.Fatal("caller deadline or queued work closed the generation early")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		select {
		case <-conn.Done():
		default:
			t.Fatal("persistently stalled control writer survived its health deadline")
		}
		<-cleaned
		<-stream.finished
		if err := <-queued; err == nil {
			t.Fatal("queued control send crossed generation closure")
		}
		if err := <-maintenance; err == nil {
			t.Fatal("queued maintenance reserved a closed generation")
		}

		newStream := &mockStream{}
		replacement := cm.Register("node", newStream)
		time.Sleep(30 * time.Second)
		if cm.GetConn("node") != replacement || replacement == conn || len(newStream.sent) != 0 {
			t.Fatal("watchdog or queued old work affected the replacement generation")
		}
		if err := cm.ObserveActivityCapabilities("node", newStream, 1, 0); err != nil {
			t.Fatal(err)
		}
		if err := cm.ReserveMaintenance(replacement, "new", func() error { return nil }); err != nil {
			t.Fatalf("maintenance could not proceed on the replacement: %v", err)
		}
	})
}

func TestImageDispatchAndRequiredCleanupUseSeparateCancellationPolicies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := New()
		stream := &mockStream{}
		conn := cm.Register("node", stream)
		msg := &pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{
			RequestId: "image", Mode: pb.FileReadMode_FILE_READ_MODE_IMAGE,
		}}}
		activity, err := cm.BeginRequest(conn, msg)
		if err != nil {
			t.Fatal(err)
		}

		conn.SendMu.Lock()
		defer conn.SendMu.Unlock()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		imageResult := make(chan error, 1)
		go func() { imageResult <- activity.SendImageRead(ctx, msg, 10*time.Second) }()
		synctest.Wait()
		cancel()
		if err := <-imageResult; !errors.Is(err, context.Canceled) {
			t.Fatalf("queued preview send: %v", err)
		}
		activity.Abandon()
		if cm.GetConn("node") != conn || len(stream.sent) != 0 || activity.Dispatched() {
			t.Fatal("abandoned preview dispatched or closed a healthy generation")
		}

		cleanup, cancelCleanup := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancelCleanup()
		if err := cm.SendToConnectionChecked(cleanup, conn, &pb.HubMessage{}, nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued cleanup send: %v", err)
		}
		if cm.GetConn("node") != nil {
			t.Fatal("required cleanup failure did not close its exact generation")
		}
	})
}
