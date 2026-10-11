package connmgr

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
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
