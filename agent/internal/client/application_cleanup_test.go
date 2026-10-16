package client

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wyiu/veyport/proto/applicationproxy"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestApplicationCancellationBetweenAttachAndDialCleansSocket(t *testing.T) {
	for _, kind := range []string{"expired-before-dial", "cancelled-after-dial"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			open := testApplicationOpen()
			stream := &applicationFaultStream{ctx: ctx, messages: []*pb.ApplicationHubMessage{{Payload: &pb.ApplicationHubMessage_Attached{Attached: &pb.ApplicationAttached{Binding: open.Binding}}}}}
			var peer net.Conn
			dials := 0
			e := &applicationTransport{ctx: ctx, cancel: cancel, client: applicationFaultService{open: func(context.Context) (pb.AgentService_ApplicationProxyClient, error) { return stream, nil }}, dial: applicationproxy.Dialer{Dial: func(context.Context, string, string) (net.Conn, error) {
				dials++
				local, remote := net.Pipe()
				peer = remote
				cancel()
				return local, nil
			}}}
			want := "cancelled"
			if kind == "expired-before-dial" {
				open.Binding.ExpiresUnixMilli = time.Now().Add(-time.Second).UnixMilli()
				want = "expired"
			}
			if got := e.serve(ctx, cancel, open); got != want {
				t.Fatalf("unexpected cleanup reason: %s", got)
			}
			if stream.sendCount != 1 {
				t.Fatal("cancelled admission sent backend-ready acknowledgement")
			}
			if kind == "expired-before-dial" && dials != 0 {
				t.Fatal("expired attachment contacted backend")
			}
			if peer != nil {
				defer peer.Close()
				peer.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("cancelled backend socket remained open: %v", err)
				}
			}
		})
	}
}

func TestApplicationCleanupAcknowledgementCannotStallControl(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controlCancelled := make(chan struct{})
	e := &applicationTransport{ctx: ctx, send: make(chan *pb.AgentMessage), controlCancel: func() { close(controlCancelled) }}
	done := make(chan struct{})
	go func() { e.emitClosed(testApplicationOpen().Binding, "transport"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup acknowledgement blocked indefinitely")
	}
	select {
	case <-controlCancelled:
	default:
		t.Fatal("unresponsive control stream was not cancelled")
	}
	// Once the control lifetime ends, cleanup must not wait for its send queue.
	cancel()
	done = make(chan struct{})
	go func() { e.emitClosed(testApplicationOpen().Binding, "transport"); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cancelled control delayed cleanup")
	}
}

type applicationDeadlineFailureConn struct {
	net.Conn
	writes int
}

func (c *applicationDeadlineFailureConn) SetWriteDeadline(time.Time) error { return io.ErrClosedPipe }
func (c *applicationDeadlineFailureConn) Write([]byte) (int, error)        { c.writes++; return 1, nil }

func TestApplicationSocketWriterRequiresBoundedWriteDeadline(t *testing.T) {
	c := &applicationDeadlineFailureConn{}
	if n, err := (applicationSocketWriter{c}).Write([]byte("x")); n != 0 || !errors.Is(err, io.ErrClosedPipe) || c.writes != 0 {
		t.Fatalf("unbounded backend write attempted: %d %v writes=%d", n, err, c.writes)
	}
}

func TestApplicationReceiveRejectsMissingOrForgedControlFrames(t *testing.T) {
	for _, kind := range []string{"nil", "unexpected", "wrong-close", "matching-close"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			binding := testApplicationOpen().Binding
			var message *pb.ApplicationHubMessage
			want := applicationproxy.ErrFrame
			switch kind {
			case "unexpected":
				message = &pb.ApplicationHubMessage{}
			case "wrong-close":
				message = &pb.ApplicationHubMessage{Payload: &pb.ApplicationHubMessage_Close{Close: &pb.ApplicationClose{Binding: &pb.ApplicationBinding{ConnectionId: "other"}}}}
			case "matching-close":
				message = &pb.ApplicationHubMessage{Payload: &pb.ApplicationHubMessage_Close{Close: &pb.ApplicationClose{Binding: binding}}}
				want = net.ErrClosed
			}
			stream := &applicationFaultStream{ctx: ctx, messages: []*pb.ApplicationHubMessage{message}}
			conn := applicationproxy.NewConn(ctx, func(applicationproxy.Frame) error { return nil }, cancel)
			defer conn.Close()
			if err := receiveApplicationBytes(stream, conn, binding); !errors.Is(err, want) {
				t.Fatalf("unexpected frame accepted: %v", err)
			}
		})
	}
}
