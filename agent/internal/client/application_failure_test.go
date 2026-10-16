package client

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	"github.com/wyiu/veyport/proto/applicationproxy"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type applicationFaultService struct {
	pb.AgentServiceClient
	open func(context.Context) (pb.AgentService_ApplicationProxyClient, error)
}

func (s applicationFaultService) ApplicationProxy(ctx context.Context, _ ...grpc.CallOption) (pb.AgentService_ApplicationProxyClient, error) {
	return s.open(ctx)
}

type applicationFaultStream struct {
	grpc.ClientStream
	ctx       context.Context
	messages  []*pb.ApplicationHubMessage
	failSend  int
	sendCount int
}

func (s *applicationFaultStream) Context() context.Context { return s.ctx }
func (s *applicationFaultStream) Send(*pb.ApplicationAgentMessage) error {
	s.sendCount++
	if s.sendCount == s.failSend {
		return io.ErrClosedPipe
	}
	return nil
}
func (s *applicationFaultStream) Recv() (*pb.ApplicationHubMessage, error) {
	if len(s.messages) > 0 {
		message := s.messages[0]
		s.messages = s.messages[1:]
		return message, nil
	}
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

func TestApplicationFailureNeverLeavesBackendOrRPCWorkers(t *testing.T) {
	for _, kind := range []string{"rpc-open", "attach-send", "bad-ack", "policy-denied", "opened-send", "malformed-data", "half-close"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			open := testApplicationOpen()
			stream := &applicationFaultStream{ctx: ctx, messages: []*pb.ApplicationHubMessage{{Payload: &pb.ApplicationHubMessage_Attached{Attached: &pb.ApplicationAttached{Binding: open.Binding}}}}}
			dials := 0
			var peer net.Conn
			e := &applicationTransport{ctx: ctx, cancel: cancel, dial: applicationproxy.Dialer{Dial: func(context.Context, string, string) (net.Conn, error) {
				dials++
				a, b := net.Pipe()
				peer = b
				return a, nil
			}}}
			e.client = applicationFaultService{open: func(context.Context) (pb.AgentService_ApplicationProxyClient, error) { return stream, nil }}
			switch kind {
			case "rpc-open":
				e.client = applicationFaultService{open: func(context.Context) (pb.AgentService_ApplicationProxyClient, error) { return nil, io.ErrClosedPipe }}
			case "attach-send":
				stream.failSend = 1
			case "bad-ack":
				stream.messages[0] = &pb.ApplicationHubMessage{}
			case "policy-denied":
				open.Target.ForbiddenAuthorities = []string{"127.0.0.1:8080"}
			case "opened-send":
				stream.failSend = 2
			case "malformed-data":
				stream.messages = append(stream.messages, &pb.ApplicationHubMessage{Payload: &pb.ApplicationHubMessage_Data{Data: &pb.ApplicationData{Sequence: 4, Data: []byte("forged")}}})
			case "half-close":
				stream.messages = append(stream.messages, &pb.ApplicationHubMessage{Payload: &pb.ApplicationHubMessage_Eof{Eof: &pb.ApplicationEOF{}}})
				e.dial.Dial = func(context.Context, string, string) (net.Conn, error) {
					dials++
					a, b := net.Pipe()
					b.Close()
					return a, nil
				}
			}
			done := make(chan string, 1)
			go func() { done <- e.serve(ctx, cancel, open) }()
			select {
			case reason := <-done:
				if reason == "" {
					t.Fatal("failure reason missing")
				}
			case <-time.After(time.Second):
				cancel()
				t.Fatal("failure leaked a worker")
			}
			cancel()
			if kind == "rpc-open" || kind == "attach-send" || kind == "bad-ack" || kind == "policy-denied" {
				if dials != 0 {
					t.Fatalf("%s contacted backend", kind)
				}
			}
			if peer != nil {
				defer peer.Close()
				peer.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := peer.Read(make([]byte, 1)); err == nil {
					t.Fatal("failure left backend socket open")
				}
			}
		})
	}
}

func TestApplicationCancellationBindingCapacityAndDuplicates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	send := make(chan *pb.AgentMessage, 4)
	budget := sessionlimit.New(8)
	e := &applicationTransport{ctx: ctx, cancel: cancel, nodeID: "node", bootID: "1234567890123456", budget: budget, send: send, sessions: make(map[string]*applicationSocket)}
	open := testApplicationOpen()
	ended := make(chan struct{})
	child, closeChild := context.WithCancel(ctx)
	go func() { <-child.Done(); close(ended) }()
	e.sessions[open.Binding.ConnectionId] = &applicationSocket{binding: open.Binding, cancel: closeChild}
	e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ApplicationOpen{ApplicationOpen: open}})
	malformedRetry := proto.Clone(open).(*pb.ApplicationOpen)
	malformedRetry.Target = nil
	e.open(malformedRetry)
	if len(send) != 0 || budget.ActivityCount() != 0 {
		t.Fatal("duplicate acknowledged or acquired another worker")
	}
	wrong := proto.Clone(open.Binding).(*pb.ApplicationBinding)
	wrong.ConfigVersion++
	e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ApplicationClose{ApplicationClose: &pb.ApplicationClose{Binding: wrong}}})
	if child.Err() != nil {
		t.Fatal("wrong binding cancelled live socket")
	}
	e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ApplicationClose{ApplicationClose: &pb.ApplicationClose{Binding: open.Binding}}})
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("valid close did not cancel")
	}
	e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ApplicationClose{ApplicationClose: &pb.ApplicationClose{}}})
	if e.handle(&pb.HubMessage{}) {
		t.Fatal("unrelated control payload consumed")
	}
	delete(e.sessions, open.Binding.ConnectionId)
	for i := range maxApplicationSockets {
		e.sessions[string(rune('a'+i))] = &applicationSocket{cancel: func() {}}
	}
	e.open(open)
	if response := <-send; response.GetApplicationClosed().ReasonCode != "capacity" {
		t.Fatal("node socket capacity not enforced")
	}
	e.closed = true
	e.open(open)
	e.open(nil)
	e.close()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("transport close did not cancel")
	}
}
