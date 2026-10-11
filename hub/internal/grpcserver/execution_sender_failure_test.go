package grpcserver

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestExecutionSenderReportsExactTransportFailureBoundary(t *testing.T) {
	for _, phase := range []string{"attached", "start", "stdin", "context-after-start"} {
		t.Run(phase, func(t *testing.T) {
			s := executionReceiveSession(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &failingProtectedStream{executionTestStream: executionTestStream{ctx: ctx, sent: make(chan *pb.ExecutionHubMessage, 4)}}
			stream.fail = func(msg *pb.ExecutionHubMessage) error {
				if (phase == "attached" && msg.GetAttached() != nil) || (phase == "start" && msg.GetStart() != nil) || (phase == "stdin" && msg.GetInput() != nil) {
					return io.ErrClosedPipe
				}
				return nil
			}
			if phase == "stdin" {
				if err := s.SendInput(ctx, []byte("queued binary input")); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "context-after-start" {
				stream.afterSend = func(msg *pb.ExecutionHubMessage) {
					if msg.GetStart() != nil {
						cancel()
					}
				}
			}
			want := error(io.ErrClosedPipe)
			if phase == "context-after-start" {
				want = context.Canceled
			}
			if err := sendExecution(stream, s); !errors.Is(err, want) {
				t.Fatalf("%s transport error: %v", phase, err)
			}
			if s.StartAttempted() != (phase != "attached") {
				t.Fatalf("%s lost the actual Start-attempt boundary", phase)
			}
			close(stream.sent)
			var attached, started bool
			for msg := range stream.sent {
				attached = attached || msg.GetAttached() != nil
				started = started || msg.GetStart() != nil
				if msg.GetInput() != nil {
					t.Fatal("failed input send was presented as delivered")
				}
			}
			if attached != (phase != "attached") || started != (phase == "stdin" || phase == "context-after-start") {
				t.Fatal("transport failure sent later lifecycle frames")
			}
			select {
			case result := <-s.Result:
				t.Fatalf("send failure fabricated process result: %+v", result)
			default:
			}
		})
	}
}

func TestExecutionSenderWaitingForDispatchStopsWithoutStart(t *testing.T) {
	for _, reason := range []string{"context", "revoked", "completed"} {
		t.Run(reason, func(t *testing.T) {
			cm := connmgrForExecutionTest()
			control := cm.GetConn("node").Stream
			es := NewExecutionSessions(NewTerminalSessions(), cm)
			es.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "boot"})
			s, err := es.Register("node", "waiting", "actor", "", []byte("id"))
			if err != nil {
				t.Fatal(err)
			}
			defer es.Remove("node", s.ID)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &executionTestStream{ctx: ctx, sent: make(chan *pb.ExecutionHubMessage, 2)}
			done := make(chan error, 1)
			go func() { done <- sendExecution(stream, s) }()
			select {
			case msg := <-stream.sent:
				if msg.GetAttached() == nil {
					t.Fatal("expected attachment acknowledgement")
				}
			case <-time.After(time.Second):
				t.Fatal("attachment stalled")
			}
			switch reason {
			case "context":
				cancel()
			case "revoked":
				s.Cancel("access revoked")
			case "completed":
				close(s.transportDone)
			}
			select {
			case err := <-done:
				if (reason == "context" && !errors.Is(err, context.Canceled)) || (reason != "context" && err != nil) {
					t.Fatalf("dispatch wait shutdown: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("dispatch wait leaked sender")
			}
			if s.StartAttempted() || len(stream.sent) != 0 {
				t.Fatal("undispatched shutdown emitted Start")
			}
		})
	}
}
