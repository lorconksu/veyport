package grpcserver

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestStandardExecutionCheckedDispatchRequiresLiveCheckAndPreservesOneStart(t *testing.T) {
	for _, authorized := range []bool{false, true} {
		name := "denied"
		if authorized {
			name = "valid"
		}
		t.Run(name, func(t *testing.T) {
			es, s := authorityPreparedSession(t)
			attach, err := s.IssueAttach()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := es.Attach(s.NodeID, attach); err != nil {
				t.Fatal(err)
			}
			if err := s.DispatchChecked(nil); err == nil || s.dispatch || len(s.start) != 0 {
				t.Fatal("missing live check consumed dispatch authority")
			}
			checked := false
			denied := errors.New("synthetic policy denial")
			if err := s.DispatchChecked(func() error {
				checked = true
				if !authorized {
					return denied
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if checked || s.StartAttempted() || s.DispatchChecked(func() error { return nil }) == nil {
				t.Fatal("queueing invoked the sender check or allowed a second dispatch")
			}
			stream := &failingProtectedStream{executionTestStream: executionTestStream{sent: make(chan *pb.ExecutionHubMessage, 4)}}
			stream.afterSend = func(msg *pb.ExecutionHubMessage) {
				if msg.GetStart() != nil {
					s.Cancel("synthetic completion")
				}
			}
			err = sendExecution(stream, s)
			if !checked || authorized && err != nil || !authorized && !errors.Is(err, denied) || s.StartAttempted() != authorized {
				t.Fatalf("incorrect final authority boundary: checked=%v attempted=%v err=%v", checked, s.StartAttempted(), err)
			}
			close(stream.sent)
			starts := 0
			for msg := range stream.sent {
				if msg.GetStart() != nil {
					starts++
				}
			}
			if starts != 0 && !authorized || starts != 1 && authorized {
				t.Fatalf("checked dispatch sent %d Starts", starts)
			}
		})
	}
}

func TestExecutionQueuedStartRechecksLifecycleAfterAuthorization(t *testing.T) {
	for _, mode := range []string{"standard", "protected"} {
		for _, change := range []string{"cancel", "transport", "context", "closed-control", "replacement-control"} {
			t.Run(mode+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var s *ExecutionSession
				if mode == "standard" {
					s = executionReceiveSession(t)
				} else {
					s = protectedSession(t, []byte("synthetic input"))
					if err := s.DispatchProtected([]byte("verified fixture"), time.Now().Add(time.Second).UnixMilli(), "2", bytes.NewReader([]byte("synthetic input")), func() error { return nil }); err != nil {
						t.Fatal(err)
					}
				}
				dispatch := <-s.start
				checked := false
				dispatch.beforeStart = func() error {
					checked = true
					switch change {
					case "cancel":
						s.Cancel("synthetic revocation")
					case "transport":
						close(s.transportDone)
					case "context":
						cancel()
					case "closed-control":
						s.connection.Close()
					case "replacement-control":
						s.registry.connections.Register(s.NodeID, &mockStream{})
					}
					return nil
				}
				s.start <- dispatch
				stream := &failingProtectedStream{executionTestStream: executionTestStream{ctx: ctx, sent: make(chan *pb.ExecutionHubMessage, 8)}}
				// Bound a failing implementation without running any command.
				stream.afterSend = func(msg *pb.ExecutionHubMessage) {
					if msg.GetStart() != nil {
						cancel()
					}
				}
				_ = sendExecution(stream, s)
				if !checked {
					t.Fatal("queued dispatch did not reach the final authorization check")
				}
				if s.StartAttempted() {
					t.Fatal("withdrawn lifecycle authority became a Start attempt")
				}
				close(stream.sent)
				for msg := range stream.sent {
					if msg.GetStart() != nil || msg.GetInput() != nil {
						t.Fatal("sender emitted launch or input after authority withdrawal")
					}
				}
			})
		}
	}
}

func TestExecutionQueuedDispatchRejectsStaleControlBeforeProtectedTransfer(t *testing.T) {
	script := []byte("synthetic input")
	s := protectedSession(t, script)
	checked := false
	if err := s.DispatchProtected([]byte("verified fixture"), time.Now().Add(time.Second).UnixMilli(), "2", bytes.NewReader(script), func() error { checked = true; return nil }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &failingProtectedStream{executionTestStream: executionTestStream{ctx: ctx, sent: make(chan *pb.ExecutionHubMessage, 8)}}
	stream.afterSend = func(msg *pb.ExecutionHubMessage) {
		if msg.GetAttached() != nil {
			s.registry.connections.Register(s.NodeID, &mockStream{})
		}
		if msg.GetStart() != nil {
			cancel()
		}
	}
	if err := sendExecution(stream, s); err == nil {
		t.Fatal("stale dispatch retained sender authority")
	}
	if checked || s.StartAttempted() || len(stream.sent) != 1 || (<-stream.sent).GetAttached() == nil {
		t.Fatal("stale dispatch transferred protected input or attempted Start")
	}
}
