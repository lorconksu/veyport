package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/execution"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type executionFaultService struct {
	pb.AgentServiceClient
	open func(context.Context) (pb.AgentService_ExecuteClient, error)
}

func (s executionFaultService) Execute(ctx context.Context, _ ...grpc.CallOption) (pb.AgentService_ExecuteClient, error) {
	return s.open(ctx)
}

type executionOutcomeFaultStream struct {
	mockExecutionStream
	resultSent      chan struct{}
	sendResultError error
	closeError      error
	replyError      error
	replyLost       bool
	closeCalls      int
	closeHook       func()
}

func (s *executionOutcomeFaultStream) Send(msg *pb.ExecutionAgentMessage) error {
	s.sent = append(s.sent, proto.Clone(msg).(*pb.ExecutionAgentMessage))
	if msg.GetResult() != nil {
		close(s.resultSent)
		return s.sendResultError
	}
	return nil
}

func (s *executionOutcomeFaultStream) Recv() (*pb.ExecutionHubMessage, error) {
	if len(s.recv) != 0 {
		return s.mockExecutionStream.Recv()
	}
	// Preserve the transport until the agent has a durable real result. This
	// isolates reply loss from process cancellation before completion.
	select {
	case <-s.resultSent:
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
	if s.replyLost {
		<-s.ctx.Done()
		return nil, s.ctx.Err()
	}
	if s.replyError != nil {
		return nil, s.replyError
	}
	return nil, io.EOF
}

func (s *executionOutcomeFaultStream) CloseSend() error {
	s.closeCalls++
	if s.closeHook != nil {
		s.closeHook()
	}
	return s.closeError
}

func outcomeFailureManager(t *testing.T) *execution.Manager {
	t.Helper()
	j, err := execution.OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m, err := execution.NewManager(execution.Config{NodeID: "node", Journal: j, TermGrace: 15 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

func TestExecutionFinalDeliveryFailureKeepsDurableRealOutcomeAndClaim(t *testing.T) {
	for _, fault := range []string{"success", "result-send", "close-send", "lost-reply", "control-cancel-before-reply"} {
		t.Run(fault, func(t *testing.T) {
			m := outcomeFailureManager(t)
			p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "final-delivery", NodeId: "node", Command: "printf actual; printf diagnostic >&2; exit 42"})
			if p.Error != "" {
				t.Fatal(p.Error)
			}
			start := &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits}
			stream := &executionOutcomeFaultStream{resultSent: make(chan struct{})}
			stream.recv = []*pb.ExecutionHubMessage{{Payload: &pb.ExecutionHubMessage_Attached{Attached: &pb.ExecutionAttached{Binding: p.Binding}}}, {Payload: &pb.ExecutionHubMessage_Start{Start: start}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var want error
			switch fault {
			case "result-send":
				stream.sendResultError = io.ErrClosedPipe
				want = io.ErrClosedPipe
			case "close-send":
				stream.closeError = io.ErrClosedPipe
				want = io.ErrClosedPipe
			case "lost-reply":
				stream.replyError = io.ErrUnexpectedEOF
				want = io.ErrUnexpectedEOF
			case "control-cancel-before-reply":
				stream.replyLost = true
				stream.closeHook = cancel
				want = context.Canceled
			}
			e := &executionTransport{ctx: ctx, manager: m, client: executionFaultService{open: func(child context.Context) (pb.AgentService_ExecuteClient, error) {
				stream.ctx = child
				return stream, nil
			}}}
			done := make(chan error, 1)
			go func() {
				done <- e.serve(&pb.ExecutionAttachRequest{Binding: p.Binding, Ticket: bytes.Repeat([]byte{1}, 32)})
			}()
			select {
			case err := <-done:
				if (want == nil && err != nil) || (want != nil && !errors.Is(err, want)) {
					t.Fatalf("final delivery failure: %v want=%v", err, want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("final delivery failure leaked transport")
			}
			status := m.Status(p.ExecutionId)
			if status.State != "exited" || status.Result == nil || status.Result.ExitCode != 42 || !status.Result.StdoutComplete || !status.Result.StderrComplete {
				t.Fatalf("reply failure replaced durable real result: %+v", status)
			}
			var stdout, stderr bytes.Buffer
			var stdoutEOF, stderrEOF bool
			var final *pb.ExecutionResult
			for _, msg := range stream.sent {
				if d := msg.GetStdout(); d != nil {
					stdout.Write(d.Data)
				}
				if d := msg.GetStderr(); d != nil {
					stderr.Write(d.Data)
				}
				if eof := msg.GetOutputEof(); eof != nil {
					if eof.Output == pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT {
						stdoutEOF = true
					} else if eof.Output == pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR {
						stderrEOF = true
					}
				}
				if result := msg.GetResult(); result != nil {
					if !stdoutEOF || !stderrEOF {
						t.Fatal("final result preceded output EOF")
					}
					final = result
				}
			}
			if stdout.String() != "actual" || stderr.String() != "diagnostic" || !proto.Equal(final, status.Result) {
				t.Fatalf("final delivery lost observed output/result: %q %q %+v", stdout.String(), stderr.String(), final)
			}
			if _, err := m.Start(context.Background(), start); !errors.Is(err, execution.ErrAlreadyClaimed) {
				t.Fatalf("reply loss allowed command replay: %v", err)
			}
			if stream.closeCalls != 1 && fault != "result-send" {
				t.Fatalf("send side not closed exactly once: %d", stream.closeCalls)
			}
		})
	}
}

func TestExecutionConnectionOpenFailureCannotClaimPreparation(t *testing.T) {
	m := outcomeFailureManager(t)
	p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "open-failure", NodeId: "node", Command: "exit 42"})
	if p.Error != "" {
		t.Fatal(p.Error)
	}
	e := &executionTransport{ctx: context.Background(), manager: m, client: executionFaultService{open: func(context.Context) (pb.AgentService_ExecuteClient, error) { return nil, io.ErrClosedPipe }}}
	if err := e.serve(&pb.ExecutionAttachRequest{Binding: p.Binding, Ticket: bytes.Repeat([]byte{1}, 32)}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("connection error: %v", err)
	}
	if got := m.Status(p.ExecutionId); got.State != "prepared" {
		t.Fatalf("connection failure claimed work: %+v", got)
	}
	if run, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits}); err != nil {
		t.Fatalf("untouched valid preparation cannot start: %v", err)
	} else {
		inputFailureResult(t, run)
	}
}
