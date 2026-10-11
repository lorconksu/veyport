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
	"google.golang.org/protobuf/proto"
)

func inputFailureRun(t *testing.T, command string) (*execution.Manager, *pb.ExecutionPrepared, *execution.Run) {
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
	p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "input-contract", NodeId: "node", Command: command})
	if p.Error != "" {
		t.Fatal(p.Error)
	}
	r, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits})
	if err != nil {
		t.Fatal(err)
	}
	return m, p, r
}

func inputFailureResult(t *testing.T, run *execution.Run) *pb.ExecutionResult {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case msg, ok := <-run.Messages():
			if !ok {
				t.Fatal("execution closed without final result")
			}
			if result := msg.GetResult(); result != nil {
				return result
			}
		case <-timer.C:
			t.Fatal("execution cancellation did not finish")
		}
	}
}

func TestExecutionInputFaultCancelsAndDrainsLaterFrames(t *testing.T) {
	for _, fault := range []string{"sequence-gap", "oversize", "wrong-eof", "missing-input", "missing-eof", "unexpected-start"} {
		t.Run(fault, func(t *testing.T) {
			m, p, run := inputFailureRun(t, "cat")
			bad := &pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_Input{Input: &pb.ExecutionData{Sequence: 1}}}
			switch fault {
			case "oversize":
				bad.GetInput().Sequence = 0
				bad.GetInput().Data = make([]byte, execution.MaxFrameBytes+1)
			case "wrong-eof":
				bad = &pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_InputEof{InputEof: &pb.ExecutionInputEOF{Sequence: 1}}}
			case "missing-input":
				bad = &pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_Input{}}
			case "missing-eof":
				bad = &pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_InputEof{}}
			case "unexpected-start":
				bad = &pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_Start{Start: &pb.ExecutionStart{Binding: p.Binding}}}
			}
			stream := &mockExecutionStream{ctx: context.Background(), recv: []*pb.ExecutionHubMessage{bad, {Payload: &pb.ExecutionHubMessage_Input{Input: &pb.ExecutionData{Sequence: 0, Data: []byte("must never reach command")}}}, {Payload: &pb.ExecutionHubMessage_Cancel{Cancel: &pb.ExecutionCancel{Binding: p.Binding, Reason: "must not replace initial reason"}}}}}
			if err := receiveExecutionInput(stream, run, p.Binding); !errors.Is(err, io.EOF) {
				t.Fatalf("input fault drain: %v", err)
			}
			result := inputFailureResult(t, run)
			if result.State != "cancelled" || result.Reason != "invalid_execution_input" {
				t.Fatalf("invalid frame result: %+v", result)
			}
			if len(stream.recv) != 0 {
				t.Fatal("invalid stream did not drain queued frames")
			}
			if durable := m.Status(p.ExecutionId); durable.Result == nil || !proto.Equal(durable.Result, result) {
				t.Fatalf("cancellation not durable: %+v", durable)
			}
		})
	}
}

func TestExecutionCancelBindingFailureDoesNotCancelDifferentRun(t *testing.T) {
	m, p, run := inputFailureRun(t, "cat")
	wrong := proto.Clone(p.Binding).(*pb.ExecutionBinding)
	wrong.ExecutionId = "another-command"
	stream := &mockExecutionStream{ctx: context.Background(), recv: []*pb.ExecutionHubMessage{{Payload: &pb.ExecutionHubMessage_Cancel{Cancel: &pb.ExecutionCancel{Binding: wrong, Reason: "client_lost"}}}}}
	if err := receiveExecutionInput(stream, run, p.Binding); err == nil {
		t.Fatal("foreign cancellation accepted")
	}
	if got := m.Status(p.ExecutionId); got.State != "running" {
		t.Fatalf("foreign cancellation changed run: %+v", got)
	}
	if err := m.Cancel(&pb.ExecutionCancel{Binding: p.Binding, Reason: "cleanup"}); err != nil {
		t.Fatal(err)
	}
	inputFailureResult(t, run)
}

func TestExecutionInputEOFAndBinaryBytesSurviveTransport(t *testing.T) {
	_, p, run := inputFailureRun(t, "cat; printf problem >&2; exit 42")
	data := []byte{0, 255, 'x'}
	stream := &mockExecutionStream{ctx: context.Background(), recv: []*pb.ExecutionHubMessage{{Payload: &pb.ExecutionHubMessage_Input{Input: &pb.ExecutionData{Data: data}}}, {Payload: &pb.ExecutionHubMessage_InputEof{InputEof: &pb.ExecutionInputEOF{Sequence: 1}}}}}
	if err := receiveExecutionInput(stream, run, p.Binding); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	var result *pb.ExecutionResult
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for result == nil {
		select {
		case msg, ok := <-run.Messages():
			if !ok {
				t.Fatal("no final result")
			}
			if d := msg.GetStdout(); d != nil {
				out.Write(d.Data)
			}
			if d := msg.GetStderr(); d != nil {
				stderr.Write(d.Data)
			}
			result = msg.GetResult()
		case <-timer.C:
			t.Fatal("EOF did not finish command")
		}
	}
	if !bytes.Equal(out.Bytes(), data) || stderr.String() != "problem" || result.State != "exited" || result.ExitCode != 42 || !result.StdoutComplete || !result.StderrComplete {
		t.Fatalf("stdin/EOF changed output: %v %q %+v", out.Bytes(), stderr.String(), result)
	}
}
