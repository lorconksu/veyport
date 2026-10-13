package grpcserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type executionRPCFaultStream struct {
	executionTestStream
	receive func() (*pb.ExecutionAgentMessage, error)
}

func (s *executionRPCFaultStream) Recv() (*pb.ExecutionAgentMessage, error) {
	return s.receive()
}

func TestExecutionRPCAdmissionRejectsFaultsAndCompletesExactAttachment(t *testing.T) {
	h, st := testHandler(t)
	if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	control := &mockStream{}
	h.connMgr.Register("node", control)
	es := NewExecutionSessions(NewTerminalSessions(), h.connMgr)
	h.executions = es
	es.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "boot"})
	s, err := es.Register("node", "rpc-fault", "actor", "", []byte("id"))
	if err != nil {
		t.Fatal(err)
	}
	defer es.Remove("node", s.ID)
	if !es.DeliverPrepared("node", control, preparedForTest(s.ID, "node", []byte("id"))) {
		t.Fatal("preparation rejected")
	}
	attach, err := s.IssueAttach()
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{Raw: []byte("node"), Subject: pkix.Name{CommonName: "node"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	ctx, cancel := context.WithCancel(peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}}}))
	defer cancel()
	for _, fault := range []string{"unenrolled", "unavailable", "capacity", "lost-first-frame", "empty-first-frame", "wrong-ticket", "context"} {
		t.Run(fault, func(t *testing.T) {
			stream := &executionRPCFaultStream{executionTestStream: executionTestStream{ctx: ctx}, receive: func() (*pb.ExecutionAgentMessage, error) { return nil, nil }}
			want := codes.InvalidArgument
			switch fault {
			case "unenrolled":
				stream.ctx = context.Background()
				want = codes.Unauthenticated
			case "unavailable":
				h.executions = nil
				defer func() { h.executions = es }()
				want = codes.Unavailable
			case "capacity":
				for i := 0; i < cap(es.rpcSlots); i++ {
					es.rpcSlots <- struct{}{}
				}
				defer func() {
					for len(es.rpcSlots) > 0 {
						<-es.rpcSlots
					}
				}()
				want = codes.ResourceExhausted
			case "lost-first-frame":
				stream.receive = func() (*pb.ExecutionAgentMessage, error) { return nil, io.ErrUnexpectedEOF }
				want = codes.Unknown
			case "wrong-ticket":
				wrong := proto.Clone(attach).(*pb.ExecutionAttachRequest)
				wrong.Ticket[0] ^= 1
				stream.receive = func() (*pb.ExecutionAgentMessage, error) {
					return &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Attach{Attach: wrong}}, nil
				}
				want = codes.PermissionDenied
			case "context":
				stopped, stop := context.WithCancel(ctx)
				stop()
				stream.ctx = stopped
				stream.receive = func() (*pb.ExecutionAgentMessage, error) { <-stopped.Done(); return nil, stopped.Err() }
				want = codes.Unknown
			}
			err := h.Execute(stream)
			if status.Code(err) != want {
				t.Fatalf("admission failure: %v want=%v", err, want)
			}
			if fault == "lost-first-frame" && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("lost attachment error: %v", err)
			}
			if fault == "context" && !errors.Is(err, context.Canceled) {
				t.Fatalf("context error: %v", err)
			}
			if fault != "capacity" && len(es.rpcSlots) != 0 {
				t.Fatal("rejected attachment leaked RPC capacity")
			}
			if s.ticketUsed || s.StartAttempted() {
				t.Fatal("rejected admission consumed another valid preparation")
			}
		})
	}
	frames := make(chan *pb.ExecutionAgentMessage, 8)
	frames <- &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Attach{Attach: attach}}
	stream := &executionRPCFaultStream{executionTestStream: executionTestStream{ctx: ctx, sent: make(chan *pb.ExecutionHubMessage, 2)}, receive: func() (*pb.ExecutionAgentMessage, error) {
		select {
		case msg := <-frames:
			return msg, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	done := make(chan error, 1)
	go func() { done <- h.Execute(stream) }()
	select {
	case msg := <-stream.sent:
		if msg.GetAttached() == nil {
			t.Fatal("missing exact attachment")
		}
	case <-time.After(time.Second):
		t.Fatal("attachment stalled")
	}
	if err := s.Dispatch(); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-stream.sent:
		if msg.GetStart() == nil || !proto.Equal(msg.GetStart().Binding, s.Binding()) {
			t.Fatal("missing exact Start")
		}
	case <-time.After(time.Second):
		t.Fatal("Start stalled")
	}
	for _, frame := range executionFinalFrames(s, &pb.ExecutionResult{Binding: s.Binding(), State: "exited", ExitCode: 42, StdoutComplete: true, StderrComplete: true}) {
		frames <- frame
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exact execution failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("final result stalled")
	}
	select {
	case result := <-s.Result:
		if result.State != "exited" || result.ExitCode != 42 {
			t.Fatalf("actual result lost: %+v", result)
		}
	default:
		t.Fatal("final RPC result missing")
	}
	select {
	case <-s.transportDone:
	default:
		t.Fatal("successful RPC did not release input transport")
	}
	if len(es.rpcSlots) != 0 {
		t.Fatal("completed execution leaked RPC capacity")
	}
}

func TestExecutionMalformedAgentFramesCannotPublishResult(t *testing.T) {
	for _, test := range []struct {
		name   string
		code   codes.Code
		frames func(*ExecutionSession) []*pb.ExecutionAgentMessage
	}{
		{"empty", codes.InvalidArgument, func(*ExecutionSession) []*pb.ExecutionAgentMessage { return []*pb.ExecutionAgentMessage{nil} }},
		{"unknown", codes.InvalidArgument, func(*ExecutionSession) []*pb.ExecutionAgentMessage { return []*pb.ExecutionAgentMessage{{}} }},
		{"wrong-started-binding", codes.InvalidArgument, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			binding := s.Binding()
			binding.NodeId = "other"
			return []*pb.ExecutionAgentMessage{{Payload: &pb.ExecutionAgentMessage_Started{Started: &pb.ExecutionStarted{Binding: binding}}}}
		}},
		{"duplicate-started", codes.InvalidArgument, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			return []*pb.ExecutionAgentMessage{executionStartedFrame(s), executionStartedFrame(s)}
		}},
		{"start-failed-after-start", codes.InvalidArgument, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			return []*pb.ExecutionAgentMessage{executionStartedFrame(s), {Payload: &pb.ExecutionAgentMessage_StartFailed{StartFailed: &pb.ExecutionStartFailed{Binding: s.Binding(), State: "launch_failed"}}}}
		}},
		{"stdout-before-start", codes.DataLoss, func(*ExecutionSession) []*pb.ExecutionAgentMessage {
			return []*pb.ExecutionAgentMessage{{Payload: &pb.ExecutionAgentMessage_Stdout{Stdout: &pb.ExecutionData{Data: []byte("untrusted")}}}}
		}},
		{"oversized-stdout", codes.ResourceExhausted, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			return []*pb.ExecutionAgentMessage{executionStartedFrame(s), {Payload: &pb.ExecutionAgentMessage_Stdout{Stdout: &pb.ExecutionData{Data: make([]byte, MaxExecutionFrameBytes+1)}}}}
		}},
		{"stderr-gap", codes.DataLoss, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			return []*pb.ExecutionAgentMessage{executionStartedFrame(s), {Payload: &pb.ExecutionAgentMessage_Stderr{Stderr: &pb.ExecutionData{Sequence: 1}}}}
		}},
		{"stdout-after-eof", codes.DataLoss, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			return []*pb.ExecutionAgentMessage{executionStartedFrame(s), executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT), {Payload: &pb.ExecutionAgentMessage_Stdout{Stdout: &pb.ExecutionData{}}}}
		}},
		{"duplicate-stderr-eof", codes.DataLoss, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			return []*pb.ExecutionAgentMessage{executionStartedFrame(s), executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR), executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR)}
		}},
		{"unknown-output-eof", codes.InvalidArgument, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			return []*pb.ExecutionAgentMessage{executionStartedFrame(s), executionEOFFrame(pb.ExecutionOutput(99))}
		}},
		{"wrong-result-binding", codes.DataLoss, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			binding := s.Binding()
			binding.PreparationId = "other"
			return executionFinalFrames(s, &pb.ExecutionResult{Binding: binding, State: "exited", StdoutComplete: true, StderrComplete: true})
		}},
		{"unknown-result-state", codes.InvalidArgument, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			return executionFinalFrames(s, &pb.ExecutionResult{Binding: s.Binding(), State: "invented", StdoutComplete: true, StderrComplete: true})
		}},
		{"lost-final-reply", codes.DataLoss, func(s *ExecutionSession) []*pb.ExecutionAgentMessage {
			return []*pb.ExecutionAgentMessage{executionStartedFrame(s), executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT), executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR)}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := executionReceiveSession(t)
			if err := receiveExecution(&executionTestStream{messages: test.frames(s)}, s); status.Code(err) != test.code {
				t.Fatalf("malformed stream error=%v want=%v", err, test.code)
			}
			select {
			case result := <-s.Result:
				t.Fatalf("malformed stream published result: %+v", result)
			default:
			}
		})
	}
}

func executionStartedFrame(s *ExecutionSession) *pb.ExecutionAgentMessage {
	return &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Started{Started: &pb.ExecutionStarted{Binding: s.Binding()}}}
}
func executionEOFFrame(output pb.ExecutionOutput) *pb.ExecutionAgentMessage {
	return &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_OutputEof{OutputEof: &pb.ExecutionOutputEOF{Output: output}}}
}
func executionFinalFrames(s *ExecutionSession, result *pb.ExecutionResult) []*pb.ExecutionAgentMessage {
	return []*pb.ExecutionAgentMessage{executionStartedFrame(s), executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT), executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR), {Payload: &pb.ExecutionAgentMessage_Result{Result: result}}}
}

func TestExecutionOutputBackpressureIsCancellableAndCopiesBytes(t *testing.T) {
	s := executionReceiveSession(t)
	data := []byte{0, 255, 1}
	if err := deliverExecutionOutput(context.Background(), s, s.stdout, data); err != nil {
		t.Fatal(err)
	}
	data[0] = 42
	if got := <-s.Stdout; !bytes.Equal(got, []byte{0, 255, 1}) {
		t.Fatalf("output alias: %v", got)
	}
	for i := 0; i < cap(s.stdout); i++ {
		if err := deliverExecutionOutput(context.Background(), s, s.stdout, []byte("queued")); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := deliverExecutionOutput(ctx, s, s.stdout, []byte("must not queue")); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked output cancellation: %v", err)
	}
	s.Cancel("revoked")
	if err := deliverExecutionOutput(context.Background(), s, s.stdout, []byte("must not queue")); err == nil {
		t.Fatal("revocation did not release blocked output")
	}
	if len(s.stdout) != cap(s.stdout) {
		t.Fatal("failed delivery changed bounded queue")
	}
}

type failingProtectedStream struct {
	executionTestStream
	fail      func(*pb.ExecutionHubMessage) error
	afterSend func(*pb.ExecutionHubMessage)
}

func (s *failingProtectedStream) Send(msg *pb.ExecutionHubMessage) error {
	if s.fail != nil {
		if err := s.fail(msg); err != nil {
			return err
		}
	}
	if err := s.executionTestStream.Send(msg); err != nil {
		return err
	}
	if s.afterSend != nil {
		s.afterSend(msg)
	}
	return nil
}

type protectedReadFault struct {
	data []byte
	err  error
}

func (r *protectedReadFault) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = nil
	return n, r.err
}

func TestProtectedTransportFaultCannotSendStart(t *testing.T) {
	for _, fault := range []string{"read-after-prefix", "chunk-send", "eof-send", "cancel-after-chunk", "context-after-chunk"} {
		t.Run(fault, func(t *testing.T) {
			script := []byte("verified script")
			s := protectedSession(t, script)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &failingProtectedStream{executionTestStream: executionTestStream{ctx: ctx, sent: make(chan *pb.ExecutionHubMessage, 8)}}
			var reader io.Reader = bytes.NewReader(script)
			wantErr := io.ErrClosedPipe
			switch fault {
			case "read-after-prefix":
				reader = &protectedReadFault{data: script[:3], err: io.ErrUnexpectedEOF}
				wantErr = io.ErrUnexpectedEOF
			case "chunk-send":
				stream.fail = func(msg *pb.ExecutionHubMessage) error {
					if msg.GetScriptChunk() != nil {
						return wantErr
					}
					return nil
				}
			case "eof-send":
				stream.fail = func(msg *pb.ExecutionHubMessage) error {
					if msg.GetScriptEof() != nil {
						return wantErr
					}
					return nil
				}
			case "cancel-after-chunk":
				stream.afterSend = func(msg *pb.ExecutionHubMessage) {
					if msg.GetScriptChunk() != nil {
						s.Cancel("revoked")
					}
				}
				wantErr = nil
			case "context-after-chunk":
				stream.afterSend = func(msg *pb.ExecutionHubMessage) {
					if msg.GetScriptChunk() != nil {
						cancel()
					}
				}
				wantErr = context.Canceled
			}
			checked := false
			if err := s.DispatchProtected([]byte("verified receipt"), time.Now().Add(20*time.Second).UnixMilli(), "2", reader, func() error { checked = true; return nil }); err != nil {
				t.Fatal(err)
			}
			err := sendExecution(stream, s)
			if err == nil || (wantErr != nil && !errors.Is(err, wantErr)) {
				t.Fatalf("transfer error: %v want=%v", err, wantErr)
			}
			if checked || s.StartAttempted() {
				t.Fatal("failed transfer reached live launch authority")
			}
			close(stream.sent)
			for msg := range stream.sent {
				if msg.GetStart() != nil {
					t.Fatal("failed transfer emitted Start")
				}
			}
		})
	}
}

func TestExecutionWaitPreparedFailureAndCloneContracts(t *testing.T) {
	for _, fault := range []string{"context", "cancel", "remote-error", "valid-clone"} {
		t.Run(fault, func(t *testing.T) {
			cm := connmgrForExecutionTest()
			control := cm.GetConn("node").Stream
			es := NewExecutionSessions(NewTerminalSessions(), cm)
			es.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "boot"})
			s, err := es.Register("node", fault, "actor", "", []byte("id"))
			if err != nil {
				t.Fatal(err)
			}
			defer es.Remove("node", fault)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := preparedForTest(fault, "node", []byte("id"))
			switch fault {
			case "context":
				cancel()
			case "cancel":
				s.Cancel("revoked")
			case "remote-error":
				p.Error = "secret environment failure"
				es.DeliverPrepared("node", control, p)
			case "valid-clone":
				if !es.DeliverPrepared("node", control, p) {
					t.Fatal("valid preparation rejected")
				}
			}
			got, err := s.WaitPrepared(ctx)
			if fault == "valid-clone" {
				if err != nil || !proto.Equal(got, p) {
					t.Fatalf("preparation: %v %v", got, err)
				}
				got.Binding.NodeId = "changed"
				got.Identity.IdentitySha256[0] ^= 1
				again, err := s.WaitPrepared(ctx)
				if err != nil || !proto.Equal(again, p) {
					t.Fatal("returned preparation aliases retained authority")
				}
			} else if err == nil || got != nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe preparation failure: got=%v err=%v", got, err)
			}
			if fault == "context" && !errors.Is(err, context.Canceled) {
				t.Fatalf("context failure: %v", err)
			}
		})
	}
}

func TestExecutionInputBoundedQueueFailureDoesNotConsumeSequence(t *testing.T) {
	for _, fault := range []string{"context", "cancel", "finished"} {
		t.Run(fault, func(t *testing.T) {
			s := executionReceiveSession(t)
			for i := 0; i < cap(s.stdin); i++ {
				if err := s.SendInput(context.Background(), []byte("queued")); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "context":
				cancel()
			case "cancel":
				s.Cancel("revoked")
			case "finished":
				close(s.transportDone)
			}
			sequence := s.inputSequence
			if err := s.SendInput(ctx, []byte("failed")); err == nil {
				t.Fatal("closed/full queue accepted input")
			} else if fault == "finished" && !errors.Is(err, ErrExecutionInputFinished) {
				t.Fatalf("completion error: %v", err)
			}
			if err := s.CloseInput(ctx); err == nil {
				t.Fatal("closed/full queue accepted EOF")
			}
			if s.inputSequence != sequence || s.inputClosed || len(s.stdin) != cap(s.stdin) {
				t.Fatal("failed enqueue mutated input sequence or queue")
			}
		})
	}
}
