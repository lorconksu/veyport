package grpcserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func authorityPreparedSession(t *testing.T) (*ExecutionSessions, *ExecutionSession) {
	t.Helper()
	cm := connmgrForExecutionTest()
	control := cm.GetConn("node").Stream
	es := NewExecutionSessions(nil, cm)
	es.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, ProtectedScript: true, BootId: "boot"})
	s, err := es.Register("node", "authority", "actor", "", []byte("id"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { es.Remove("node", s.ID) })
	if !es.DeliverPrepared("node", control, preparedForTest(s.ID, "node", []byte("id"))) {
		t.Fatal("valid preparation rejected")
	}
	return es, s
}

func TestExecutionRegistrationRefusalsPreserveExistingAuthorityAndCapacity(t *testing.T) {
	es, s := authorityPreparedSession(t)
	for _, submission := range []struct {
		node, id, actor string
		command         []byte
	}{
		{"node", "", "actor", []byte("id")},
		{"node", "invalid", "actor", []byte{'i', 0, 'd'}},
		{"node", "invalid", "actor", []byte{255}},
		{"node", "invalid", "actor", bytes.Repeat([]byte{'x'}, MaxExecutionCommandBytes+1)},
		{"absent", "unsupported", "actor", []byte("id")},
		{"node", s.ID, "another-actor", []byte("different command")},
	} {
		if got, err := es.Register(submission.node, submission.id, submission.actor, "", submission.command); err == nil || got != nil {
			t.Fatal("invalid or duplicate registration acquired authority")
		}
	}
	if len(es.sessions) != 1 || es.sessions[makeKey("node", s.ID)] != s || len(es.terminals.ListByUser("actor")) != 1 {
		t.Fatal("refused registration replaced authority or consumed capacity")
	}
	if es.DeliverPrepared("node", s.connection.Stream, nil) || es.DeliverPrepared("node", s.connection.Stream, preparedForTest(s.ID, "node", []byte("id"))) {
		t.Fatal("duplicate or missing preparation replaced the retained binding")
	}
	if _, err := s.WaitPrepared(context.Background()); err != nil {
		t.Fatal("refusal destroyed the original usable preparation:", err)
	}
}

func TestWithdrawnExecutionCapabilityCannotAttachOrLaunchPreparedWork(t *testing.T) {
	es, s := authorityPreparedSession(t)
	attach, err := s.IssueAttach()
	if err != nil {
		t.Fatal(err)
	}
	// A stale generation must not withdraw the live connection's capability.
	es.SetCapabilities("node", &mockStream{}, nil)
	if !es.SupportsProtected("node") {
		t.Fatal("stale capability publication changed the current generation")
	}
	es.SetCapabilities("node", s.connection.Stream, nil)
	if es.Supports("node") || es.SupportsProtected("node") {
		t.Fatal("withdrawn capability retained execution authority")
	}
	if _, err := es.Attach("node", attach); err == nil || s.ticketUsed {
		t.Fatal("withdrawn capability consumed an attachment ticket")
	}
	if _, err := es.Register("node", "new", "actor", "", []byte("id")); !errors.Is(err, ErrExecutionUnsupported) {
		t.Fatal("withdrawn capability accepted new work:", err)
	}
	select {
	case <-s.Done:
	default:
		t.Fatal("capability withdrawal did not cancel prepared work")
	}
	if len(s.start) != 0 || s.StartAttempted() {
		t.Fatal("withdrawal fabricated a Start attempt")
	}
}

func TestCancelledExecutionAttachmentAndDispatchCannotConsumeStart(t *testing.T) {
	t.Run("closed-control-before-attach", func(t *testing.T) {
		es, s := authorityPreparedSession(t)
		attach, err := s.IssueAttach()
		if err != nil {
			t.Fatal(err)
		}
		s.connection.Close()
		if _, err := es.Attach("node", attach); err == nil || s.ticketUsed {
			t.Fatal("closed control connection consumed a ticket")
		}
	})
	t.Run("cancelled-standard-dispatch", func(t *testing.T) {
		es, s := authorityPreparedSession(t)
		attach, err := s.IssueAttach()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := es.Attach("node", attach); err != nil {
			t.Fatal(err)
		}
		s.Cancel("authority revoked before launch")
		if err := s.Dispatch(); err == nil || s.dispatch || s.StartAttempted() || len(s.start) != 0 {
			t.Fatal("cancelled Standard preparation became dispatched")
		}
	})
	t.Run("cancelled-protected-dispatch", func(t *testing.T) {
		script := []byte("true\n")
		s := protectedSession(t, script)
		s.Cancel("authority revoked before launch")
		if err := s.DispatchProtected([]byte("hub-verified receipt"), time.Now().Add(time.Second).UnixMilli(), "2", bytes.NewReader(script), func() error { return nil }); err == nil || s.dispatch || s.StartAttempted() || len(s.start) != 0 {
			t.Fatal("cancelled protected preparation became dispatched")
		}
	})
}

func TestExecutionInputRejectionPreservesExactSequenceAndSingleEOF(t *testing.T) {
	s := executionReceiveSession(t)
	if err := s.Configure(true, nil, 0, DefaultExecutionLimits()); err == nil {
		t.Fatal("prepared identity and limits were reconfigured")
	}
	if err := s.SendInput(context.Background(), make([]byte, MaxExecutionFrameBytes+1)); err == nil || s.inputSequence != 0 || len(s.stdin) != 0 {
		t.Fatal("oversize input consumed a sequence or queue slot")
	}
	if err := s.CloseInput(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseInput(context.Background()); err != nil || len(s.stdin) != 1 {
		t.Fatal("idempotent stdin closure emitted another EOF")
	}
	if err := s.SendInput(context.Background(), []byte("late input")); err == nil || s.inputSequence != 0 || len(s.stdin) != 1 {
		t.Fatal("input after EOF changed the bounded queue")
	}
	if eof := (<-s.stdin).GetInputEof(); eof == nil || eof.Sequence != 0 {
		t.Fatal("closure lost the exact input sequence")
	}
}

func TestExecutionMalformedEOFAndOutputCancellationCannotPublishSuccess(t *testing.T) {
	for _, phase := range []string{"before-start", "duplicate-stdout", "stdout-sequence", "blocked-output-cancelled"} {
		t.Run(phase, func(t *testing.T) {
			s := executionReceiveSession(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			frames := []*pb.ExecutionAgentMessage{executionStartedFrame(s)}
			want := codes.DataLoss
			switch phase {
			case "before-start":
				frames = []*pb.ExecutionAgentMessage{executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT)}
			case "duplicate-stdout":
				frames = append(frames, executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT), executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT))
			case "stdout-sequence":
				eof := executionEOFFrame(pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT)
				eof.GetOutputEof().Sequence = 1
				frames = append(frames, eof)
			case "blocked-output-cancelled":
				for range cap(s.stdout) {
					s.stdout <- []byte("bounded queued output")
				}
				cancel()
				frames = append(frames, &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Stdout{Stdout: &pb.ExecutionData{Data: []byte("undelivered output")}}})
				want = codes.Unknown
			}
			err := receiveExecution(&executionTestStream{ctx: ctx, messages: frames}, s)
			if status.Code(err) != want || phase == "blocked-output-cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("invalid completion error=%v want=%v", err, want)
			}
			select {
			case result := <-s.Result:
				t.Fatalf("malformed/incomplete delivery published a result: %+v", result)
			default:
			}
		})
	}
}

func TestExecutionFailureReasonsRemainRedactedAndOutcomeTruthful(t *testing.T) {
	for _, state := range []string{"launch_failed", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			s := executionReceiveSession(t)
			frames := []*pb.ExecutionAgentMessage{{Payload: &pb.ExecutionAgentMessage_StartFailed{StartFailed: &pb.ExecutionStartFailed{Binding: s.Binding(), State: state, Reason: "PRIVATE_REMOTE_COMMAND_CANARY"}}}}
			if err := receiveExecution(&executionTestStream{messages: frames}, s); err != nil {
				t.Fatal(err)
			}
			result := <-s.Result
			if result.State != state || result.Reason != "agent reported "+state {
				t.Fatal("start failure lost its truthful redacted classification")
			}
			if _, ok := <-s.Stdout; ok {
				t.Fatal("failed launch retained an output stream")
			}
		})
	}
	for _, reason := range []string{"completion not durable", "PRIVATE_REMOTE_COMMAND_CANARY"} {
		t.Run(reason, func(t *testing.T) {
			s := executionReceiveSession(t)
			frames := executionFinalFrames(s, &pb.ExecutionResult{Binding: s.Binding(), State: "exited", ExitCode: 42, StdoutComplete: true, StderrComplete: true, Reason: reason})
			if err := receiveExecution(&executionTestStream{messages: frames}, s); err != nil {
				t.Fatal(err)
			}
			result := <-s.Result
			want := "agent reported exited"
			if reason == "completion not durable" {
				want = "completion metadata unconfirmed"
			}
			if result.ExitCode != 42 || result.State != "exited" || result.Reason != want {
				t.Fatal("redaction changed the real process outcome or hid its durability gap")
			}
		})
	}
}

func TestExecutionCertificateWithoutNodeIdentityCannotAcquireAuthority(t *testing.T) {
	h, _ := testHandler(t)
	certificate := &x509.Certificate{NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute)}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}}})
	if node, err := h.executionNode(ctx); node != "" || status.Code(err) != codes.Unauthenticated {
		t.Fatal("verified certificate without a node identity acquired execution authority")
	}
}
