package grpcserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type executionTestStream struct {
	ctx      context.Context
	messages []*pb.ExecutionAgentMessage
	sent     chan *pb.ExecutionHubMessage
}

func (s *executionTestStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}
func (s *executionTestStream) Recv() (*pb.ExecutionAgentMessage, error) {
	if len(s.messages) == 0 {
		return nil, io.EOF
	}
	m := s.messages[0]
	s.messages = s.messages[1:]
	return m, nil
}
func (s *executionTestStream) Send(message *pb.ExecutionHubMessage) error {
	if s.sent != nil {
		s.sent <- message
	}
	return nil
}
func (s *executionTestStream) SendMsg(interface{}) error    { return nil }
func (s *executionTestStream) RecvMsg(interface{}) error    { return nil }
func (s *executionTestStream) SetHeader(metadata.MD) error  { return nil }
func (s *executionTestStream) SendHeader(metadata.MD) error { return nil }
func (s *executionTestStream) SetTrailer(metadata.MD)       {}

func TestExecutionRPCRequiresVerifiedCurrentEnrolledCertificate(t *testing.T) {
	h, st := testHandler(t)
	if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	h.connMgr.Register("node", &mockStream{})
	cert := &x509.Certificate{Raw: []byte("node"), Subject: pkix.Name{CommonName: "node"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	for _, test := range []struct {
		name  string
		state *tls.ConnectionState
		want  codes.Code
	}{
		{"missing-peer", nil, codes.Unauthenticated},
		{"enrollment-without-cert", &tls.ConnectionState{}, codes.Unauthenticated},
		{"unverified-cert", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, codes.Unauthenticated},
		{"verified", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}, codes.OK},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.state != nil {
				ctx = peer.NewContext(ctx, &peer.Peer{AuthInfo: credentials.TLSInfo{State: *test.state}})
			}
			node, err := h.executionNode(ctx)
			if status.Code(err) != test.want {
				t.Fatalf("node=%q err=%v wantcode=%v", node, err, test.want)
			}
		})
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}}})
	if err := st.UpdateServerStatus("node", "offline"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.executionNode(ctx); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("offline enrolled node accepted: %v", err)
	}
	if err := st.UpdateServerStatus("node", "online"); err != nil {
		t.Fatal(err)
	}
	h.connMgr.GetConn("node").Close()
	if _, err := h.executionNode(ctx); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("closed control generation accepted before disconnect cleanup: %v", err)
	}
}

func executionReceiveSession(t *testing.T) *ExecutionSession {
	t.Helper()
	cm := connmgrForExecutionTest()
	control := cm.GetConn("node").Stream
	es := NewExecutionSessions(NewTerminalSessions(), cm)
	es.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "boot"})
	s, err := es.Register("node", "exec", "actor", "", []byte("id"))
	if err != nil {
		t.Fatal(err)
	}
	if !es.DeliverPrepared("node", control, preparedForTest("exec", "node", []byte("id"))) {
		t.Fatal("prepare failed")
	}
	a, err := s.IssueAttach()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = es.Attach("node", a); err != nil {
		t.Fatal(err)
	}
	if err = s.Dispatch(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { es.Remove("node", "exec") })
	return s
}

func connmgrForExecutionTest() *connmgr.ConnManager {
	cm := connmgr.New()
	cm.Register("node", &mockStream{})
	return cm
}

func TestExecutionOutputSequenceAndCompleteResult(t *testing.T) {
	for _, test := range []struct {
		name                                  string
		wrongSequence, missingEOF, incomplete bool
	}{
		{"valid", false, false, false}, {"gap", true, false, false}, {"missing-stderr-eof", false, true, false}, {"incomplete-success", false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := executionReceiveSession(t)
			seq := uint64(0)
			if test.wrongSequence {
				seq = 1
			}
			messages := []*pb.ExecutionAgentMessage{{Payload: &pb.ExecutionAgentMessage_Started{Started: &pb.ExecutionStarted{Binding: s.Binding()}}}, {Payload: &pb.ExecutionAgentMessage_Stdout{Stdout: &pb.ExecutionData{Sequence: seq, Data: []byte{0, 255}}}}, {Payload: &pb.ExecutionAgentMessage_OutputEof{OutputEof: &pb.ExecutionOutputEOF{Output: pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT, Sequence: 1}}}}
			if !test.missingEOF {
				messages = append(messages, &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_OutputEof{OutputEof: &pb.ExecutionOutputEOF{Output: pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR, Sequence: 0}}})
			}
			messages = append(messages, &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Result{Result: &pb.ExecutionResult{Binding: s.Binding(), State: "exited", ExitCode: 42, StdoutComplete: !test.incomplete, StderrComplete: true}}})
			err := receiveExecution(&executionTestStream{messages: messages}, s)
			if test.name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				result := <-s.Result
				if result.ExitCode != 42 {
					t.Fatal("exit changed")
				}
				select {
				case <-s.Done:
					t.Fatal("valid result cancelled before relay drain")
				default:
				}
			} else if err == nil {
				t.Fatal("invalid output accepted")
			}
		})
	}
}

func TestExecutionPostSpawnJournalFailurePreservesUnknownOutcome(t *testing.T) {
	s := executionReceiveSession(t)
	err := receiveExecution(&executionTestStream{messages: []*pb.ExecutionAgentMessage{{Payload: &pb.ExecutionAgentMessage_StartFailed{StartFailed: &pb.ExecutionStartFailed{Binding: s.Binding(), State: "outcome_unknown", Reason: "SECRET_COMMAND_CANARY"}}}}}, s)
	if err != nil {
		t.Fatal(err)
	}
	result := <-s.Result
	if result.State != "outcome_unknown" || result.Reason == "SECRET_COMMAND_CANARY" {
		t.Fatalf("unsafe outcome: %+v", result)
	}
}

func TestExecutionResultValidatesProcessExitRepresentation(t *testing.T) {
	for _, test := range []struct {
		name   string
		code   int32
		signal string
		valid  bool
	}{
		{"zero", 0, "", true},
		{"native-255", 255, "", true},
		{"signalled", -1, syscall.SIGTERM.String(), true},
		{"negative-without-signal", -1, "", false},
		{"negative-invalid-signal", -1, "SECRET_COMMAND_CANARY", false},
		{"negative-out-of-range", -2, syscall.SIGTERM.String(), false},
		{"positive-out-of-range", 256, "", false},
		{"contradictory-signal", 0, syscall.SIGTERM.String(), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := executionReceiveSession(t)
			messages := []*pb.ExecutionAgentMessage{
				{Payload: &pb.ExecutionAgentMessage_Started{Started: &pb.ExecutionStarted{Binding: s.Binding()}}},
				{Payload: &pb.ExecutionAgentMessage_OutputEof{OutputEof: &pb.ExecutionOutputEOF{Output: pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT}}},
				{Payload: &pb.ExecutionAgentMessage_OutputEof{OutputEof: &pb.ExecutionOutputEOF{Output: pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR}}},
				{Payload: &pb.ExecutionAgentMessage_Result{Result: &pb.ExecutionResult{Binding: s.Binding(), State: "exited", ExitCode: test.code, Signal: test.signal, StdoutComplete: true, StderrComplete: true}}},
			}
			err := receiveExecution(&executionTestStream{messages: messages}, s)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
}

func TestExecutionSenderStopsAfterSuccessfulTransportCompletion(t *testing.T) {
	s := executionReceiveSession(t)
	stream := &executionTestStream{sent: make(chan *pb.ExecutionHubMessage, 2)}
	done := make(chan error, 1)
	go func() { done <- sendExecution(stream, s) }()
	for range 2 {
		select {
		case <-stream.sent:
		case <-time.After(time.Second):
			t.Fatal("sender did not attach and start")
		}
	}
	close(s.transportDone)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("successful transport completion retained the stdin sender")
	}
}
