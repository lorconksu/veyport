package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/certs"
	"github.com/wyiu/veyport/agent/internal/execution"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

func TestExecutionNeverFallsBackToBootstrapOrInsecure(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		c := New(Config{HubAddr: "127.0.0.1:1", CertDir: t.TempDir(), Insecure: insecure})
		if conn, err := c.dialExecutionHub(); err == nil {
			conn.Close()
			t.Fatal("execution accepted missing enrolled certificate")
		}
	}
}

type executionTestHub struct {
	pb.UnimplementedAgentServiceServer
	prepared       chan *pb.ExecutionPrepared
	started        chan struct{}
	controlHealthy chan struct{}
	outcome        chan error
	controlAddress chan string
}

func (h *executionTestHub) Connect(stream pb.AgentService_ConnectServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	if msg.GetHeartbeat() == nil {
		return fmt.Errorf("expected heartbeat handshake")
	}
	p, _ := peer.FromContext(stream.Context())
	h.controlAddress <- p.Addr.String()
	if err = stream.Send(&pb.HubMessage{Payload: &pb.HubMessage_HeartbeatAck{HeartbeatAck: &pb.HeartbeatAck{}}}); err != nil {
		return err
	}
	msg, err = stream.Recv()
	if err != nil {
		return err
	}
	caps := msg.GetExecutionCapabilities()
	if caps == nil || !caps.StandardExec || caps.ProtectedScript || caps.BootId == "" {
		return fmt.Errorf("invalid execution capabilities")
	}
	if err = stream.Send(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionPrepare{ExecutionPrepare: &pb.ExecutionPrepare{ExecutionId: "tls-stream", NodeId: "node", Command: "head -c 2097152 /dev/zero; printf problem >&2; exit 42"}}}); err != nil {
		return err
	}
	msg, err = stream.Recv()
	if err != nil {
		return err
	}
	if msg.GetUpdateCapabilities() != nil {
		msg, err = stream.Recv()
		if err != nil {
			return err
		}
	}
	prepared := msg.GetExecutionPrepared()
	if prepared == nil || prepared.Error != "" || prepared.Binding.BootId != caps.BootId {
		return fmt.Errorf("invalid prepared response")
	}
	h.prepared <- prepared
	if err = stream.Send(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionAttach{ExecutionAttach: &pb.ExecutionAttachRequest{Binding: prepared.Binding, Ticket: bytes.Repeat([]byte{1}, 32)}}}); err != nil {
		return err
	}
	select {
	case <-h.started:
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	// Execution output is blocked at this point; ordinary control still works.
	if err = stream.Send(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionStatusRequest{ExecutionStatusRequest: &pb.ExecutionStatusRequest{ExecutionId: prepared.ExecutionId}}}); err != nil {
		return err
	}
	for {
		msg, err = stream.Recv()
		if err != nil {
			return err
		}
		if status := msg.GetExecutionStatus(); status != nil {
			if status.State != "running" {
				return fmt.Errorf("status while output blocked: %s", status.State)
			}
			close(h.controlHealthy)
			break
		}
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}
func (h *executionTestHub) Execute(stream pb.AgentService_ExecuteServer) (returnErr error) {
	defer func() { h.outcome <- returnErr }()
	p, _ := peer.FromContext(stream.Context())
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || tlsInfo.State.PeerCertificates[0].Subject.CommonName != "node" {
		return fmt.Errorf("execution not authenticated")
	}
	controlAddress := <-h.controlAddress
	if p.Addr.String() == controlAddress {
		return fmt.Errorf("execution reused control connection")
	}
	prepared := <-h.prepared
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	if msg.GetAttach() == nil {
		return fmt.Errorf("attach required")
	}
	if err = stream.Send(&pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_Attached{Attached: &pb.ExecutionAttached{Binding: prepared.Binding}}}); err != nil {
		return err
	}
	if err = stream.Send(&pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_Start{Start: &pb.ExecutionStart{Binding: prepared.Binding, CommandSha256: prepared.CommandSha256, IdentitySha256: prepared.Identity.IdentitySha256, Limits: prepared.Limits, PolicyVersion: "standard"}}}); err != nil {
		return err
	}
	msg, err = stream.Recv()
	if err != nil {
		return err
	}
	if msg.GetStarted() == nil {
		return fmt.Errorf("actual start missing: %T", msg.Payload)
	}
	close(h.started)
	select {
	case <-h.controlHealthy:
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	if err = stream.Send(&pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_InputEof{InputEof: &pb.ExecutionInputEOF{Sequence: 0}}}); err != nil {
		return err
	}
	var stdoutBytes int
	var stderr bytes.Buffer
	var outSeq, errSeq uint64
	var stdoutEOF, stderrEOF bool
	for {
		msg, err = stream.Recv()
		if err != nil {
			return err
		}
		if data := msg.GetStdout(); data != nil {
			if data.Sequence != outSeq || len(data.Data) > 65536 {
				return fmt.Errorf("stdout integrity")
			}
			outSeq++
			stdoutBytes += len(data.Data)
			for _, value := range data.Data {
				if value != 0 {
					return fmt.Errorf("binary data changed")
				}
			}
		}
		if data := msg.GetStderr(); data != nil {
			if data.Sequence != errSeq {
				return fmt.Errorf("stderr sequence")
			}
			errSeq++
			stderr.Write(data.Data)
		}
		if eof := msg.GetOutputEof(); eof != nil {
			if eof.Output == pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT {
				stdoutEOF = eof.Sequence == outSeq
			} else {
				stderrEOF = eof.Sequence == errSeq
			}
		}
		if result := msg.GetResult(); result != nil {
			if stdoutBytes != 2097152 || stderr.String() != "problem" || !stdoutEOF || !stderrEOF || !result.StdoutComplete || !result.StderrComplete || result.State != "exited" || result.ExitCode != 42 {
				return fmt.Errorf("final integrity: bytes=%d stderr=%q result=%+v", stdoutBytes, stderr.String(), result)
			}
			return nil
		}
	}
}
func TestSeparateMTLSExecutionConnectionPreservesControlAndBinaryOutput(t *testing.T) {
	tlsCfg, store := executionTestTLS(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	hub := &executionTestHub{prepared: make(chan *pb.ExecutionPrepared, 1), started: make(chan struct{}), controlHealthy: make(chan struct{}), outcome: make(chan error, 1), controlAddress: make(chan string, 1)}
	pb.RegisterAgentServiceServer(server, hub)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	c := New(Config{HubAddr: listener.Addr().String(), ServerID: "node", CertDir: t.TempDir(), DropzoneDir: t.TempDir()})
	c.certStore = store
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientDone := make(chan error, 1)
	go func() { clientDone <- c.connectAndStream(ctx) }()
	select {
	case err = <-hub.outcome:
		if err != nil {
			t.Fatal(err)
		}
	case err = <-clientDone:
		t.Fatalf("control failed: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	select {
	case <-clientDone:
	case <-time.After(2 * time.Second):
		t.Fatal("execution connection leaked after control loss")
	}
}
func executionTestTLS(t *testing.T) (*tls.Config, *certs.Store) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	store := certs.NewMemoryStore()
	csrDER, err := store.GenerateCSR("node")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: csr.Subject, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca, csr.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.StoreCert(clientDER, caDER); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, store
}

func TestExecutionControlBackpressureCancelsInsteadOfBlockingCancellation(t *testing.T) {
	journal, err := execution.OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := execution.NewManager(execution.Config{NodeID: "node", Journal: journal})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	controlCtx, cancelControl := context.WithCancel(context.Background())
	defer cancelControl()
	e := &executionTransport{ctx: ctx, cancel: cancel, manager: manager, responses: make(chan *pb.AgentMessage, 1), controlCancel: cancelControl}
	e.send(&pb.AgentMessage{})
	e.send(&pb.AgentMessage{})
	if ctx.Err() == nil || controlCtx.Err() == nil {
		t.Fatal("control overload did not close both transports")
	}
	e.close()
	if !e.closed {
		t.Fatal("execution transport not closed")
	}
	if !e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionPrepare{ExecutionPrepare: &pb.ExecutionPrepare{ExecutionId: "after-close", NodeId: "node", Command: "exit 0"}}}) {
		t.Fatal("closed execution request escaped handler")
	}
	if manager.Status("after-close").State != "not_found" {
		t.Fatal("closed transport started preparation")
	}
}

type mockExecutionStream struct {
	ctx         context.Context
	recv        []*pb.ExecutionHubMessage
	sent        []*pb.ExecutionAgentMessage
	sendErr     error
	recvErr     error
	blockedSend bool
}

func (m *mockExecutionStream) Header() (metadata.MD, error) { return nil, nil }
func (m *mockExecutionStream) Trailer() metadata.MD         { return nil }
func (m *mockExecutionStream) CloseSend() error             { return nil }
func (m *mockExecutionStream) Context() context.Context     { return m.ctx }
func (m *mockExecutionStream) SendMsg(any) error            { return nil }
func (m *mockExecutionStream) RecvMsg(any) error            { return nil }
func (m *mockExecutionStream) Send(msg *pb.ExecutionAgentMessage) error {
	if m.blockedSend {
		<-m.ctx.Done()
		return m.ctx.Err()
	}
	m.sent = append(m.sent, msg)
	return m.sendErr
}
func (m *mockExecutionStream) Recv() (*pb.ExecutionHubMessage, error) {
	if len(m.recv) == 0 {
		if m.recvErr != nil {
			return nil, m.recvErr
		}
		return nil, io.EOF
	}
	msg := m.recv[0]
	m.recv = m.recv[1:]
	return msg, nil
}

type mockExecutionService struct {
	pb.AgentServiceClient
	stream *mockExecutionStream
}

func (m mockExecutionService) Connect(context.Context, ...grpc.CallOption) (pb.AgentService_ConnectClient, error) {
	return nil, errors.New("control unused")
}
func (m mockExecutionService) Execute(ctx context.Context, _ ...grpc.CallOption) (pb.AgentService_ExecuteClient, error) {
	m.stream.ctx = ctx
	return m.stream, nil
}
func TestExecutionHandshakeFaultsNeverLaunch(t *testing.T) {
	for _, fault := range []string{"send", "recv", "attached", "missing_start", "wrong_start", "wrong_hash", "expired"} {
		t.Run(fault, func(t *testing.T) {
			journal, err := execution.OpenJournal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			manager, err := execution.NewManager(execution.Config{NodeID: "node", Journal: journal})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			prepared := manager.Prepare(&pb.ExecutionPrepare{ExecutionId: fault, NodeId: "node", Command: "exit 0"})
			if prepared.Error != "" {
				t.Fatal(prepared.Error)
			}
			binding := proto.Clone(prepared.Binding).(*pb.ExecutionBinding)
			stream := &mockExecutionStream{recv: []*pb.ExecutionHubMessage{{Payload: &pb.ExecutionHubMessage_Attached{Attached: &pb.ExecutionAttached{Binding: binding}}}, {Payload: &pb.ExecutionHubMessage_Start{Start: &pb.ExecutionStart{Binding: binding, CommandSha256: prepared.CommandSha256, IdentitySha256: prepared.Identity.IdentitySha256, Limits: prepared.Limits}}}}}
			attach := &pb.ExecutionAttachRequest{Binding: prepared.Binding, Ticket: bytes.Repeat([]byte{1}, 32)}
			switch fault {
			case "send":
				stream.sendErr = io.ErrClosedPipe
			case "recv":
				stream.recv = nil
				stream.recvErr = io.ErrUnexpectedEOF
			case "attached":
				stream.recv[0].GetAttached().Binding = &pb.ExecutionBinding{ExecutionId: "other"}
			case "missing_start":
				stream.recv[1] = &pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_InputEof{InputEof: &pb.ExecutionInputEOF{}}}
			case "wrong_start":
				stream.recv[1].GetStart().Binding = &pb.ExecutionBinding{ExecutionId: "other"}
			case "wrong_hash":
				stream.recv[1].GetStart().CommandSha256 = []byte("wrong")
			case "expired":
				attach.Binding = proto.Clone(prepared.Binding).(*pb.ExecutionBinding)
				attach.Binding.ExpiresUnixMilli = time.Now().Add(-time.Second).UnixMilli()
			}
			e := &executionTransport{ctx: context.Background(), manager: manager, client: mockExecutionService{stream: stream}}
			if err = e.serve(attach); err == nil {
				t.Fatal("invalid handshake accepted")
			}
			if manager.Status(fault).State != "prepared" {
				t.Fatalf("handshake launched: %+v", manager.Status(fault))
			}
			if fault == "wrong_hash" {
				if len(stream.sent) != 2 || stream.sent[1].GetStartFailed() == nil || stream.sent[1].GetStartFailed().State != "launch_failed" {
					t.Fatal("binding denial missing")
				}
			}
		})
	}
}
func TestBlockedExecutionSendDeadlineCancelsItsStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &mockExecutionStream{ctx: ctx, blockedSend: true}
	if err := sendExecutionMessage(stream, cancel, &pb.ExecutionAgentMessage{}, 15*time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked send: %v", err)
	}
}
func TestUnexpectedProtectedScriptCancelsOrdinaryExecution(t *testing.T) {
	journal, err := execution.OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := execution.NewManager(execution.Config{NodeID: "node", Journal: journal, TermGrace: 15 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	prepared := manager.Prepare(&pb.ExecutionPrepare{ExecutionId: "no-script", NodeId: "node", Command: "cat"})
	run, err := manager.Start(context.Background(), &pb.ExecutionStart{Binding: prepared.Binding, CommandSha256: prepared.CommandSha256, IdentitySha256: prepared.Identity.IdentitySha256, Limits: prepared.Limits})
	if err != nil {
		t.Fatal(err)
	}
	stream := &mockExecutionStream{ctx: context.Background(), recv: []*pb.ExecutionHubMessage{{Payload: &pb.ExecutionHubMessage_ScriptChunk{ScriptChunk: &pb.ExecutionScriptChunk{Data: []byte("forbidden")}}}}}
	if err = receiveExecutionInput(stream, run, prepared.Binding); err != io.EOF {
		t.Fatal(err)
	}
	select {
	case <-run.Done():
	case <-time.After(time.Second):
		t.Fatal("invalid script did not cancel")
	}
	status := manager.Status(prepared.ExecutionId)
	if status.State != "cancelled" || status.Result.Reason != "invalid_execution_input" {
		t.Fatalf("invalid script result: %+v", status)
	}
}
