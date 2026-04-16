package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/aerodocs/agent/internal/certs"
	"github.com/wyiu/aerodocs/agent/internal/dropzone"
	pb "github.com/wyiu/aerodocs/proto/aerodocs/v1"
	"google.golang.org/grpc/metadata"
)

const (
	testHubAddr                = "localhost:9090"
	testExpectedFileDeleteResp = "expected FileDeleteResponse"
	testExpectedRespOnSendCh   = "expected response on sendCh"
	testSessionID              = "session-1"
	testExpectedAckOnSendCh    = "expected ack on sendCh"
	testReqList                = "req-list"
	testReqLog                 = "req-log"
	testHubHostName            = "hub.example.com"
)

// newTestDropzone creates a Dropzone using a test directory.
func newTestDropzone(dir string) *dropzone.Dropzone {
	return dropzone.New(dir)
}

func TestNextBackoff(t *testing.T) {
	c := &Client{
		backoff:    1 * time.Second,
		maxBackoff: 60 * time.Second,
	}
	b1 := c.nextBackoff()
	if b1 != 1*time.Second {
		t.Fatalf("expected 1s, got %v", b1)
	}
	b2 := c.nextBackoff()
	if b2 != 2*time.Second {
		t.Fatalf("expected 2s, got %v", b2)
	}
	b3 := c.nextBackoff()
	if b3 != 4*time.Second {
		t.Fatalf("expected 4s, got %v", b3)
	}
}

func TestNextBackoff_CapsAtMax(t *testing.T) {
	c := &Client{
		backoff:    32 * time.Second,
		maxBackoff: 60 * time.Second,
	}
	b1 := c.nextBackoff()
	if b1 != 32*time.Second {
		t.Fatalf("expected 32s, got %v", b1)
	}
	b2 := c.nextBackoff()
	if b2 != 60*time.Second {
		t.Fatalf("expected 60s (capped), got %v", b2)
	}
}

func TestResetBackoff(t *testing.T) {
	c := &Client{
		backoff:    16 * time.Second,
		maxBackoff: 60 * time.Second,
	}
	c.resetBackoff()
	b := c.nextBackoff()
	if b != 1*time.Second {
		t.Fatalf("expected 1s after reset, got %v", b)
	}
}

func TestNewClient(t *testing.T) {
	c := New(Config{
		HubAddr:  testHubAddr,
		ServerID: "srv-1",
	})
	if c.hubAddr != testHubAddr {
		t.Fatalf("expected hubAddr 'localhost:9090', got '%s'", c.hubAddr)
	}
	if c.serverID != "srv-1" {
		t.Fatalf("expected serverID 'srv-1', got '%s'", c.serverID)
	}
}

func TestServerID(t *testing.T) {
	c := New(Config{ServerID: "my-server"})
	if c.ServerID() != "my-server" {
		t.Fatalf("expected 'my-server', got '%s'", c.ServerID())
	}
}

type mockConnectClientStream struct {
	ctx  context.Context
	sent []*pb.AgentMessage
	recv []*pb.HubMessage
}

func (m *mockConnectClientStream) Header() (metadata.MD, error) { return nil, nil }
func (m *mockConnectClientStream) Trailer() metadata.MD         { return nil }
func (m *mockConnectClientStream) CloseSend() error             { return nil }
func (m *mockConnectClientStream) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}
func (m *mockConnectClientStream) SendMsg(interface{}) error { return nil }
func (m *mockConnectClientStream) RecvMsg(interface{}) error { return nil }
func (m *mockConnectClientStream) Send(msg *pb.AgentMessage) error {
	m.sent = append(m.sent, msg)
	return nil
}
func (m *mockConnectClientStream) Recv() (*pb.HubMessage, error) {
	if len(m.recv) == 0 {
		return nil, io.EOF
	}
	msg := m.recv[0]
	m.recv = m.recv[1:]
	return msg, nil
}

func TestUseTLS(t *testing.T) {
	// useTLS now defaults to true, false only when insecure flag is set
	t.Run("default_true", func(t *testing.T) {
		c := &Client{hubAddr: testHubAddr}
		if !c.useTLS() {
			t.Fatal("useTLS should default to true")
		}
	})
	t.Run("insecure_false", func(t *testing.T) {
		c := &Client{hubAddr: testHubAddr, insecure: true}
		if c.useTLS() {
			t.Fatal("useTLS should be false when insecure=true")
		}
	})
}

func TestBootstrapTLSConfig_RequiresCAPin(t *testing.T) {
	c := &Client{hubAddr: testHubAddr}
	if _, err := c.bootstrapTLSConfig(); err == nil {
		t.Fatal("expected bootstrap TLS config to require a CA pin")
	}
}

func TestVerifyPinnedHubCertificate(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Hub CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: testHubHostName},
		DNSNames:     []string{testHubHostName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	pin := sha256.Sum256(caCert.Raw)
	if err := verifyPinnedHubCertificate([][]byte{serverDER, caCert.Raw}, pin[:], testHubHostName); err != nil {
		t.Fatalf("verify pinned hub certificate: %v", err)
	}
	if err := verifyPinnedHubCertificate([][]byte{serverDER, caCert.Raw}, pin[:], "other.example.com"); err == nil {
		t.Fatal("expected hostname mismatch to fail")
	}
}

func TestSendRegister_RequiresReconnectForMTLS(t *testing.T) {
	c := New(Config{
		HubAddr:  testHubAddr,
		Token:    "reg-token",
		Hostname: "host1",
		CertDir:  t.TempDir(),
	})
	stream := &mockConnectClientStream{
		recv: []*pb.HubMessage{
			{
				Payload: &pb.HubMessage_RegisterAck{
					RegisterAck: &pb.RegisterAck{
						Success:  true,
						ServerId: "srv-1",
					},
				},
			},
		},
	}

	bootstrapRegistered, err := c.sendRegister(stream)
	if err != nil {
		t.Fatalf("sendRegister: %v", err)
	}
	if !bootstrapRegistered {
		t.Fatal("expected successful registration to require an mTLS reconnect")
	}
	if c.serverID != "srv-1" {
		t.Fatalf("expected server ID to be recorded, got %q", c.serverID)
	}
	if len(stream.sent) != 1 || stream.sent[0].GetRegister() == nil {
		t.Fatal("expected a RegisterAgent message to be sent")
	}
}

func TestSendRegister_InvokesOnRegisteredCallback(t *testing.T) {
	var gotServerID string
	c := New(Config{
		HubAddr:  testHubAddr,
		Token:    "reg-token",
		Hostname: "host1",
		CertDir:  t.TempDir(),
		OnRegistered: func(serverID string) {
			gotServerID = serverID
		},
	})
	stream := &mockConnectClientStream{
		recv: []*pb.HubMessage{
			{
				Payload: &pb.HubMessage_RegisterAck{
					RegisterAck: &pb.RegisterAck{
						Success:  true,
						ServerId: "srv-callback",
					},
				},
			},
		},
	}

	bootstrapRegistered, err := c.sendRegister(stream)
	if err != nil {
		t.Fatalf("sendRegister: %v", err)
	}
	if !bootstrapRegistered {
		t.Fatal("expected successful registration to require an mTLS reconnect")
	}
	if gotServerID != "srv-callback" {
		t.Fatalf("expected OnRegistered callback to receive %q, got %q", "srv-callback", gotServerID)
	}
}

func TestHandleFileDeleteRequest_OutsideDropzone(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{}), dropzone: dropzone.New(t.TempDir())}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage_FileDeleteRequest{
		FileDeleteRequest: &pb.FileDeleteRequest{
			RequestId: "req-1",
			Path:      "/etc/passwd",
		},
	}
	c.handleFileDeleteRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		ack := resp.GetFileDeleteResponse()
		if ack == nil {
			t.Fatal(testExpectedFileDeleteResp)
		}
		if ack.Success {
			t.Fatal("expected failure for path outside dropzone")
		}
		if ack.Error == "" {
			t.Fatal("expected error message")
		}
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

func TestHandleFileDeleteRequest_NonexistentFile(t *testing.T) {
	dropzoneDir := t.TempDir()
	c := &Client{tailSessions: make(map[string]chan struct{}), dropzone: dropzone.New(dropzoneDir)}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage_FileDeleteRequest{
		FileDeleteRequest: &pb.FileDeleteRequest{
			RequestId: "req-1",
			Path:      filepath.Join(dropzoneDir, "nonexistent-file.txt"),
		},
	}
	c.handleFileDeleteRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		ack := resp.GetFileDeleteResponse()
		if ack == nil {
			t.Fatal(testExpectedFileDeleteResp)
		}
		if ack.Success {
			t.Fatal("expected failure for nonexistent file")
		}
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

func TestHandleFileDeleteRequest_Success(t *testing.T) {
	dropzoneDir := t.TempDir()
	testFile := filepath.Join(dropzoneDir, "test-delete-file.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	c := &Client{tailSessions: make(map[string]chan struct{}), dropzone: dropzone.New(dropzoneDir)}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage_FileDeleteRequest{
		FileDeleteRequest: &pb.FileDeleteRequest{
			RequestId: "req-del",
			Path:      testFile,
		},
	}
	c.handleFileDeleteRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		ack := resp.GetFileDeleteResponse()
		if ack == nil {
			t.Fatal(testExpectedFileDeleteResp)
		}
		if !ack.Success {
			t.Fatalf("expected success, got error: %s", ack.Error)
		}
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

func TestHandleLogStreamStop_ExistingSession(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{})}
	stop := make(chan struct{})
	c.tailSessions[testSessionID] = stop

	msg := &pb.HubMessage_LogStreamStop{
		LogStreamStop: &pb.LogStreamStop{RequestId: testSessionID},
	}
	c.handleLogStreamStop(msg)

	// channel should be closed and removed
	if _, ok := c.tailSessions[testSessionID]; ok {
		t.Fatal("expected session to be removed")
	}

	select {
	case <-stop:
		// closed as expected
	default:
		t.Fatal("expected stop channel to be closed")
	}
}

func TestHandleLogStreamStop_NonexistentSession(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{})}

	// Should not panic for nonexistent session
	msg := &pb.HubMessage_LogStreamStop{
		LogStreamStop: &pb.LogStreamStop{RequestId: "nonexistent"},
	}
	c.handleLogStreamStop(msg)
}

func TestHandleUnregisterRequest_NoCert(t *testing.T) {
	c := &Client{
		tailSessions: make(map[string]chan struct{}),
		hubAddr:      testHubAddr,
		serverID:     "srv-1",
		certStore:    certs.NewMemoryStore(),
	}
	sendCh := make(chan *pb.AgentMessage, 2)

	msg := &pb.HubMessage_UnregisterRequest{
		UnregisterRequest: &pb.UnregisterRequest{RequestId: "req-unreg"},
	}
	c.handleUnregisterRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		ack := resp.GetUnregisterAck()
		if ack == nil {
			t.Fatal("expected UnregisterAck")
		}
		// Without mTLS cert, unregister should be rejected
		if ack.Success {
			t.Fatal("expected rejection without mTLS cert")
		}
	default:
		t.Fatal(testExpectedAckOnSendCh)
	}
}

func TestHandleMessage_UnknownType(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{})}
	sendCh := make(chan *pb.AgentMessage, 1)

	// HeartbeatAck is a HubMessage type not handled in handleMessage
	msg := &pb.HubMessage{
		Payload: &pb.HubMessage_HeartbeatAck{
			HeartbeatAck: &pb.HeartbeatAck{},
		},
	}
	// Should not panic
	c.handleMessage(msg, sendCh)
}

func TestHandleFileListRequest(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{})}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage_FileListRequest{
		FileListRequest: &pb.FileListRequest{
			RequestId: testReqList,
			Path:      "/tmp",
		},
	}
	c.handleFileListRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		listResp := resp.GetFileListResponse()
		if listResp == nil {
			t.Fatal("expected FileListResponse")
		}
		if listResp.RequestId != testReqList {
			t.Fatalf("expected 'req-list', got '%s'", listResp.RequestId)
		}
	default:
		t.Fatal("expected response on sendCh for /tmp")
	}
}

func TestHandleFileReadRequest(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "test-read-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("hello world")
	tmpFile.Close()

	c := &Client{tailSessions: make(map[string]chan struct{})}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage_FileReadRequest{
		FileReadRequest: &pb.FileReadRequest{
			RequestId: "req-read",
			Path:      tmpFile.Name(),
			Offset:    0,
			Limit:     100,
		},
	}
	c.handleFileReadRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		readResp := resp.GetFileReadResponse()
		if readResp == nil {
			t.Fatal("expected FileReadResponse")
		}
		if readResp.RequestId != "req-read" {
			t.Fatalf("expected 'req-read', got '%s'", readResp.RequestId)
		}
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

func TestHandleFileUploadRequest(t *testing.T) {
	dir := t.TempDir()
	c := &Client{
		tailSessions: make(map[string]chan struct{}),
		dropzone:     newTestDropzone(dir),
	}
	sendCh := make(chan *pb.AgentMessage, 2)

	// Send file upload with done=true (complete file in one chunk)
	msg := &pb.HubMessage_FileUploadRequest{
		FileUploadRequest: &pb.FileUploadRequest{
			RequestId: "req-upload",
			Filename:  "test.txt",
			Chunk:     []byte("hello"),
			Done:      true,
		},
	}
	c.handleFileUploadRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		ack := resp.GetFileUploadAck()
		if ack == nil {
			t.Fatal("expected FileUploadAck")
		}
		if !ack.Success {
			t.Fatalf("expected success, got error: %s", ack.Error)
		}
	default:
		t.Fatal(testExpectedAckOnSendCh)
	}
}

func TestHandleLogStreamRequest(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{})}
	sendCh := make(chan *pb.AgentMessage, 10)

	// Create a temporary log file
	tmpFile, err := os.CreateTemp("", "test-log-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("log line 1\n")
	tmpFile.Close()

	msg := &pb.HubMessage_LogStreamRequest{
		LogStreamRequest: &pb.LogStreamRequest{
			RequestId: testReqLog,
			Path:      tmpFile.Name(),
			Grep:      "",
			Offset:    0,
		},
	}
	c.handleLogStreamRequest(msg, sendCh)

	// Verify the session was created
	if _, ok := c.tailSessions[testReqLog]; !ok {
		t.Fatal("expected tail session to be registered")
	}

	// Stop the session
	stopMsg := &pb.HubMessage_LogStreamStop{
		LogStreamStop: &pb.LogStreamStop{RequestId: testReqLog},
	}
	c.handleLogStreamStop(stopMsg)
}

func TestHandleMessage_FileList(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{})}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage{
		Payload: &pb.HubMessage_FileListRequest{
			FileListRequest: &pb.FileListRequest{
				RequestId: testReqList,
				Path:      "/tmp",
			},
		},
	}
	c.handleMessage(msg, sendCh)

	select {
	case <-sendCh:
		// ok
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

func TestHandleMessage_FileDelete(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{}), dropzone: dropzone.New(t.TempDir())}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage{
		Payload: &pb.HubMessage_FileDeleteRequest{
			FileDeleteRequest: &pb.FileDeleteRequest{
				RequestId: "req-del",
				Path:      "/etc/not-allowed",
			},
		},
	}
	c.handleMessage(msg, sendCh)

	select {
	case <-sendCh:
		// ok
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

func TestHandleMessage_LogStreamStop(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{})}
	stop := make(chan struct{})
	c.tailSessions["session-abc"] = stop
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage{
		Payload: &pb.HubMessage_LogStreamStop{
			LogStreamStop: &pb.LogStreamStop{RequestId: "session-abc"},
		},
	}
	c.handleMessage(msg, sendCh)

	select {
	case <-stop:
		// closed
	default:
		t.Fatal("expected stop channel to be closed")
	}
}

func TestHandleMessage_Unregister(t *testing.T) {
	c := &Client{
		tailSessions: make(map[string]chan struct{}),
		hubAddr:      testHubAddr,
		certStore:    certs.NewMemoryStore(),
	}
	sendCh := make(chan *pb.AgentMessage, 2)

	msg := &pb.HubMessage{
		Payload: &pb.HubMessage_UnregisterRequest{
			UnregisterRequest: &pb.UnregisterRequest{RequestId: "req-unreg"},
		},
	}
	c.handleMessage(msg, sendCh)

	select {
	case <-sendCh:
		// got ack (rejected without cert, but ack is still sent)
	default:
		t.Fatal(testExpectedAckOnSendCh)
	}
}
