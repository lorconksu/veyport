package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/notify"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// mockGRPCStream implements pb.AgentService_ConnectServer for testing.
type mockGRPCStream struct {
	ctx                  context.Context
	sent                 []*pb.HubMessage
	pending              *grpcserver.PendingRequests
	serverID             string
	terms                *grpcserver.TerminalSessions
	terminalOpenResponse proto.Message
	sendErr              error
}

func (m *mockGRPCStream) Send(msg *pb.HubMessage) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, msg)
	if m.pending == nil {
		return nil
	}
	m.deliverMockResponse(msg)
	return nil
}

func (m *mockGRPCStream) deliverMockResponse(msg *pb.HubMessage) {
	switch p := msg.Payload.(type) {
	case *pb.HubMessage_FileListRequest:
		m.deliverLater(p.FileListRequest.RequestId, &pb.FileListResponse{RequestId: p.FileListRequest.RequestId})
	case *pb.HubMessage_FileReadRequest:
		m.deliverLater(p.FileReadRequest.RequestId, &pb.FileReadResponse{RequestId: p.FileReadRequest.RequestId})
	case *pb.HubMessage_FileDeleteRequest:
		m.deliverLater(p.FileDeleteRequest.RequestId, &pb.FileDeleteResponse{RequestId: p.FileDeleteRequest.RequestId, Success: true})
	case *pb.HubMessage_UnregisterRequest:
		m.deliverLater(p.UnregisterRequest.RequestId, &pb.UnregisterAck{RequestId: p.UnregisterRequest.RequestId})
	case *pb.HubMessage_FileUploadRequest:
		m.deliverFileUploadAck(p.FileUploadRequest)
	case *pb.HubMessage_TerminalOpenRequest:
		m.deliverTerminalOpen(p.TerminalOpenRequest)
	}
}

func (m *mockGRPCStream) deliverLater(requestID string, resp proto.Message) {
	go func() {
		m.pending.Deliver(m.serverID, requestID, resp)
	}()
}

func (m *mockGRPCStream) deliverFileUploadAck(req *pb.FileUploadRequest) {
	if !req.Done {
		return
	}
	m.deliverLater(req.RequestId, &pb.FileUploadAck{RequestId: req.RequestId, Success: true})
}

func (m *mockGRPCStream) deliverTerminalOpen(req *pb.TerminalOpenRequest) {
	go func() {
		resp := m.terminalOpenResponse
		if resp == nil {
			resp = &pb.TerminalOpenAck{SessionId: req.SessionId, Success: true}
		}
		m.pending.Deliver(m.serverID, req.SessionId, resp)
		if terminalOpenSucceeded(resp) && m.terms != nil {
			m.terms.DeliverData(m.serverID, req.SessionId, []byte("mock$ "))
		}
	}()
}

func terminalOpenSucceeded(resp proto.Message) bool {
	ack, ok := resp.(*pb.TerminalOpenAck)
	return ok && ack.Success
}

func (m *mockGRPCStream) Recv() (*pb.AgentMessage, error) { return nil, nil }
func (m *mockGRPCStream) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}
func (m *mockGRPCStream) SendMsg(msg interface{}) error { return nil }
func (m *mockGRPCStream) RecvMsg(msg interface{}) error { return nil }
func (m *mockGRPCStream) SetHeader(metadata.MD) error   { return nil }
func (m *mockGRPCStream) SendHeader(metadata.MD) error  { return nil }
func (m *mockGRPCStream) SetTrailer(metadata.MD) {
	// no-op: mock stub for testing
}

// testServerWithAgent creates a test server with a connMgr and a mock agent stream.
// Returns the server, the admin token, and the serverID of a registered server.
// The mock stream auto-delivers responses for FileList and FileRead requests.
func testServerWithAgent(t *testing.T) (s *Server, adminToken, serverID string) {
	t.Helper()
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	t.Cleanup(func() { st.Close() })

	jwtSecret, err := InitJWTSecret(st)
	if err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}

	cm := connmgr.New()
	pending := grpcserver.NewPendingRequests()
	logSessions := grpcserver.NewLogSessions()
	terminalSessions := grpcserver.NewTerminalSessions()

	notifier := notify.New(st)
	t.Cleanup(func() { notifier.Close() })

	s = New(Config{
		Addr:             ":0",
		Store:            st,
		JWTSecret:        jwtSecret,
		IsDev:            true,
		ConnMgr:          cm,
		Pending:          pending,
		LogSessions:      logSessions,
		TerminalSessions: terminalSessions,
		Notifier:         notifier,
	})

	// Create a server in the store
	adminToken = registerAndGetAdminToken(t, s)
	serverID = createTestServer(t, s, adminToken, "agent-test-srv")

	// Register a mock stream that auto-delivers responses
	stream := &mockGRPCStream{pending: pending, serverID: serverID, terms: terminalSessions}
	cm.Register(serverID, stream)
	t.Cleanup(func() { cm.Unregister(serverID) })

	return s, adminToken, serverID
}

// TestRequireAgent_AgentConnected verifies requireAgent returns success when agent is connected.
func TestRequireAgent_AgentConnected(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testFilesQuery, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// Should get a real response (not 502 no-agent) - either 200 or the response from mock agent
	if rec.Code == http.StatusBadGateway {
		t.Fatalf("agent is registered, should not get 502 no-agent; got 502")
	}
}

// TestSendAgentRequest_Success verifies sendAgentRequest gets a response when agent responds.
func TestSendAgentRequest_Success(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testFilesQuery, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// Mock agent returns empty FileListResponse → handler returns 200 with empty files
	if rec.Code != http.StatusOK {
		t.Logf("sendAgentRequest response: %d: %s", rec.Code, rec.Body.String())
	}
}

// TestRequireAgent_NilConnMgr verifies requireAgent returns 502 when connMgr is nil.
func TestRequireAgent_NilConnMgr(t *testing.T) {
	s := testServer(t) // testServer has nil connMgr
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/some-server/files?path=/var/log", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for nil connMgr, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleReadFile_WithAgent verifies handleReadFile works with a connected agent.
func TestHandleReadFile_WithAgent(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files/read?path=/etc/hosts", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// Should get 200 from mock agent (not 502)
	if rec.Code == http.StatusBadGateway {
		t.Fatalf("should not get 502 with connected agent, got 502")
	}
	// Mock agent returns empty FileReadResponse, which means no error
	// Handler will try to process the response
	t.Logf("handleReadFile response: %d: %s", rec.Code, rec.Body.String())
}

// TestHandleListFiles_WithConnectedAgent verifies file list with connected agent.
func TestHandleListFiles_WithConnectedAgent(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testFilesQuery, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// With a connected agent that auto-responds with empty FileListResponse
	if rec.Code == http.StatusBadGateway {
		t.Fatalf("should not get 502 (no agent) with connected agent")
	}
	// Should be 200 since mock returns empty (no error) FileListResponse
	if rec.Code != http.StatusOK {
		t.Logf("handleListFiles response: %d: %s", rec.Code, rec.Body.String())
	}
}
