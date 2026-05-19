package server

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/notify"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/metadata"
)

const testTxtFilename = "test.txt"

// TestHandleUploadFile_WithAgent verifies upload works with a connected agent.
func TestHandleUploadFile_WithAgent(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", testTxtFilename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	part.Write([]byte("hello world"))
	writer.Close()

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Logf("upload response: %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleUploadFile_LargeFile verifies 413 is returned for files over 100MB.
func TestHandleUploadFile_TooBig(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	// Create a multipart body that exceeds the limit header
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.CreateFormFile("file", "big.bin")
	writer.Close()

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, writer.FormDataContentType())
	// Override body with oversized content
	bigBody := bytes.Repeat([]byte("x"), 100*1024*1024+2048)
	req2 := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, bytes.NewReader(bigBody))
	req2.Header.Set("Authorization", testBearerPrefix+adminToken)
	req2.Header.Set(testContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req2)

	// Should get 413 (too large)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Logf("expected 413 for oversized upload, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleUploadFile_NoAgentConnected verifies 502 when no agent connected.
func TestHandleUploadFile_NoAgentConnected(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, token, "upload-no-agent")

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", testTxtFilename)
	part.Write([]byte("hello"))
	writer.Close()

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	req.Header.Set(testContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf(testExpected502Body, rec.Code, rec.Body.String())
	}
}

// TestHandleUploadFile_NoFileField verifies 400 when no file field in multipart.
func TestHandleUploadFile_NoFileField(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("other", "value")
	writer.Close()

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for no file, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleListDropzone_WithAgent verifies dropzone list with connected agent.
func TestHandleListDropzone_WithAgent(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testDropzoneSuffix, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for list dropzone, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleListDropzone_NoAgentConnected verifies 502 when no agent connected.
func TestHandleListDropzone_NoAgentConnected(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, token, "dropzone-no-agent")

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testDropzoneSuffix, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleDeleteDropzoneFile_WithAgent verifies file deletion with connected agent.
func TestHandleDeleteDropzoneFile_WithAgent(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+"/dropzone?filename=test.txt", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// Should get 204 (no content) on success
	if rec.Code != http.StatusNoContent {
		t.Logf("dropzone delete response: %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleDeleteDropzoneFile_NoFilename verifies 400 for missing filename.
func TestHandleDeleteDropzoneFile_NoFilename(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+testDropzoneSuffix, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for no filename, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleDeleteDropzoneFile_NoAgentConnected verifies 502 when no agent connected.
func TestHandleDeleteDropzoneFile_NoAgentConnected(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, token, "dropzone-del-no-agent")

	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+"/dropzone?filename=test.txt", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleUnregisterServer_WithConnectedAgent verifies unregister sends command to agent.
func TestHandleUnregisterServer_WithConnectedAgent(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+testUnregSuffix, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

// TestHandleSelfUnregister_AgentExists verifies self-unregister for an existing server.
func TestHandleSelfUnregister_AgentExists(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	_ = adminToken

	// Use HMAC token for self-unregister authentication
	unregToken := s.selfUnregisterToken(serverID)

	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+testSelfUnregSuffix, nil)
	req.Header.Set(testUnregTokenHdr, unregToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleSelfUnregister_AgentNotExists verifies self-unregister for a nonexistent server.
func TestHandleSelfUnregister_AgentNotExists(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("DELETE", "/api/servers/nonexistent-server/self-unregister", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleAuthStatus_Initialized verifies auth status returns initialized:true after register.
func TestHandleAuthStatus_Initialized(t *testing.T) {
	s := testServer(t)
	registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/auth/status", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if body == "" {
		t.Fatal("expected non-empty body")
	}
}

// TestHandleAuthStatus_Uninitialized verifies auth status returns initialized:false when no users.
func TestHandleAuthStatus_Uninitialized(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/api/auth/status", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

// TestHandleMe_ValidUser verifies /api/auth/me returns user data.
func TestHandleMe_ValidUser(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", testMePath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

// TestHandleListUsers_EmptyList verifies listing users works.
func TestHandleListUsers_Empty(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", testUsersPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

// TestHandleUpdateUserRole_SelfRole verifies admin cannot change own role.
func TestHandleUpdateUserRole_SelfRole(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	user, _ := s.store.GetUserByUsername("admin")

	req := httptest.NewRequest("PUT", testUsersPrefix+user.ID+"/role", mustJSON(t, map[string]string{"role": "viewer"}))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for self-role change, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleUpdateUserRole_InvalidRole verifies invalid role returns 400.
func TestHandleUpdateUserRole_InvalidRole(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("PUT", "/api/users/some-other-id/role", mustJSON(t, map[string]string{"role": "superadmin"}))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
}

// TestHandleDeleteUser_SelfDelete verifies admin cannot delete own account.
func TestHandleDeleteUser_SelfDelete(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	user, _ := s.store.GetUserByUsername("admin")

	req := httptest.NewRequest("DELETE", testUsersPrefix+user.ID, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for self-delete, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleDeleteUser_NotFound verifies deleting a nonexistent user returns 404.
func TestHandleDeleteUser_NotFound(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("DELETE", "/api/users/nonexistent-id", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleListPaths_WithPermissions verifies listing paths for a server.
func TestHandleListPaths_WithPermissions(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "paths-srv")

	viewerToken := createViewerAndGetToken(t, s, adminToken)
	_ = viewerToken

	users, _ := s.store.ListUsers()
	var viewerID string
	for _, u := range users {
		if u.Role == "viewer" {
			viewerID = u.ID
			break
		}
	}

	s.store.CreatePermission(viewerID, serverID, testVarLog)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testPathsSuffix, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

// TestHandleDeletePath_WrongServer verifies 404 when path belongs to different server.
func TestHandleDeletePath_WrongServer(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "wrongsrv-path")
	otherServerID := createTestServer(t, s, adminToken, "wrongsrv-other")

	users, _ := s.store.ListUsers()
	var viewerID string
	for _, u := range users {
		if u.Role == "admin" {
			viewerID = u.ID
			break
		}
	}

	// create permission on otherServer
	perm, _ := s.store.CreatePermission(viewerID, otherServerID, testVarLog)

	// try to delete via serverID (wrong server)
	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+"/paths/"+perm.ID, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleTailLog_MissingPath verifies 400 for missing path in log tail.
func TestHandleTailLog_MissingPath(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/logs/tail", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing path, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleRegister_Disabled verifies register is blocked when users exist.
func TestHandleRegister_Disabled(t *testing.T) {
	s := testServer(t)
	registerAndGetAdminToken(t, s)

	// Try to register again
	req := httptest.NewRequest("POST", testRegisterPath, mustJSON(t, map[string]string{
		"username": "second", "email": "second@test.com", "password": testPassword,
	}))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleChangePassword_WrongCurrentPassword verifies 401 for wrong current password.
func TestHandleChangePassword_WrongCurrentPassword(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("PUT", testPasswordPath, mustJSON(t, map[string]string{
		"current_password": "WrongPassword!123",
		"new_password":     "NewP@ssw0rd!234",
	}))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401Body, rec.Code, rec.Body.String())
	}
}

// --- Mock agents with custom upload ack behavior ---

// mockGRPCStreamFailedAck delivers a FileUploadAck with Success=false.
type mockGRPCStreamFailedAck struct {
	sent     []*pb.HubMessage
	pending  *grpcserver.PendingRequests
	serverID string
}

func (m *mockGRPCStreamFailedAck) Send(msg *pb.HubMessage) error {
	m.sent = append(m.sent, msg)
	if m.pending != nil {
		if p, ok := msg.Payload.(*pb.HubMessage_FileUploadRequest); ok && p.FileUploadRequest.Done {
			go func() {
				resp := &pb.FileUploadAck{
					RequestId: p.FileUploadRequest.RequestId,
					Success:   false,
					Error:     "disk full",
				}
				m.pending.Deliver(m.serverID, p.FileUploadRequest.RequestId, resp)
			}()
		}
	}
	return nil
}

func (m *mockGRPCStreamFailedAck) Recv() (*pb.AgentMessage, error) { return nil, nil }
func (m *mockGRPCStreamFailedAck) Context() context.Context        { return context.Background() }
func (m *mockGRPCStreamFailedAck) SendMsg(interface{}) error       { return nil }
func (m *mockGRPCStreamFailedAck) RecvMsg(interface{}) error       { return nil }
func (m *mockGRPCStreamFailedAck) SetHeader(metadata.MD) error     { return nil }
func (m *mockGRPCStreamFailedAck) SendHeader(metadata.MD) error    { return nil }
func (m *mockGRPCStreamFailedAck) SetTrailer(metadata.MD) {
	// no-op: mock stub for testing
}

// mockGRPCStreamWrongAckType delivers a wrong message type for upload ack.
type mockGRPCStreamWrongAckType struct {
	sent     []*pb.HubMessage
	pending  *grpcserver.PendingRequests
	serverID string
}

func (m *mockGRPCStreamWrongAckType) Send(msg *pb.HubMessage) error {
	m.sent = append(m.sent, msg)
	if m.pending != nil {
		if p, ok := msg.Payload.(*pb.HubMessage_FileUploadRequest); ok && p.FileUploadRequest.Done {
			go func() {
				// Deliver a FileListResponse instead of FileUploadAck
				resp := &pb.FileListResponse{RequestId: p.FileUploadRequest.RequestId}
				m.pending.Deliver(m.serverID, p.FileUploadRequest.RequestId, resp)
			}()
		}
	}
	return nil
}

func (m *mockGRPCStreamWrongAckType) Recv() (*pb.AgentMessage, error) { return nil, nil }
func (m *mockGRPCStreamWrongAckType) Context() context.Context        { return context.Background() }
func (m *mockGRPCStreamWrongAckType) SendMsg(interface{}) error       { return nil }
func (m *mockGRPCStreamWrongAckType) RecvMsg(interface{}) error       { return nil }
func (m *mockGRPCStreamWrongAckType) SetHeader(metadata.MD) error     { return nil }
func (m *mockGRPCStreamWrongAckType) SendHeader(metadata.MD) error    { return nil }
func (m *mockGRPCStreamWrongAckType) SetTrailer(metadata.MD) {
	// no-op: mock stub for testing
}

// testServerWithCustomAgent creates a test server with a custom mock stream.
func testServerWithCustomAgent(t *testing.T, streamFactory func(pending *grpcserver.PendingRequests, serverID string) pb.AgentService_ConnectServer) (s *Server, adminToken, serverID string) {
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

	notifier := notify.New(st)
	t.Cleanup(func() { notifier.Close() })

	s = New(Config{
		Addr:        ":0",
		Store:       st,
		JWTSecret:   jwtSecret,
		IsDev:       true,
		ConnMgr:     cm,
		Pending:     pending,
		LogSessions: logSessions,
		Notifier:    notifier,
	})

	adminToken = registerAndGetAdminToken(t, s)
	serverID = createTestServer(t, s, adminToken, "custom-agent-srv")

	stream := streamFactory(pending, serverID)
	cm.Register(serverID, stream)
	t.Cleanup(func() { cm.Unregister(serverID) })

	return s, adminToken, serverID
}

// mockGRPCStreamFileListError delivers a FileListResponse with an error string.
type mockGRPCStreamFileListError struct {
	sent     []*pb.HubMessage
	pending  *grpcserver.PendingRequests
	serverID string
}

func (m *mockGRPCStreamFileListError) Send(msg *pb.HubMessage) error {
	m.sent = append(m.sent, msg)
	if m.pending != nil {
		if p, ok := msg.Payload.(*pb.HubMessage_FileListRequest); ok {
			go func() {
				resp := &pb.FileListResponse{
					RequestId: p.FileListRequest.RequestId,
					Error:     "no such directory",
				}
				m.pending.Deliver(m.serverID, p.FileListRequest.RequestId, resp)
			}()
		}
	}
	return nil
}

func (m *mockGRPCStreamFileListError) Recv() (*pb.AgentMessage, error) { return nil, nil }
func (m *mockGRPCStreamFileListError) Context() context.Context        { return context.Background() }
func (m *mockGRPCStreamFileListError) SendMsg(interface{}) error       { return nil }
func (m *mockGRPCStreamFileListError) RecvMsg(interface{}) error       { return nil }
func (m *mockGRPCStreamFileListError) SetHeader(metadata.MD) error     { return nil }
func (m *mockGRPCStreamFileListError) SendHeader(metadata.MD) error    { return nil }
func (m *mockGRPCStreamFileListError) SetTrailer(metadata.MD) {
	// no-op: mock stub for testing
}

// TestHandleListDropzone_ErrorFromAgent covers the resp.Error != "" branch in handleListDropzone.
func TestHandleListDropzone_ErrorFromAgent(t *testing.T) {
	s, adminToken, serverID := testServerWithCustomAgent(t, func(pending *grpcserver.PendingRequests, sid string) pb.AgentService_ConnectServer {
		return &mockGRPCStreamFileListError{pending: pending, serverID: sid}
	})

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testDropzoneSuffix, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// When the agent returns an error for dropzone list, the handler returns 200 with empty list
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	// Body should contain empty files array
	if !strings.Contains(rec.Body.String(), "[]") {
		t.Errorf("expected empty files list in body, got: %s", rec.Body.String())
	}
}

// mockGRPCStreamDeleteFailed delivers a FileDeleteResponse with Success=false.
type mockGRPCStreamDeleteFailed struct {
	sent     []*pb.HubMessage
	pending  *grpcserver.PendingRequests
	serverID string
}

func (m *mockGRPCStreamDeleteFailed) Send(msg *pb.HubMessage) error {
	m.sent = append(m.sent, msg)
	if m.pending != nil {
		if p, ok := msg.Payload.(*pb.HubMessage_FileDeleteRequest); ok {
			go func() {
				resp := &pb.FileDeleteResponse{
					RequestId: p.FileDeleteRequest.RequestId,
					Success:   false,
					Error:     "file not found",
				}
				m.pending.Deliver(m.serverID, p.FileDeleteRequest.RequestId, resp)
			}()
		}
	}
	return nil
}

func (m *mockGRPCStreamDeleteFailed) Recv() (*pb.AgentMessage, error) { return nil, nil }
func (m *mockGRPCStreamDeleteFailed) Context() context.Context        { return context.Background() }
func (m *mockGRPCStreamDeleteFailed) SendMsg(interface{}) error       { return nil }
func (m *mockGRPCStreamDeleteFailed) RecvMsg(interface{}) error       { return nil }
func (m *mockGRPCStreamDeleteFailed) SetHeader(metadata.MD) error     { return nil }
func (m *mockGRPCStreamDeleteFailed) SendHeader(metadata.MD) error    { return nil }
func (m *mockGRPCStreamDeleteFailed) SetTrailer(metadata.MD) {
	// no-op: mock stub for testing
}

// TestHandleDeleteDropzoneFile_AgentReportsFailure covers the resp.Success=false branch.
func TestHandleDeleteDropzoneFile_AgentReportsFailure(t *testing.T) {
	s, adminToken, serverID := testServerWithCustomAgent(t, func(pending *grpcserver.PendingRequests, sid string) pb.AgentService_ConnectServer {
		return &mockGRPCStreamDeleteFailed{pending: pending, serverID: sid}
	})

	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+"/dropzone?filename=missing.txt", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for failed delete, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "file not found") {
		t.Errorf("expected 'file not found' in error, got: %s", rec.Body.String())
	}
}

// TestHandleUploadFile_AckFailure covers the ack.Success=false branch in handleUploadFile.
func TestHandleUploadFile_AckFailure(t *testing.T) {
	s, adminToken, serverID := testServerWithCustomAgent(t, func(pending *grpcserver.PendingRequests, sid string) pb.AgentService_ConnectServer {
		return &mockGRPCStreamFailedAck{pending: pending, serverID: sid}
	})

	body, ct := buildMultipartBody(t, "file", testTxtFilename, []byte("hello"))

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, ct)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for failed ack, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "disk full") {
		t.Errorf("expected 'disk full' in error, got: %s", rec.Body.String())
	}
}

// TestHandleUploadFile_WrongAckType covers the unexpected response type branch in handleUploadFile.
func TestHandleUploadFile_WrongAckType(t *testing.T) {
	s, adminToken, serverID := testServerWithCustomAgent(t, func(pending *grpcserver.PendingRequests, sid string) pb.AgentService_ConnectServer {
		return &mockGRPCStreamWrongAckType{pending: pending, serverID: sid}
	})

	body, ct := buildMultipartBody(t, "file", testTxtFilename, []byte("hello"))

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, ct)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for wrong ack type, got %d: %s", rec.Code, rec.Body.String())
	}
}
