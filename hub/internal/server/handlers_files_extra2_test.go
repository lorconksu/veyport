package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/notify"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// mockGRPCStreamFileErrors responds with errors for file operations and a large file for read.
type mockGRPCStreamFileErrors struct {
	mockGRPCStream
}

func (m *mockGRPCStreamFileErrors) Send(msg *pb.HubMessage) error {
	if m.pending != nil {
		switch p := msg.Payload.(type) {
		case *pb.HubMessage_FileListRequest:
			go func() {
				resp := &pb.FileListResponse{
					RequestId: p.FileListRequest.RequestId,
					Error:     "permission denied",
				}
				m.pending.Deliver(m.serverID, p.FileListRequest.RequestId, resp)
			}()
		case *pb.HubMessage_FileReadRequest:
			go func() {
				// Return a file that is "too large" (TotalSize > maxFileViewSize = 10MB)
				resp := &pb.FileReadResponse{
					RequestId: p.FileReadRequest.RequestId,
					Data:      []byte("some data"),
					TotalSize: int64(maxFileViewSize + 1),
					MimeType:  "text/plain",
				}
				m.pending.Deliver(m.serverID, p.FileReadRequest.RequestId, resp)
			}()
		}
	}
	return nil
}

// testServerWithFileErrorAgent creates a test server whose mock agent returns file errors.
func testServerWithFileErrorAgent(t *testing.T) (s *Server, adminToken, serverID string) {
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
	serverID = createTestServer(t, s, adminToken, "file-error-srv")

	stream := &mockGRPCStreamFileErrors{}
	stream.pending = pending
	stream.serverID = serverID
	cm.Register(serverID, stream)
	t.Cleanup(func() { cm.Unregister(serverID) })

	return s, adminToken, serverID
}

// TestHandleListFiles_AgentReturnsError verifies 404 when agent reports an error.
func TestHandleListFiles_AgentReturnsError(t *testing.T) {
	s, adminToken, serverID := testServerWithFileErrorAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files?path=/root/secret", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for agent error, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleReadFile_FileTooLarge verifies 413 when agent reports file is too large.
func TestHandleReadFile_FileTooLarge(t *testing.T) {
	s, adminToken, serverID := testServerWithFileErrorAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files/read?path=/var/log/huge.log", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for file too large, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleReadFile_MissingPath verifies 400 when path is missing.
func TestHandleReadFile_MissingPath(t *testing.T) {
	s, adminToken, serverID := testServerWithFileErrorAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files/read", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing path, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleReadFile_PathTraversal2 verifies 400 for double-dot path traversal.
func TestHandleReadFile_PathTraversal2(t *testing.T) {
	s, adminToken, serverID := testServerWithFileErrorAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files/read?path=/var/../etc/passwd", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for path traversal, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleListFiles_RelativePath2 verifies 400 for relative path in list.
func TestHandleListFiles_RelativePath2(t *testing.T) {
	s, adminToken, serverID := testServerWithFileErrorAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files?path=relative/path", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for relative path, got %d: %s", rec.Code, rec.Body.String())
	}
}
