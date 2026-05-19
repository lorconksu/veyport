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

// mockGRPCStreamReadError responds with a file read error.
type mockGRPCStreamReadError struct {
	mockGRPCStream
}

func (m *mockGRPCStreamReadError) Send(msg *pb.HubMessage) error {
	if m.pending != nil {
		switch p := msg.Payload.(type) {
		case *pb.HubMessage_FileReadRequest:
			go func() {
				resp := &pb.FileReadResponse{
					RequestId: p.FileReadRequest.RequestId,
					Error:     "file not found",
				}
				m.pending.Deliver(m.serverID, p.FileReadRequest.RequestId, resp)
			}()
		}
	}
	return nil
}

// testServerWithReadErrorAgent creates a test server whose mock agent returns read errors.
func testServerWithReadErrorAgent(t *testing.T) (s *Server, adminToken, serverID string) {
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
	serverID = createTestServer(t, s, adminToken, "read-error-srv")

	stream := &mockGRPCStreamReadError{}
	stream.pending = pending
	stream.serverID = serverID
	cm.Register(serverID, stream)
	t.Cleanup(func() { cm.Unregister(serverID) })

	return s, adminToken, serverID
}

// TestHandleReadFile_AgentReturnsError verifies 404 when agent reports a read error.
func TestHandleReadFile_AgentReturnsError(t *testing.T) {
	s, adminToken, serverID := testServerWithReadErrorAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files/read?path=/nonexistent/file.txt", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for agent read error, got %d: %s", rec.Code, rec.Body.String())
	}
}

// mockGRPCStreamCaptureOffset captures the offset from FileReadRequest.
type mockGRPCStreamCaptureOffset struct {
	mockGRPCStream
	capturedOffset int64
	capturedLimit  int64
}

func (m *mockGRPCStreamCaptureOffset) Send(msg *pb.HubMessage) error {
	if m.pending != nil {
		switch p := msg.Payload.(type) {
		case *pb.HubMessage_FileReadRequest:
			m.capturedOffset = p.FileReadRequest.Offset
			m.capturedLimit = p.FileReadRequest.Limit
			go func() {
				resp := &pb.FileReadResponse{
					RequestId: p.FileReadRequest.RequestId,
					Data:      []byte("tail data"),
					TotalSize: 5000000, // 5MB file
					MimeType:  "text/plain",
				}
				m.pending.Deliver(m.serverID, p.FileReadRequest.RequestId, resp)
			}()
		}
	}
	return nil
}

// TestHandleReadFile_SendsNegativeOffset verifies the hub sends offset=-1
// to request the tail of the file.
func TestHandleReadFile_SendsNegativeOffset(t *testing.T) {
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

	s := New(Config{
		Addr:        ":0",
		Store:       st,
		JWTSecret:   jwtSecret,
		IsDev:       true,
		ConnMgr:     cm,
		Pending:     pending,
		LogSessions: logSessions,
	})

	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "offset-capture-srv")

	stream := &mockGRPCStreamCaptureOffset{}
	stream.pending = pending
	stream.serverID = serverID
	cm.Register(serverID, stream)
	t.Cleanup(func() { cm.Unregister(serverID) })

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files/read?path=/var/log/big.log", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	// Verify the hub sent offset=-1 (tail request)
	if stream.capturedOffset != -1 {
		t.Fatalf("expected hub to send offset=-1, got %d", stream.capturedOffset)
	}
	// Verify the hub sent limit=maxFileReadSize (1MB)
	if stream.capturedLimit != maxFileReadSize {
		t.Fatalf("expected hub to send limit=%d, got %d", maxFileReadSize, stream.capturedLimit)
	}
}
