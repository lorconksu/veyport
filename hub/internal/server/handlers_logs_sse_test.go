package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/notify"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// mockGRPCStreamWithLog extends mockGRPCStream to also handle LogStreamRequest.
type mockGRPCStreamWithLog struct {
	mockGRPCStream
	logSessions *grpcserver.LogSessions
}

func (m *mockGRPCStreamWithLog) Send(msg *pb.HubMessage) error {
	m.sent = append(m.sent, msg)
	if m.pending != nil {
		switch p := msg.Payload.(type) {
		case *pb.HubMessage_FileListRequest:
			go func() {
				resp := &pb.FileListResponse{RequestId: p.FileListRequest.RequestId}
				m.pending.Deliver(m.serverID, p.FileListRequest.RequestId, resp)
			}()
		case *pb.HubMessage_FileReadRequest:
			go func() {
				resp := &pb.FileReadResponse{RequestId: p.FileReadRequest.RequestId}
				m.pending.Deliver(m.serverID, p.FileReadRequest.RequestId, resp)
			}()
		case *pb.HubMessage_FileDeleteRequest:
			go func() {
				resp := &pb.FileDeleteResponse{RequestId: p.FileDeleteRequest.RequestId, Success: true}
				m.pending.Deliver(m.serverID, p.FileDeleteRequest.RequestId, resp)
			}()
		case *pb.HubMessage_UnregisterRequest:
			go func() {
				resp := &pb.UnregisterAck{RequestId: p.UnregisterRequest.RequestId}
				m.pending.Deliver(m.serverID, p.UnregisterRequest.RequestId, resp)
			}()
		case *pb.HubMessage_FileUploadRequest:
			if p.FileUploadRequest.Done {
				go func() {
					resp := &pb.FileUploadAck{RequestId: p.FileUploadRequest.RequestId, Success: true}
					m.pending.Deliver(m.serverID, p.FileUploadRequest.RequestId, resp)
				}()
			}
		case *pb.HubMessage_LogStreamRequest:
			// Deliver a log chunk and then stop
			if m.logSessions != nil {
				go func() {
					time.Sleep(10 * time.Millisecond)
					m.logSessions.Deliver(m.serverID, p.LogStreamRequest.RequestId, []byte("2026-01-01 hello world\n"))
					// After delivering one chunk, remove the session to close the channel
					time.Sleep(10 * time.Millisecond)
					m.logSessions.Remove(m.serverID, p.LogStreamRequest.RequestId)
				}()
			}
		}
	}
	return nil
}

// testServerWithAgentAndLog creates a test server with a connMgr and a mock agent stream
// that also handles log session delivery.
func testServerWithAgentAndLog(t *testing.T) (s *Server, adminToken, serverID string) {
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
	serverID = createTestServer(t, s, adminToken, "logtail-test-srv")

	stream := &mockGRPCStreamWithLog{
		mockGRPCStream: mockGRPCStream{pending: pending, serverID: serverID},
		logSessions:    logSessions,
	}
	cm.Register(serverID, stream)
	t.Cleanup(func() { cm.Unregister(serverID) })

	return s, adminToken, serverID
}

// TestHandleTailLog_StreamsData verifies the SSE streaming path delivers log data.
func TestHandleTailLog_StreamsData(t *testing.T) {
	s, adminToken, serverID := testServerWithAgentAndLog(t)

	// Use a context that we'll cancel to stop the SSE loop
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testLogsTailQuery, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req = req.WithContext(ctx)

	// Use a flusherRecorder to support SSE (http.Flusher interface)
	rec := &flusherRecorder{ResponseRecorder: httptest.NewRecorder()}
	s.routes().ServeHTTP(rec, req)

	// Should get 200 (set when SSE starts streaming)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for SSE stream, got %d: %s", rec.Code, rec.Body.String())
	}

	if !rec.flushed {
		t.Fatal("expected flusher to have been called")
	}
}

// TestHandleTailLog_InvalidPath verifies 400 for invalid path characters.
func TestHandleTailLog_InvalidPath(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/logs/tail?path=../etc/passwd", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid path, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleTailLog_ViewerDenied verifies viewer without permission gets 403.
func TestHandleTailLog_ViewerDenied(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-tail-denied")
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testLogsTailQuery, nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthorized viewer, got %d: %s", rec.Code, rec.Body.String())
	}
}
