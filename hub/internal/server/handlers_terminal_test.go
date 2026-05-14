package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
	pb "github.com/wyiu/aerodocs/proto/aerodocs/v1"
)

const testTerminalSessionsSuffix = "/terminal/sessions"

func createTerminalSessionForTest(t *testing.T, s *Server, token, serverID string) string {
	t.Helper()

	body := mustJSON(t, map[string]interface{}{
		"cols": 120,
		"rows": 36,
	})
	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp model.TerminalSessionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode terminal session response: %v", err)
	}
	if resp.SessionID == "" {
		t.Fatal("expected terminal session id")
	}
	return resp.SessionID
}

func TestHandleCreateTerminalSession(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	sessionID := createTerminalSessionForTest(t, s, adminToken, serverID)

	conn := s.connMgr.GetConn(serverID)
	stream, ok := conn.Stream.(*mockGRPCStream)
	if !ok {
		t.Fatal("expected mockGRPCStream")
	}
	if len(stream.sent) == 0 {
		t.Fatal("expected a terminal open request to be sent to the agent")
	}
	openReq := stream.sent[len(stream.sent)-1].GetTerminalOpenRequest()
	if openReq == nil {
		t.Fatal("expected last message to be a terminal open request")
	}
	if openReq.SessionId != sessionID {
		t.Fatalf("expected session id %s, got %s", sessionID, openReq.SessionId)
	}
}

func TestHandleCreateTerminalSession_InvalidCwd(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]interface{}{
		"cols": 80,
		"rows": 24,
		"cwd":  "relative/path",
	}))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "absolute") {
		t.Fatalf("expected cwd validation error, got %s", rec.Body.String())
	}
}

func TestHandleCreateTerminalSession_InvalidBody(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, strings.NewReader("{"))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid create body, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateTerminalSession_ServiceUnavailable(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	s.terminalSessions = nil

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]interface{}{"cols": 80, "rows": 24}))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateTerminalSession_AgentFailure(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	conn := s.connMgr.GetConn(serverID)
	stream := conn.Stream.(*mockGRPCStream)
	stream.terminalOpenResponse = &pb.TerminalOpenAck{
		SessionId: "ignored",
		Success:   false,
		Error:     "terminal cwd not available",
	}

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]interface{}{"cols": 80, "rows": 24}))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for cwd failure, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateTerminalSession_AgentGatewayFailure(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	conn := s.connMgr.GetConn(serverID)
	stream := conn.Stream.(*mockGRPCStream)
	stream.terminalOpenResponse = &pb.TerminalOpenAck{
		SessionId: "ignored",
		Success:   false,
		Error:     "shell unavailable",
	}

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]interface{}{"cols": 80, "rows": 24}))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for agent open failure, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateTerminalSession_UnexpectedAgentResponse(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	conn := s.connMgr.GetConn(serverID)
	stream := conn.Stream.(*mockGRPCStream)
	stream.terminalOpenResponse = &pb.FileListResponse{RequestId: "unexpected"}

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]interface{}{"cols": 80, "rows": 24}))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for unexpected terminal response, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateTerminalSession_ViewerDenied(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]interface{}{"cols": 80, "rows": 24}))
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateTerminalSession_APITokenDenied(t *testing.T) {
	s, _, serverID := testServerWithAgent(t)
	user, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get admin user: %v", err)
	}
	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if err := s.store.CreateAPIToken(&model.APIToken{
		ID:          uuid.NewString(),
		UserID:      user.ID,
		Name:        "automation",
		TokenHash:   hash,
		TokenPrefix: prefix,
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]interface{}{"cols": 80, "rows": 24}))
	req.Header.Set("Authorization", testBearerPrefix+raw)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleTerminalInput_RejectsClosedAndLargeInput(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	sessionID := createTerminalSessionForTest(t, s, adminToken, serverID)

	if !s.terminalSessions.End(serverID, sessionID, 0, "") {
		t.Fatal("expected terminal session end")
	}
	closedReq := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID+"/input", mustJSON(t, map[string]string{"data": "pwd\n"}))
	closedReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	closedRec := httptest.NewRecorder()
	s.routes().ServeHTTP(closedRec, closedReq)
	if closedRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for closed terminal input, got %d: %s", closedRec.Code, closedRec.Body.String())
	}

	openSessionID := createTerminalSessionForTest(t, s, adminToken, serverID)
	largeReq := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+openSessionID+"/input", mustJSON(t, map[string]string{
		"data": strings.Repeat("x", maxTerminalInputBytes+1),
	}))
	largeReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	largeRec := httptest.NewRecorder()
	s.routes().ServeHTTP(largeRec, largeReq)
	if largeRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for large terminal input, got %d: %s", largeRec.Code, largeRec.Body.String())
	}
}

func TestHandleTerminalInput_InvalidBodyAndMissingSession(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	badBodyReq := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix+"/missing/input", strings.NewReader("{"))
	badBodyReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	badBodyRec := httptest.NewRecorder()
	s.routes().ServeHTTP(badBodyRec, badBodyReq)
	if badBodyRec.Code != http.StatusNotFound {
		t.Fatalf("missing session should be checked before body parsing, got %d: %s", badBodyRec.Code, badBodyRec.Body.String())
	}

	sessionID := createTerminalSessionForTest(t, s, adminToken, serverID)
	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID+"/input", strings.NewReader("{"))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid input body, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleTerminalInputAndResize(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	sessionID := createTerminalSessionForTest(t, s, adminToken, serverID)

	inputBody := mustJSON(t, map[string]string{"data": "pwd\n"})
	inputReq := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID+"/input", inputBody)
	inputReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	inputRec := httptest.NewRecorder()
	s.routes().ServeHTTP(inputRec, inputReq)
	if inputRec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", inputRec.Code, inputRec.Body.String())
	}

	resizeBody := mustJSON(t, map[string]int{"cols": 132, "rows": 40})
	resizeReq := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID+"/resize", resizeBody)
	resizeReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	resizeRec := httptest.NewRecorder()
	s.routes().ServeHTTP(resizeRec, resizeReq)
	if resizeRec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", resizeRec.Code, resizeRec.Body.String())
	}

	conn := s.connMgr.GetConn(serverID)
	stream := conn.Stream.(*mockGRPCStream)
	foundInput := false
	foundResize := false
	for _, msg := range stream.sent {
		if payload := msg.GetTerminalInput(); payload != nil && payload.SessionId == sessionID && string(payload.Data) == "pwd\n" {
			foundInput = true
		}
		if payload := msg.GetTerminalResize(); payload != nil && payload.SessionId == sessionID && payload.Cols == 132 && payload.Rows == 40 {
			foundResize = true
		}
	}
	if !foundInput {
		t.Fatal("expected terminal input message")
	}
	if !foundResize {
		t.Fatal("expected terminal resize message")
	}
}

func TestHandleTerminalInputAndResize_SendFailures(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	sessionID := createTerminalSessionForTest(t, s, adminToken, serverID)
	conn := s.connMgr.GetConn(serverID)
	stream := conn.Stream.(*mockGRPCStream)
	stream.sendErr = errors.New("send failed")

	inputReq := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID+"/input", mustJSON(t, map[string]string{"data": "pwd\n"}))
	inputReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	inputRec := httptest.NewRecorder()
	s.routes().ServeHTTP(inputRec, inputReq)
	if inputRec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for input send failure, got %d: %s", inputRec.Code, inputRec.Body.String())
	}

	resizeReq := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID+"/resize", mustJSON(t, map[string]int{"cols": 100, "rows": 32}))
	resizeReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	resizeRec := httptest.NewRecorder()
	s.routes().ServeHTTP(resizeRec, resizeReq)
	if resizeRec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for resize send failure, got %d: %s", resizeRec.Code, resizeRec.Body.String())
	}
}

func TestHandleTerminalResize_RejectsClosedAndInvalidBody(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	sessionID := createTerminalSessionForTest(t, s, adminToken, serverID)

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID+"/resize", strings.NewReader("{"))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid resize body, got %d: %s", rec.Code, rec.Body.String())
	}

	if !s.terminalSessions.End(serverID, sessionID, 0, "") {
		t.Fatal("expected terminal session end")
	}
	closedReq := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID+"/resize", mustJSON(t, map[string]int{"cols": 80, "rows": 24}))
	closedReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	closedRec := httptest.NewRecorder()
	s.routes().ServeHTTP(closedRec, closedReq)
	if closedRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for closed resize, got %d: %s", closedRec.Code, closedRec.Body.String())
	}
}

func TestHandleTerminalStream_ServiceUnavailableAndMissingSession(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	s.terminalSessions = nil

	serviceReq := httptest.NewRequest("GET", testServersPrefix+serverID+testTerminalSessionsSuffix+"/missing/stream", nil)
	serviceReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	serviceRec := httptest.NewRecorder()
	s.routes().ServeHTTP(serviceRec, serviceReq)
	if serviceRec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for unavailable terminal stream service, got %d: %s", serviceRec.Code, serviceRec.Body.String())
	}

	s, adminToken, serverID = testServerWithAgent(t)
	missingReq := httptest.NewRequest("GET", testServersPrefix+serverID+testTerminalSessionsSuffix+"/missing/stream", nil)
	missingReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	missingRec := httptest.NewRecorder()
	s.routes().ServeHTTP(missingRec, missingReq)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing stream session, got %d: %s", missingRec.Code, missingRec.Body.String())
	}
}

func TestHandleTerminalStream(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	sessionID := createTerminalSessionForTest(t, s, adminToken, serverID)

	if !s.terminalSessions.End(serverID, sessionID, 0, "") {
		t.Fatal("expected terminal session end")
	}

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID+"/stream", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "bW9jayQg") {
		t.Fatalf("expected base64 terminal output in stream, got %q", body)
	}
	if !strings.Contains(body, "event: exit") {
		t.Fatalf("expected exit event in stream, got %q", body)
	}
}

func TestHandleTerminalStream_RejectsSecondAttach(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	sessionID := createTerminalSessionForTest(t, s, adminToken, serverID)
	admin, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	if _, exists, attached := s.terminalSessions.AttachStream(serverID, sessionID, admin.ID); !exists || !attached {
		t.Fatalf("expected manual stream attachment, exists=%v attached=%v", exists, attached)
	}

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID+"/stream", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for second stream attach, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCloseTerminalSession_MissingSession(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+testTerminalSessionsSuffix+"/missing", bytes.NewReader(nil))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing close session, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCloseTerminalSession(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)
	sessionID := createTerminalSessionForTest(t, s, adminToken, serverID)

	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+testTerminalSessionsSuffix+"/"+sessionID, bytes.NewReader(nil))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := s.terminalSessions.Get(serverID, sessionID); ok {
		t.Fatal("expected terminal session to be removed")
	}

	conn := s.connMgr.GetConn(serverID)
	stream := conn.Stream.(*mockGRPCStream)
	foundClose := false
	for _, msg := range stream.sent {
		if payload := msg.GetTerminalClose(); payload != nil && payload.SessionId == sessionID {
			foundClose = true
		}
	}
	if !foundClose {
		t.Fatal("expected terminal close message")
	}
}
