package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

// mockReEnrollReleaser is a test double for ReEnrollReleaser.
type mockReEnrollReleaser struct {
	called   bool
	serverID string
	adminID  string
	err      error // error to return from ReleaseKEK
}

func (m *mockReEnrollReleaser) ReleaseKEK(serverID, decidedBy string) error {
	m.called = true
	m.serverID = serverID
	m.adminID = decidedBy
	return m.err
}

// newTestServerWithReleaser creates a test server with an injected ReEnrollReleaser.
func newTestServerWithReleaser(t *testing.T, releaser ReEnrollReleaser) *Server {
	t.Helper()
	s := testServer(t)
	s.reEnrollReleaser = releaser
	return s
}

// seedAdminWithTOTP registers the first admin, sets up TOTP, and returns the
// admin's raw (decrypted) TOTP secret and access token.
func seedAdminWithTOTP(t *testing.T, s *Server) (adminID, rawTOTPSecret, accessToken string) {
	t.Helper()
	accessToken = registerAndGetAdminToken(t, s)

	// Retrieve admin from /api/auth/me
	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+accessToken)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)
	var me model.User
	json.NewDecoder(meRec.Body).Decode(&me)
	adminID = me.ID

	// Read back the admin's TOTP secret from the store.
	admin, err := s.store.GetUserByID(adminID)
	if err != nil || admin.TOTPSecret == nil {
		t.Fatalf("seedAdminWithTOTP: cannot load admin TOTP secret: %v", err)
	}
	rawTOTPSecret, err = s.DecryptTOTPSecret(*admin.TOTPSecret)
	if err != nil {
		t.Fatalf("seedAdminWithTOTP: decrypt TOTP: %v", err)
	}
	return adminID, rawTOTPSecret, accessToken
}

// seedReEnrollRequest inserts a server with node crypto and a pending re-enroll request.
func seedReEnrollRequest(t *testing.T, s *Server, adminToken, serverID, requestID string) {
	t.Helper()
	// Create server in the store.
	if err := s.store.CreateServer(&model.Server{ID: serverID, Name: serverID, Status: "offline", Labels: "{}"}); err != nil {
		t.Fatalf("seedReEnrollRequest CreateServer: %v", err)
	}
	// Attach node crypto.
	if err := s.store.SetNodeCrypto(serverID, "dGVzdC1wdWI=", "00112233", "fp-old"); err != nil {
		t.Fatalf("seedReEnrollRequest SetNodeCrypto: %v", err)
	}
	// Insert a pending re-enroll request.
	req := &model.ReEnrollRequest{
		ID:           requestID,
		ServerID:     serverID,
		RequestedAt:  "2026-07-11 00:00:00",
		IPAddress:    "10.0.0.1",
		Fingerprint:  "fp-new",
		Status:       "pending",
		AnomalyFlags: `{"fingerprint_changed":true,"original_online":false}`,
	}
	if err := s.store.CreateReEnrollRequest(req); err != nil {
		t.Fatalf("seedReEnrollRequest CreateReEnrollRequest: %v", err)
	}
}

// TestReEnrollApprove_WrongTOTP verifies that a wrong TOTP code is rejected
// with 401 and that ReleaseKEK is never called.
func TestReEnrollApprove_WrongTOTP(t *testing.T) {
	mock := &mockReEnrollReleaser{}
	s := newTestServerWithReleaser(t, mock)

	_, _, accessToken := seedAdminWithTOTP(t, s)
	seedReEnrollRequest(t, s, accessToken, "srv-reenroll-1", "re-req-1")

	body, _ := json.Marshal(reEnrollApproveRequest{
		RequestID: "re-req-1",
		TOTPCode:  "000000",
	})
	req := httptest.NewRequest("POST", "/api/servers/srv-reenroll-1/reenroll/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if mock.called {
		t.Fatal("ReleaseKEK must NOT be called when TOTP is wrong")
	}

	// Assert the re-enroll request status is still "pending" in the DB.
	dbReq, err := s.store.GetReEnrollRequest("re-req-1")
	if err != nil {
		t.Fatalf("GetReEnrollRequest: %v", err)
	}
	if dbReq.Status != "pending" {
		t.Fatalf("want status=pending after wrong TOTP, got %q", dbReq.Status)
	}
}

// TestReEnrollApprove_CorrectTOTP_ReachesReleaseKEK verifies that a correct
// TOTP code causes ReleaseKEK to be called with the correct serverID.
// The mock releaser returns an error simulating "no pending re-enroll" since
// there is no live gRPC stream in this test — we only need to assert the call
// was made (full stream validation happens in Task 8).
func TestReEnrollApprove_CorrectTOTP_ReachesReleaseKEK(t *testing.T) {
	mock := &mockReEnrollReleaser{err: errors.New("no pending re-enroll for server")}
	s := newTestServerWithReleaser(t, mock)

	_, rawSecret, accessToken := seedAdminWithTOTP(t, s)
	seedReEnrollRequest(t, s, accessToken, "srv-reenroll-2", "re-req-2")

	// Clear the TOTP replay cache so the code generated here is accepted.
	s.ClearTOTPCache()
	code, _ := auth.GenerateValidCode(rawSecret)

	body, _ := json.Marshal(reEnrollApproveRequest{
		RequestID: "re-req-2",
		TOTPCode:  code,
	})
	req := httptest.NewRequest("POST", "/api/servers/srv-reenroll-2/reenroll/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// The mock returns an error → the handler maps it to 404.
	// What matters is that ReleaseKEK was reached.
	if !mock.called {
		t.Fatalf("want ReleaseKEK to be called, got status %d: %s", rec.Code, rec.Body.String())
	}
	if mock.serverID != "srv-reenroll-2" {
		t.Fatalf("ReleaseKEK called with wrong serverID: %q", mock.serverID)
	}
}

// TestReEnrollDeny_Success verifies the deny endpoint marks the request denied.
func TestReEnrollDeny_Success(t *testing.T) {
	s := testServer(t)

	accessToken := registerAndGetAdminToken(t, s)
	seedReEnrollRequest(t, s, accessToken, "srv-deny-1", "re-deny-1")

	body, _ := json.Marshal(reEnrollDenyRequest{RequestID: "re-deny-1"})
	req := httptest.NewRequest("POST", "/api/servers/srv-deny-1/reenroll/deny", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Confirm status is updated in the DB.
	pending, _ := s.store.ListPendingReEnroll()
	for _, r := range pending {
		if r.ID == "re-deny-1" {
			t.Fatal("denied request should not appear in pending list")
		}
	}
}

// TestReEnrollDeny_NoPendingRequest verifies the deny endpoint returns 404 when
// there is no pending re-enroll request for the server.
func TestReEnrollDeny_NoPendingRequest(t *testing.T) {
	s := testServer(t)
	accessToken := registerAndGetAdminToken(t, s)

	// Do NOT seed a re-enroll request — server has no pending request.
	if err := s.store.CreateServer(&model.Server{ID: "srv-deny-nopending", Name: "srv-deny-nopending", Status: "offline", Labels: "{}"}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	body, _ := json.Marshal(reEnrollDenyRequest{RequestID: "re-deny-nonexistent"})
	req := httptest.NewRequest("POST", "/api/servers/srv-deny-nopending/reenroll/deny", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 when no pending request exists, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestReEnrollDeny_MismatchedRequestID verifies the deny endpoint returns 409 when
// the provided request_id does not match the current pending request for the server.
func TestReEnrollDeny_MismatchedRequestID(t *testing.T) {
	s := testServer(t)
	accessToken := registerAndGetAdminToken(t, s)
	// Seed a pending request with ID "re-deny-actual".
	seedReEnrollRequest(t, s, accessToken, "srv-deny-mismatch", "re-deny-actual")

	// Submit a deny with a different request_id.
	body, _ := json.Marshal(reEnrollDenyRequest{RequestID: "re-deny-stale"})
	req := httptest.NewRequest("POST", "/api/servers/srv-deny-mismatch/reenroll/deny", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 when request_id mismatches current pending, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestListPendingReEnroll_Success verifies the GET endpoint returns pending requests.
func TestListPendingReEnroll_Success(t *testing.T) {
	s := testServer(t)

	accessToken := registerAndGetAdminToken(t, s)
	seedReEnrollRequest(t, s, accessToken, "srv-list-1", "re-list-1")
	seedReEnrollRequest(t, s, accessToken, "srv-list-2", "re-list-2")

	req := httptest.NewRequest("GET", "/api/servers/reenroll/pending", nil)
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var list []model.ReEnrollRequest
	json.NewDecoder(rec.Body).Decode(&list)
	if len(list) != 2 {
		t.Fatalf("want 2 pending requests, got %d", len(list))
	}
}

// TestReEnrollApprove_MissingTOTPCode verifies that the endpoint rejects a
// request without a totp_code.
func TestReEnrollApprove_MissingTOTPCode(t *testing.T) {
	mock := &mockReEnrollReleaser{}
	s := newTestServerWithReleaser(t, mock)
	accessToken := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(map[string]string{"request_id": "re-1"})
	req := httptest.NewRequest("POST", "/api/servers/any/reenroll/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if mock.called {
		t.Fatal("ReleaseKEK must not be called on bad request")
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests for handlers_reenroll.go
// ---------------------------------------------------------------------------

// TestReEnrollApprove_BadJSONBody: malformed JSON → 400
func TestReEnrollApprove_BadJSONBody(t *testing.T) {
	mock := &mockReEnrollReleaser{}
	s := newTestServerWithReleaser(t, mock)
	accessToken := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("POST", "/api/servers/srv-1/reenroll/approve", bytes.NewReader([]byte("not-json{{{")))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d: %s", rec.Code, rec.Body.String())
	}
	if mock.called {
		t.Fatal("ReleaseKEK must not be called on malformed body")
	}
}

// TestReEnrollApprove_MissingRequestID: valid TOTP but empty request_id → 400
func TestReEnrollApprove_MissingRequestID(t *testing.T) {
	mock := &mockReEnrollReleaser{}
	s := newTestServerWithReleaser(t, mock)

	_, rawSecret, accessToken := seedAdminWithTOTP(t, s)
	seedReEnrollRequest(t, s, accessToken, "srv-missing-rid", "re-missing-rid-1")

	s.ClearTOTPCache()
	code, _ := auth.GenerateValidCode(rawSecret)

	// Provide TOTP code but no request_id.
	body, _ := json.Marshal(map[string]string{"totp_code": code})
	req := httptest.NewRequest("POST", "/api/servers/srv-missing-rid/reenroll/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty request_id, got %d: %s", rec.Code, rec.Body.String())
	}
	if mock.called {
		t.Fatal("ReleaseKEK must not be called when request_id is missing")
	}
}

// TestReEnrollApprove_NoPendingRequest: valid TOTP + request_id but server has no pending requests → 404
func TestReEnrollApprove_NoPendingRequest(t *testing.T) {
	mock := &mockReEnrollReleaser{}
	s := newTestServerWithReleaser(t, mock)

	_, rawSecret, accessToken := seedAdminWithTOTP(t, s)
	// Create the server but NO pending re-enroll request.
	if err := s.store.CreateServer(&model.Server{ID: "srv-no-pending", Name: "srv-no-pending", Status: "offline", Labels: "{}"}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	s.ClearTOTPCache()
	code, _ := auth.GenerateValidCode(rawSecret)

	body, _ := json.Marshal(reEnrollApproveRequest{RequestID: "re-nonexistent", TOTPCode: code})
	req := httptest.NewRequest("POST", "/api/servers/srv-no-pending/reenroll/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 when no pending request, got %d: %s", rec.Code, rec.Body.String())
	}
	if mock.called {
		t.Fatal("ReleaseKEK must not be called when there is no pending request")
	}
}

// TestReEnrollApprove_MismatchedRequestID: valid TOTP + wrong request_id → 409
func TestReEnrollApprove_MismatchedRequestID(t *testing.T) {
	mock := &mockReEnrollReleaser{}
	s := newTestServerWithReleaser(t, mock)

	_, rawSecret, accessToken := seedAdminWithTOTP(t, s)
	// Seed a pending request with ID "re-actual-id".
	seedReEnrollRequest(t, s, accessToken, "srv-mismatch-id", "re-actual-id")

	s.ClearTOTPCache()
	code, _ := auth.GenerateValidCode(rawSecret)

	// Submit with a different (stale) request_id.
	body, _ := json.Marshal(reEnrollApproveRequest{RequestID: "re-stale-id", TOTPCode: code})
	req := httptest.NewRequest("POST", "/api/servers/srv-mismatch-id/reenroll/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 for mismatched request_id, got %d: %s", rec.Code, rec.Body.String())
	}
	if mock.called {
		t.Fatal("ReleaseKEK must not be called for mismatched request_id")
	}
}

// TestReEnrollApprove_ReleaserNil: valid TOTP + correct request_id but reEnrollReleaser==nil → 503
func TestReEnrollApprove_ReleaserNil(t *testing.T) {
	// Use a plain testServer (no injected releaser).
	s := testServer(t)
	// Confirm the releaser is nil (testServer does not set it).
	s.reEnrollReleaser = nil

	_, rawSecret, accessToken := seedAdminWithTOTP(t, s)
	seedReEnrollRequest(t, s, accessToken, "srv-nil-releaser", "re-nil-releaser-1")

	s.ClearTOTPCache()
	code, _ := auth.GenerateValidCode(rawSecret)

	body, _ := json.Marshal(reEnrollApproveRequest{RequestID: "re-nil-releaser-1", TOTPCode: code})
	req := httptest.NewRequest("POST", "/api/servers/srv-nil-releaser/reenroll/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when releaser is nil, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestReEnrollApprove_ReleaseKEKTimedOut: ReleaseKEK returns error containing "timed out" → 504
func TestReEnrollApprove_ReleaseKEKTimedOut(t *testing.T) {
	mock := &mockReEnrollReleaser{err: errors.New("timed out waiting for agent proof")}
	s := newTestServerWithReleaser(t, mock)

	_, rawSecret, accessToken := seedAdminWithTOTP(t, s)
	seedReEnrollRequest(t, s, accessToken, "srv-timeout", "re-timeout-1")

	s.ClearTOTPCache()
	code, _ := auth.GenerateValidCode(rawSecret)

	body, _ := json.Marshal(reEnrollApproveRequest{RequestID: "re-timeout-1", TOTPCode: code})
	req := httptest.NewRequest("POST", "/api/servers/srv-timeout/reenroll/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("want 504 when ReleaseKEK times out, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestReEnrollApprove_ReleaseKEKGenericError: ReleaseKEK returns generic error → 409
func TestReEnrollApprove_ReleaseKEKGenericError(t *testing.T) {
	mock := &mockReEnrollReleaser{err: errors.New("something went wrong")}
	s := newTestServerWithReleaser(t, mock)

	_, rawSecret, accessToken := seedAdminWithTOTP(t, s)
	seedReEnrollRequest(t, s, accessToken, "srv-generr", "re-generr-1")

	s.ClearTOTPCache()
	code, _ := auth.GenerateValidCode(rawSecret)

	body, _ := json.Marshal(reEnrollApproveRequest{RequestID: "re-generr-1", TOTPCode: code})
	req := httptest.NewRequest("POST", "/api/servers/srv-generr/reenroll/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 for generic ReleaseKEK error, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestReEnrollDeny_BadJSONBody: malformed JSON → 400
func TestReEnrollDeny_BadJSONBody(t *testing.T) {
	s := testServer(t)
	accessToken := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("POST", "/api/servers/srv-1/reenroll/deny", bytes.NewReader([]byte("not-json{{{")))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestReEnrollDeny_MissingRequestID: empty request_id field → 400
func TestReEnrollDeny_MissingRequestID(t *testing.T) {
	s := testServer(t)
	accessToken := registerAndGetAdminToken(t, s)

	// Provide an empty request_id.
	body, _ := json.Marshal(reEnrollDenyRequest{RequestID: ""})
	req := httptest.NewRequest("POST", "/api/servers/srv-1/reenroll/deny", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty request_id, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestListPendingReEnroll_Empty: no pending requests → 200 with [] (not null)
func TestListPendingReEnroll_Empty(t *testing.T) {
	s := testServer(t)
	accessToken := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/reenroll/pending", nil)
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Body must be [] not null.
	var list []model.ReEnrollRequest
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if list == nil {
		t.Fatal("want [] (non-nil empty slice) in response, got null")
	}
	if len(list) != 0 {
		t.Fatalf("want 0 pending requests, got %d", len(list))
	}
}

// TestReEnrollApprove_Success: valid TOTP + matching request_id + releaser
// returning nil → 200 {"status":"approved"} and a ReEnrollApproved audit entry.
// This covers the success tail of handleReEnrollApprove (audit + respondJSON 200).
func TestReEnrollApprove_Success(t *testing.T) {
	mock := &mockReEnrollReleaser{} // err==nil → ReleaseKEK succeeds.
	s := newTestServerWithReleaser(t, mock)

	_, rawSecret, accessToken := seedAdminWithTOTP(t, s)
	seedReEnrollRequest(t, s, accessToken, "srv-approve-ok", "re-approve-ok-1")

	s.ClearTOTPCache()
	code, _ := auth.GenerateValidCode(rawSecret)

	body, _ := json.Marshal(reEnrollApproveRequest{RequestID: "re-approve-ok-1", TOTPCode: code})
	req := httptest.NewRequest("POST", "/api/servers/srv-approve-ok/reenroll/approve", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+accessToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 on successful approve, got %d: %s", rec.Code, rec.Body.String())
	}
	if !mock.called || mock.serverID != "srv-approve-ok" {
		t.Fatalf("expected ReleaseKEK called with srv-approve-ok, got called=%v id=%q", mock.called, mock.serverID)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "approved" {
		t.Fatalf("want status=approved, got %q", resp["status"])
	}

	// A ReEnrollApproved audit entry must have been recorded.
	action := model.AuditReEnrollApproved
	_, total, err := s.store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 10})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if total < 1 {
		t.Fatalf("expected a re-enroll approved audit entry, got total=%d", total)
	}
}
