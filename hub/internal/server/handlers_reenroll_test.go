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
