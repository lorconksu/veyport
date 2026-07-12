package server

// Coverage top-up tests for handlers_reenroll.go — these tests cover branches
// that are unreachable through the normal HTTP router (missing PathValue) or
// require injecting specific internal state (e.g., GetUserByID error).
// They call the handler methods directly on a *Server to hit those branches.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auth"
)

// withUserID injects a user ID into the request context so handlers can call
// UserIDFromContext without going through the full auth middleware.
func withUserID(r *http.Request, userID string) *http.Request {
	ctx := context.WithValue(r.Context(), ctxUserID, userID)
	return r.WithContext(ctx)
}

// ---------------------------------------------------------------------------
// handleReEnrollApprove — missing server ID branch
// ---------------------------------------------------------------------------

// TestReEnrollApprove_MissingServerIDDirect calls handleReEnrollApprove directly
// (bypassing the router) with no PathValue("id") set so serverID == "".
// Expected: 400 Bad Request with "missing server id".
func TestReEnrollApprove_MissingServerIDDirect(t *testing.T) {
	s := testServer(t)
	// Seed an admin so we have a valid user context, but we call the handler
	// directly and only need the missing-serverID branch — which fires before
	// any DB call.

	body, _ := json.Marshal(reEnrollApproveRequest{RequestID: "re-1", TOTPCode: "123456"})
	req := httptest.NewRequest("POST", "/api/servers//reenroll/approve", bytes.NewReader(body))
	// Deliberately do NOT set a PathValue — PathValue("id") returns "".
	req = withUserID(req, "admin-x")
	rec := httptest.NewRecorder()

	s.handleReEnrollApprove(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing server id, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// handleReEnrollDeny — missing server ID branch
// ---------------------------------------------------------------------------

// TestReEnrollDeny_MissingServerIDDirect calls handleReEnrollDeny directly with
// no PathValue("id") set — covers the "missing server id" guard (lines 133-136).
func TestReEnrollDeny_MissingServerIDDirect(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(reEnrollDenyRequest{RequestID: "re-1"})
	req := httptest.NewRequest("POST", "/api/servers//reenroll/deny", bytes.NewReader(body))
	req = withUserID(req, "admin-x")
	rec := httptest.NewRecorder()

	s.handleReEnrollDeny(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing server id, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// handleReEnrollApprove — GetUserByID failure branch
// ---------------------------------------------------------------------------

// TestReEnrollApprove_UserNotFound covers lines 49-52: valid TOTP code is
// provided but the admin's user record cannot be found in the DB.
// We close the store AFTER TOTP validation by injecting a non-existent user ID
// into the context (so GetUserByID returns ErrNotFound immediately).
func TestReEnrollApprove_UserNotFound(t *testing.T) {
	mock := &mockReEnrollReleaser{}
	s := newTestServerWithReleaser(t, mock)

	// Seed an admin and a re-enroll request.
	_, rawSecret, accessToken := seedAdminWithTOTP(t, s)
	seedReEnrollRequest(t, s, accessToken, "srv-user-nf", "re-user-nf-1")

	s.ClearTOTPCache()
	code, _ := auth.GenerateValidCode(rawSecret)

	body, _ := json.Marshal(reEnrollApproveRequest{RequestID: "re-user-nf-1", TOTPCode: code})
	req := httptest.NewRequest("POST", "/api/servers/srv-user-nf/reenroll/approve", bytes.NewReader(body))

	// Inject a user ID that does NOT exist in the DB → GetUserByID will fail.
	req = withUserID(req, "nonexistent-admin-id")

	// Set the PathValue so the router would have matched {id}.
	req.SetPathValue("id", "srv-user-nf")
	rec := httptest.NewRecorder()

	s.handleReEnrollApprove(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when GetUserByID fails, got %d: %s", rec.Code, rec.Body.String())
	}
	if mock.called {
		t.Fatal("ReleaseKEK must not be called when GetUserByID fails")
	}
}

// ---------------------------------------------------------------------------
// handleListPendingReEnroll — store failure branch
// ---------------------------------------------------------------------------

// TestListPendingReEnroll_StoreFailure covers lines 195-198: the ListPendingReEnroll
// query fails (store is closed). Call the handler directly with a closed store.
func TestListPendingReEnroll_StoreFailure(t *testing.T) {
	s := testServer(t)
	accessToken := registerAndGetAdminToken(t, s)

	// Close the store so the DB query fails.
	s.store.Close()

	req := httptest.NewRequest("GET", "/api/servers/reenroll/pending", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req = withUserID(req, "admin-x")
	rec := httptest.NewRecorder()

	s.handleListPendingReEnroll(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when store is closed, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// handleReEnrollDeny — ListPendingReEnroll and UpdateReEnrollStatus failure branches
// ---------------------------------------------------------------------------

// TestReEnrollDeny_ListPendingReEnrollFails covers lines 154-157: the deny handler
// calls ListPendingReEnroll and the store is closed → 500.
func TestReEnrollDeny_ListPendingReEnrollFails(t *testing.T) {
	s := testServer(t)

	// Close the store BEFORE the request so ListPendingReEnroll fails.
	s.store.Close()

	body, _ := json.Marshal(reEnrollDenyRequest{RequestID: "re-1"})
	req := httptest.NewRequest("POST", "/api/servers/srv-1/reenroll/deny", bytes.NewReader(body))
	req.SetPathValue("id", "srv-1")
	req = withUserID(req, "admin-x")
	rec := httptest.NewRecorder()

	s.handleReEnrollDeny(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when ListPendingReEnroll fails in deny, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Note: UpdateReEnrollStatus failure path (lines 174-177 in handlers_reenroll.go)
// requires the store to fail ONLY on the UPDATE while allowing the preceding
// SELECT (ListPendingReEnroll) to succeed. This is not achievable with the real
// SQLite store without a mock; that path is left uncovered.
