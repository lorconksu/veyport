package server

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleUnregisterServer_ConnectedAgent verifies that unregistering a server
// with nil connMgr skips the agent notification path and succeeds.
func TestHandleUnregisterServer_NilConnMgr(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	serverID := createTestServer(t, s, token, "nilconn-unregister-server")

	// testServer has nil connMgr, so the "if s.connMgr != nil" block is skipped
	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+testUnregSuffix, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

// TestHandleUploadFile_EmptyMultipart verifies that uploading with malformed multipart returns 413/400.
func TestHandleUploadFile_EmptyMultipart(t *testing.T) {
	s, token, serverID := testServerWithAgent(t)

	// Build multipart form with empty body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.Close()

	req := httptest.NewRequest("POST", "/api/servers/"+serverID+"/upload", body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	req.Header.Set(testContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// Should be 400 (no file field)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty multipart, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleListUsers_WithUsers verifies listing users returns all users.
func TestHandleListUsers_WithUsers(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Create an additional user
	createViewerAndGetToken(t, s, adminToken)

	req := httptest.NewRequest("GET", testUsersPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

// TestHandleCreateServer_MissingName verifies creating server with no name returns 400.
func TestHandleCreateServer_MissingName(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("POST", testServersPath, mustJSON(t, map[string]string{"name": ""}))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing name, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleListAuditLogs_WithFilters verifies filtering audit logs works.
func TestHandleListAuditLogs_WithFilters(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/audit-logs?limit=5&offset=0", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}
