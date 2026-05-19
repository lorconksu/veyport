package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

// createTestServer creates a server in the store and returns its ID.
func createTestServer(t *testing.T, s *Server, adminToken, name string) string {
	t.Helper()
	req := httptest.NewRequest("POST", testServersPath, mustJSON(t, model.CreateServerRequest{Name: name}))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("createTestServer: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.CreateServerResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	return resp.Server.ID
}

// createTestViewer creates a viewer user, returns their user ID and access token.
func createTestViewer(t *testing.T, s *Server, adminToken, username, email string) (string, string) {
	t.Helper()

	// Create user
	createReq := httptest.NewRequest("POST", testUsersPath, mustJSON(t, model.CreateUserRequest{
		Username: username, Email: email, Role: model.RoleViewer,
	}))
	createReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("createTestViewer: expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}
	var createResp model.CreateUserResponse
	json.NewDecoder(createRec.Body).Decode(&createResp)
	return createResp.User.ID, ""
}

// TestHandleListPaths_Empty verifies that listing paths for a server with no permissions returns empty.
func TestHandleListPaths_Empty(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-list-empty")

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testPathsSuffix, nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	paths := resp["paths"].([]interface{})
	if len(paths) != 0 {
		t.Fatalf("expected 0 paths, got %d", len(paths))
	}
}

// TestHandleCreatePath_Success verifies that creating a path permission works.
func TestHandleCreatePath_Success(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-create-path")

	// Create a viewer user to grant the path to
	viewerID, _ := createTestViewer(t, s, adminToken, "pathviewer", "pathviewer@test.com")

	body := mustJSON(t, map[string]string{
		"user_id": viewerID,
		"path":    testVarLog,
	})
	req := httptest.NewRequest("POST", testServersPrefix+serverID+testPathsSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var perm model.Permission
	json.NewDecoder(rec.Body).Decode(&perm)
	if perm.Path != testVarLog {
		t.Fatalf("expected path '/var/log', got '%s'", perm.Path)
	}
	if perm.UserID != viewerID {
		t.Fatalf("expected user_id '%s', got '%s'", viewerID, perm.UserID)
	}
	if perm.ServerID != serverID {
		t.Fatalf("expected server_id '%s', got '%s'", serverID, perm.ServerID)
	}
}

// TestHandleCreatePath_MissingFields verifies that missing user_id or path returns 400.
func TestHandleCreatePath_MissingFields(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-missing-fields")

	tests := []struct {
		name string
		body interface{}
	}{
		{"missing user_id", map[string]string{"path": testVarLog}},
		{"missing path", map[string]string{"user_id": "some-id"}},
		{"both missing", map[string]string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", testServersPrefix+serverID+testPathsSuffix, mustJSON(t, tc.body))
			req.Header.Set("Authorization", testBearerPrefix+adminToken)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestHandleDeletePath_Success verifies that deleting a path permission works.
func TestHandleDeletePath_Success(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-delete-path")

	viewerID, _ := createTestViewer(t, s, adminToken, "pathdelviewer", "pathdelviewer@test.com")

	// Create the permission
	createReq := httptest.NewRequest("POST", testServersPrefix+serverID+testPathsSuffix, mustJSON(t, map[string]string{
		"user_id": viewerID,
		"path":    testVarLog,
	}))
	createReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating path, got %d", createRec.Code)
	}

	var perm model.Permission
	json.NewDecoder(createRec.Body).Decode(&perm)

	// Delete the permission
	delReq := httptest.NewRequest("DELETE", testServersPrefix+serverID+"/paths/"+perm.ID, nil)
	delReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	delRec := httptest.NewRecorder()
	s.routes().ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", delRec.Code, delRec.Body.String())
	}
}

// TestHandleDeletePath_NotFound verifies that deleting a non-existent permission returns 404.
func TestHandleDeletePath_NotFound(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-delete-notfound")

	req := httptest.NewRequest("DELETE", testServersPrefix+serverID+"/paths/nonexistent-id", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleGetUserPaths_Admin verifies that admin gets "/" as their allowed path.
func TestHandleGetUserPaths_Admin(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-my-paths-admin")

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/my-paths", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	paths := resp["paths"].([]interface{})
	if len(paths) != 1 || paths[0].(string) != "/" {
		t.Fatalf("expected admin to have paths=['/'], got %v", paths)
	}
}

// TestHandleGetUserPaths_Viewer verifies that a viewer with granted paths sees their paths.
func TestHandleGetUserPaths_Viewer(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-my-paths-viewer")

	viewerID, _ := createTestViewer(t, s, adminToken, "mypathviewer", "mypathviewer@test.com")
	viewerToken := createViewerAndGetToken(t, s, adminToken)
	_ = viewerToken // We won't use this — we'll register a second viewer

	// Grant path to the viewer
	s.store.CreatePermission(viewerID, serverID, testVarLog)

	// To test the viewer's own my-paths, we need a token for viewerID.
	// The createViewerAndGetToken helper creates a "viewertest" user.
	// We need to check the my-paths for a user whose token we have.
	// Use the "viewertest" user (created by createViewerAndGetToken).
	// Get their ID from the store.
	user, err := s.store.GetUserByUsername("viewertest")
	if err != nil {
		t.Fatalf("get viewertest user: %v", err)
	}

	// Grant path to viewertest
	s.store.CreatePermission(user.ID, serverID, "/etc")

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/my-paths", nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	paths := resp["paths"].([]interface{})
	if len(paths) != 1 || paths[0].(string) != "/etc" {
		t.Fatalf("expected viewer to have paths=['/etc'], got %v", paths)
	}
}

// TestHandleListPaths_RequiresAdmin verifies that non-admin cannot list all paths.
func TestHandleListPaths_RequiresAdmin(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-list-requires-admin")
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testPathsSuffix, nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer, got %d", rec.Code)
	}
}

// TestHandleCreatePath_PathTraversal verifies that path traversal is rejected.
func TestHandleCreatePath_PathTraversal(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-path-traversal")
	viewerID, _ := createTestViewer(t, s, adminToken, "travviewer", "travviewer@test.com")

	tests := []struct {
		name string
		path string
	}{
		{"dot-dot traversal", "../../etc"},
		{"absolute with dot-dot", "/var/log/../../etc/passwd"},
		{"relative path", "var/log"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := mustJSON(t, map[string]string{
				"user_id": viewerID,
				"path":    tc.path,
			})
			req := httptest.NewRequest("POST", testServersPrefix+serverID+testPathsSuffix, body)
			req.Header.Set("Authorization", testBearerPrefix+adminToken)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for path %q, got %d: %s", tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestHandleCreatePath_InvalidBody verifies that a malformed request body returns 400.
func TestHandleCreatePath_InvalidBody(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "srv-invalid-body")

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testPathsSuffix, mustJSON(t, "not an object"))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// A string body parses to empty struct fields, so expect 400
	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
}
