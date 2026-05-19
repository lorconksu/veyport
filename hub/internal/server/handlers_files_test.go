package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

// TestValidateRequestPath tests the path validation helper directly.
func TestValidateRequestPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"absolute path OK", "/var/log/syslog", false},
		{"root path OK", "/", false},
		{"relative path rejected", "var/log", true},
		{"path traversal rejected", "/var/../etc/passwd", true},
		{"path traversal double-dot rejected", "/var/log/../../etc", true},
		{"no leading slash", "etc/passwd", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRequestPath(tc.path)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for path %q, got nil", tc.path)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for path %q, got %v", tc.path, err)
			}
		})
	}
}

// TestIsPathAllowed tests the permission-check helper against the store.
func TestIsPathAllowed(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Create a server to get a valid server ID
	req := httptest.NewRequest("POST", testServersPath, mustJSON(t, model.CreateServerRequest{Name: "perm-server"}))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	var srvResp model.CreateServerResponse
	json.NewDecoder(rec.Body).Decode(&srvResp)
	serverID := srvResp.Server.ID

	// Create a viewer user
	viewerReq := httptest.NewRequest("POST", testUsersPath, mustJSON(t, model.CreateUserRequest{
		Username: "viewer1", Email: testViewerEmail, Role: model.RoleViewer,
	}))
	viewerReq.Header.Set("Authorization", testBearerPrefix+token)
	viewerRec := httptest.NewRecorder()
	s.routes().ServeHTTP(viewerRec, viewerReq)
	var viewerResp model.CreateUserResponse
	json.NewDecoder(viewerRec.Body).Decode(&viewerResp)
	viewerID := viewerResp.User.ID

	// Add a path permission for the viewer
	s.store.CreatePermission(viewerID, serverID, testVarLog)

	tests := []struct {
		name        string
		path        string
		wantAllowed bool
	}{
		{"exact match allowed", testVarLog, true},
		{"child path allowed", "/var/log/syslog", true},
		{"deep child path allowed", "/var/log/app/service.log", true},
		{"unrelated path denied", "/etc/passwd", false},
		{"parent path denied", "/var", false},
		{"prefix-but-not-child denied", "/var/logs", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := s.isPathAllowed(viewerID, serverID, tc.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tc.wantAllowed {
				t.Fatalf("isPathAllowed(%q) = %v, want %v", tc.path, allowed, tc.wantAllowed)
			}
		})
	}
}

// TestHandleListFiles_PathTraversal verifies path traversal is rejected with 400.
func TestHandleListFiles_PathTraversal(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/s1/files?path=/../etc/passwd", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for path traversal, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleListFiles_NoAgent verifies that a valid path with no connected agent returns 502.
func TestHandleListFiles_NoAgent(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/s1/files?path=/var/log", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf(testExpected502Body, rec.Code, rec.Body.String())
	}
}

// TestHandleListFiles_DefaultPath verifies the handler accepts no path param (defaults to /).
// Without a connected agent this will end at 502, but the path validation passes.
func TestHandleListFiles_DefaultPath(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/s1/files", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// Without an agent we get 502, NOT 400 — the default "/" is valid
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("expected valid path to not return 400, got: %s", rec.Body.String())
	}
}

// TestHandleReadFile_NoPath verifies missing path returns 400.
func TestHandleReadFile_NoPath(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/s1/files/read", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing path, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleReadFile_PathTraversal verifies path traversal is rejected with 400.
func TestHandleReadFile_PathTraversal(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/s1/files/read?path=/../etc/passwd", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for path traversal, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleReadFile_NoAgent verifies that a valid path with no connected agent returns 502.
func TestHandleReadFile_NoAgent(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/s1/files/read?path=/etc/hosts", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf(testExpected502Body, rec.Code, rec.Body.String())
	}
}

// TestHandleListFiles_ViewerPermissionDenied verifies non-admin with no paths gets 403.
func TestHandleListFiles_ViewerPermissionDenied(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Create server
	srvReq := httptest.NewRequest("POST", testServersPath, mustJSON(t, model.CreateServerRequest{Name: "test-srv"}))
	srvReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	srvRec := httptest.NewRecorder()
	s.routes().ServeHTTP(srvRec, srvReq)
	var srvResp model.CreateServerResponse
	json.NewDecoder(srvRec.Body).Decode(&srvResp)
	serverID := srvResp.Server.ID

	// Create viewer and get their token
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	// Viewer tries to access a path they have no permission for
	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files?path=/etc", nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer with no paths, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleReadFile_ViewerPermissionDenied verifies non-admin with no paths gets 403.
func TestHandleReadFile_ViewerPermissionDenied(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Create server
	srvReq := httptest.NewRequest("POST", testServersPath, mustJSON(t, model.CreateServerRequest{Name: "test-srv2"}))
	srvReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	srvRec := httptest.NewRecorder()
	s.routes().ServeHTTP(srvRec, srvReq)
	var srvResp model.CreateServerResponse
	json.NewDecoder(srvRec.Body).Decode(&srvResp)
	serverID := srvResp.Server.ID

	viewerToken := createViewerAndGetToken(t, s, adminToken)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files/read?path=/etc/passwd", nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer with no paths, got %d: %s", rec.Code, rec.Body.String())
	}
}
