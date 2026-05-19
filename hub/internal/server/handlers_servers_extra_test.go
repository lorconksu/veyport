package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

// TestListServers_Viewer verifies that viewers see only their permitted servers.
func TestListServers_Viewer(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Create servers
	s1ID := createTestServer(t, s, adminToken, "srv-viewer-1")
	s2ID := createTestServer(t, s, adminToken, "srv-viewer-2")

	viewerToken := createViewerAndGetToken(t, s, adminToken)

	// Get viewer's user ID
	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+viewerToken)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)
	var viewerUser model.User
	json.NewDecoder(meRec.Body).Decode(&viewerUser)

	// Grant permission for only s1
	s.store.CreatePermission(viewerUser.ID, s1ID, testVarLog)

	req := httptest.NewRequest("GET", testServersPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	total := int(resp["total"].(float64))
	if total != 1 {
		t.Fatalf("viewer should see only 1 server (permitted), got %d", total)
	}
	_ = s2ID
}

// TestListServers_SearchFilter verifies that search query param works.
func TestListServers_SearchFilter(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	s.store.CreateServer(&model.Server{ID: "s1", Name: "web-prod", Status: "online", Labels: "{}"})
	s.store.CreateServer(&model.Server{ID: "s2", Name: "db-prod", Status: "online", Labels: "{}"})
	s.store.CreateServer(&model.Server{ID: "s3", Name: "cache-dev", Status: "online", Labels: "{}"})

	req := httptest.NewRequest("GET", "/api/servers?search=prod", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200, rec.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	total := int(resp["total"].(float64))
	if total != 2 {
		t.Fatalf("expected 2 servers matching 'prod', got %d", total)
	}
}

// TestListServers_PaginationParams verifies limit/offset params are respected.
func TestListServers_PaginationParams(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	for i := 0; i < 5; i++ {
		s.store.CreateServer(&model.Server{
			ID:     "srv-" + string(rune('a'+i)),
			Name:   "server-" + string(rune('a'+i)),
			Status: "online",
			Labels: "{}",
		})
	}

	req := httptest.NewRequest("GET", "/api/servers?limit=2&offset=0", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200, rec.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	servers := resp["servers"].([]interface{})
	if len(servers) > 2 {
		t.Fatalf("expected at most 2 servers with limit=2, got %d", len(servers))
	}
}

// TestGetServer_ViewerWithPermission verifies that a viewer with permission can get a server.
func TestGetServer_ViewerWithPermission(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	serverID := createTestServer(t, s, adminToken, "viewer-permitted-srv")

	viewerToken := createViewerAndGetToken(t, s, adminToken)
	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+viewerToken)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)
	var viewerUser model.User
	json.NewDecoder(meRec.Body).Decode(&viewerUser)

	// Grant permission for this server
	s.store.CreatePermission(viewerUser.ID, serverID, testVarLog)

	req := httptest.NewRequest("GET", testServersPrefix+serverID, nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for viewer with permission, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestGetServer_ViewerWithoutPermission verifies that a viewer without permission gets 403.
func TestGetServer_ViewerWithoutPermission(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	serverID := createTestServer(t, s, adminToken, "no-perm-srv")
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	req := httptest.NewRequest("GET", testServersPrefix+serverID, nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer without permission, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateServer_InvalidJSON verifies invalid JSON returns 400.
func TestUpdateServer_InvalidJSON(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("PUT", testServerS1Path, bytes.NewReader([]byte(testNotJSON)))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

// TestUpdateServer_EmptyName verifies empty name returns 400.
func TestUpdateServer_EmptyName(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(map[string]string{"name": "", "labels": "{}"})
	req := httptest.NewRequest("PUT", testServerS1Path, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

// TestUpdateServer_NotFound verifies non-existent server returns 404.
func TestUpdateServer_NotFound(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(map[string]string{"name": "new-name", "labels": "{}"})
	req := httptest.NewRequest("PUT", "/api/servers/nonexistent-id", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// TestDeleteServer_NotFound verifies deleting non-existent server returns 404.
func TestDeleteServer_NotFound(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("DELETE", "/api/servers/nonexistent-id", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestBatchDeleteServers_InvalidJSON verifies invalid JSON returns 400.
func TestBatchDeleteServers_InvalidJSON(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("POST", "/api/servers/batch-delete", bytes.NewReader([]byte(testNotJSON)))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

// TestCreateServer_InvalidJSON verifies invalid JSON returns 400.
func TestCreateServer_InvalidJSON(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("POST", testServersPath, bytes.NewReader([]byte(testNotJSON)))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

// TestHandleAgentBinary_UnsupportedOS verifies unsupported OS returns 404.
func TestHandleAgentBinary_UnsupportedOS(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/install/windows/amd64", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unsupported OS, got %d", rec.Code)
	}
}

// TestHandleAgentBinary_UnsupportedArch verifies unsupported arch returns 404.
func TestHandleAgentBinary_UnsupportedArch(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/install/linux/386", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unsupported arch, got %d", rec.Code)
	}
}

// TestHandleAgentBinary_ValidPlatformMissingFile verifies valid platform but missing binary returns 404.
func TestHandleAgentBinary_ValidPlatformMissingFile(t *testing.T) {
	s := testServer(t)
	// agentBinDir defaults to "" which means no binary will be found

	req := httptest.NewRequest("GET", "/install/linux/amd64", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing binary file, got %d", rec.Code)
	}
}
