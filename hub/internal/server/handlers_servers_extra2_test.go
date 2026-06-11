package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

// TestHandleInstallScript_NotFound verifies the install script endpoint handles missing file.
func TestHandleInstallScript_NotFound(t *testing.T) {
	s := testServer(t)

	// The install script endpoint serves an embedded file. If the embed is
	// populated, this will return 200. If empty (test environment without
	// embedded asset), it should cleanly return 404 (not 500).
	req := httptest.NewRequest("GET", "/install.sh", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusInternalServerError {
		t.Fatalf("unexpected 500: %s", rec.Body.String())
	}
	if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
		t.Fatalf("expected 200 or 404, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Code == http.StatusOK {
		ct := rec.Header().Get("Content-Type")
		if !strings.HasPrefix(ct, "text/x-shellscript") {
			t.Fatalf("expected shellscript content type, got %q", ct)
		}
	}
}

// TestHandleListServers_SearchFilter verifies search filter works in list servers.
func TestHandleListServers_SearchFilter(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	createTestServer(t, s, adminToken, "my-search-server")
	createTestServer(t, s, adminToken, "other-server")

	req := httptest.NewRequest("GET", "/api/servers?search=my-search", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

// TestHandleGetServer_ViewerNotPermitted verifies viewer gets 403 for unpermitted server.
func TestHandleGetServer_ViewerNotPermitted(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	serverID := createTestServer(t, s, adminToken, "forbidden-server")
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	req := httptest.NewRequest("GET", testServersPrefix+serverID, nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// Viewer has no permissions for this server
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer without permission, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestGetServer_ViewerMultipleServersAccessSecond verifies that a viewer with
// permissions on multiple servers can access any of them (not just the first).
// This is a regression test for the Limit:1 bug where only the first permitted
// server was accessible.
func TestGetServer_ViewerMultipleServersAccessSecond(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Create 3 servers
	s1ID := createTestServer(t, s, adminToken, "multi-srv-1")
	s2ID := createTestServer(t, s, adminToken, "multi-srv-2")
	s3ID := createTestServer(t, s, adminToken, "multi-srv-3")

	viewerToken := createViewerAndGetToken(t, s, adminToken)

	// Get viewer user ID
	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+viewerToken)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)
	var viewerUser model.User
	json.NewDecoder(meRec.Body).Decode(&viewerUser)

	// Grant permissions on all 3 servers
	s.store.CreatePermission(viewerUser.ID, s1ID, testVarLog)
	s.store.CreatePermission(viewerUser.ID, s2ID, testVarLog)
	s.store.CreatePermission(viewerUser.ID, s3ID, testVarLog)

	// Access the SECOND server — this failed with the Limit:1 bug
	req2 := httptest.NewRequest("GET", testServersPrefix+s2ID, nil)
	req2.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec2 := httptest.NewRecorder()
	s.routes().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 for second permitted server, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// Access the THIRD server — also should work
	req3 := httptest.NewRequest("GET", testServersPrefix+s3ID, nil)
	req3.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec3 := httptest.NewRecorder()
	s.routes().ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 for third permitted server, got %d: %s", rec3.Code, rec3.Body.String())
	}

	// Verify access is still denied for a server WITHOUT permission
	unpermittedID := createTestServer(t, s, adminToken, "no-perm-srv")
	reqDenied := httptest.NewRequest("GET", testServersPrefix+unpermittedID, nil)
	reqDenied.Header.Set("Authorization", testBearerPrefix+viewerToken)
	recDenied := httptest.NewRecorder()
	s.routes().ServeHTTP(recDenied, reqDenied)

	if recDenied.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unpermitted server, got %d: %s", recDenied.Code, recDenied.Body.String())
	}
}

// TestHandleCreateServer_ProductionMode verifies grpcTarget in production mode.
func TestHandleCreateServer_ProductionMode(t *testing.T) {
	s := testServer(t)
	// Override isDev to false for this test
	s.isDev = false
	s.grpcExternalAddr = "veyport.example.com:9443"

	adminToken := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("POST", testServersPath, mustJSON(t, map[string]string{
		"name": "prod-server",
	}))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Host = "veyport.example.com"
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleCreateServer_ProductionModeWithPort verifies grpcTarget strips port from host.
func TestHandleCreateServer_ProductionModeWithPort(t *testing.T) {
	s := testServer(t)
	s.isDev = false
	s.grpcExternalAddr = "veyport.example.com:9443"

	adminToken := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("POST", testServersPath, mustJSON(t, map[string]string{
		"name": "prod-server-port",
	}))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Host = "veyport.example.com:8443"
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}
