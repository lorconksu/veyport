package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

// TestHandleListFiles_ViewerWithPermissionNoAgent verifies viewer with permission
// but no agent gets 502 (passes the permission check).
func TestHandleListFiles_ViewerWithPermissionNoAgent(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	srvReq := httptest.NewRequest("POST", testServersPath, mustJSON(t, model.CreateServerRequest{Name: "files-perm-srv"}))
	srvReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	srvRec := httptest.NewRecorder()
	s.routes().ServeHTTP(srvRec, srvReq)
	var srvResp model.CreateServerResponse
	json.NewDecoder(srvRec.Body).Decode(&srvResp)
	serverID := srvResp.Server.ID

	viewerToken := createViewerAndGetToken(t, s, adminToken)
	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+viewerToken)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)

	var viewerUser interface{}
	json.NewDecoder(meRec.Body).Decode(&viewerUser)
	viewerID := viewerUser.(map[string]interface{})["id"].(string)

	// Grant permission for /var/log
	s.store.CreatePermission(viewerID, serverID, testVarLog)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+testFilesQuery, nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// Should reach agent check (502), not permission denial (403)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("viewer with permission should not get 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf(testExpected502Body, rec.Code, rec.Body.String())
	}
}

// TestHandleReadFile_ViewerWithPermissionNoAgent verifies viewer with permission
// but no agent gets 502.
func TestHandleReadFile_ViewerWithPermissionNoAgent(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	srvReq := httptest.NewRequest("POST", testServersPath, mustJSON(t, model.CreateServerRequest{Name: "read-perm-srv"}))
	srvReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	srvRec := httptest.NewRecorder()
	s.routes().ServeHTTP(srvRec, srvReq)
	var srvResp model.CreateServerResponse
	json.NewDecoder(srvRec.Body).Decode(&srvResp)
	serverID := srvResp.Server.ID

	viewerToken := createViewerAndGetToken(t, s, adminToken)
	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+viewerToken)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)

	var viewerUser interface{}
	json.NewDecoder(meRec.Body).Decode(&viewerUser)
	viewerID := viewerUser.(map[string]interface{})["id"].(string)

	// Grant permission for /var/log
	s.store.CreatePermission(viewerID, serverID, testVarLog)

	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files/read?path=/var/log/syslog", nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// Should reach agent check (502), not permission denial (403)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("viewer with permission should not get 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf(testExpected502Body, rec.Code, rec.Body.String())
	}
}

// TestIsPathAllowed_ErrorFromStore verifies that a store error returns false.
func TestHandleListFiles_AdminDefaultPath(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	serverID := createTestServer(t, s, adminToken, "list-default")

	// Admin with default path "/" — should reach agent check, not 400
	req := httptest.NewRequest("GET", testServersPrefix+serverID+"/files", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusBadRequest {
		t.Fatalf("expected no 400 for default path, got: %s", rec.Body.String())
	}
}
