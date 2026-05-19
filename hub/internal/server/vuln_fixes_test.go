package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

// #36: Verify non-admin users get 403 for both nonexistent and unauthorized servers.
func TestGetServer_ViewerNonexistentReturns403(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	// Request a nonexistent server as viewer — should get 403, not 404
	req := httptest.NewRequest("GET", "/api/servers/nonexistent-id", nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for nonexistent server as viewer, got %d: %s", rec.Code, rec.Body.String())
	}
}

// #36: Admin still gets 404 for nonexistent servers (expected behavior).
func TestGetServer_AdminNonexistentReturns404(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/nonexistent-id", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent server as admin, got %d: %s", rec.Code, rec.Body.String())
	}
}

// #45: Verify duplicate server names are rejected.
func TestCreateServer_DuplicateName(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body1, _ := json.Marshal(model.CreateServerRequest{Name: "same-name"})
	req1 := httptest.NewRequest("POST", testServersPath, bytes.NewReader(body1))
	req1.Header.Set("Authorization", testBearerPrefix+token)
	rec1 := httptest.NewRecorder()
	s.routes().ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusCreated {
		t.Fatalf("expected 201 for first server, got %d: %s", rec1.Code, rec1.Body.String())
	}

	body2, _ := json.Marshal(model.CreateServerRequest{Name: "same-name"})
	req2 := httptest.NewRequest("POST", testServersPath, bytes.NewReader(body2))
	req2.Header.Set("Authorization", testBearerPrefix+token)
	rec2 := httptest.NewRecorder()
	s.routes().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate name, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// #44: Verify user deletion warns about exclusive server access.
func TestDeleteUser_ExclusiveServerAccess(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Create a viewer user
	createBody, _ := json.Marshal(model.CreateUserRequest{
		Username: "viewer1", Email: testViewerEmail, Role: model.RoleViewer,
	})
	createReq := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)

	var createResp model.CreateUserResponse
	json.NewDecoder(createRec.Body).Decode(&createResp)
	viewerID := createResp.User.ID

	// Create a server and give only this viewer access
	s.store.CreateServer(&model.Server{ID: "srv-exclusive", Name: "exclusive-srv", Status: "online", Labels: "{}"})
	s.store.CreatePermission(viewerID, "srv-exclusive", testVarLog)

	// Try to delete without force — should get 409
	delReq := httptest.NewRequest("DELETE", testUsersPrefix+viewerID, nil)
	delReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	delRec := httptest.NewRecorder()
	s.routes().ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", delRec.Code, delRec.Body.String())
	}

	var conflictResp map[string]interface{}
	json.NewDecoder(delRec.Body).Decode(&conflictResp)
	if conflictResp["exclusive_servers"] == nil {
		t.Fatal("expected exclusive_servers in response")
	}

	// Delete with force=true — should succeed
	delReq2 := httptest.NewRequest("DELETE", testUsersPrefix+viewerID+"?force=true", nil)
	delReq2.Header.Set("Authorization", testBearerPrefix+adminToken)
	delRec2 := httptest.NewRecorder()
	s.routes().ServeHTTP(delRec2, delReq2)

	if delRec2.Code != http.StatusOK {
		t.Fatalf("expected 200 with force=true, got %d: %s", delRec2.Code, delRec2.Body.String())
	}
}

// #44: Verify deletion succeeds when user has no exclusive access.
func TestDeleteUser_NoExclusiveAccess(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Create a viewer
	createBody, _ := json.Marshal(model.CreateUserRequest{
		Username: "viewer2", Email: "viewer2@test.com", Role: model.RoleViewer,
	})
	createReq := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)

	var createResp model.CreateUserResponse
	json.NewDecoder(createRec.Body).Decode(&createResp)

	// Delete without force — should succeed (no exclusive access)
	delReq := httptest.NewRequest("DELETE", testUsersPrefix+createResp.User.ID, nil)
	delReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	delRec := httptest.NewRecorder()
	s.routes().ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, delRec.Code, delRec.Body.String())
	}
}
