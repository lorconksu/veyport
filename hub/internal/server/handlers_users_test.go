package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

func registerAndGetAdminToken(t *testing.T, s *Server) string {
	t.Helper()

	// Register first admin
	body, _ := json.Marshal(model.RegisterRequest{
		Username: "admin", Email: testAdminEmail, Password: testPassword,
	})
	req := httptest.NewRequest("POST", testRegisterPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	var regResp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&regResp)
	setupToken := regResp["setup_token"].(string)

	// Setup TOTP
	req2 := httptest.NewRequest("POST", testTOTPSetupPath, nil)
	req2.Header.Set("Authorization", testBearerPrefix+setupToken)
	rec2 := httptest.NewRecorder()
	s.routes().ServeHTTP(rec2, req2)

	var totpResp model.TOTPSetupResponse
	json.NewDecoder(rec2.Body).Decode(&totpResp)

	// Generate valid TOTP code and enable
	code, _ := auth.GenerateValidCode(totpResp.Secret)

	enableBody, _ := json.Marshal(model.TOTPEnableRequest{Code: code})
	req3 := httptest.NewRequest("POST", testTOTPEnablePath, bytes.NewReader(enableBody))
	req3.Header.Set("Authorization", testBearerPrefix+setupToken)
	rec3 := httptest.NewRecorder()
	s.routes().ServeHTTP(rec3, req3)

	accessCookie := findCookie(rec3.Result().Cookies(), cookieAccess)
	if accessCookie == nil {
		t.Fatal("expected access cookie after TOTP enable")
	}

	return accessCookie.Value
}

func TestUpdateUserRole_Success(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Create a viewer user first
	createBody, _ := json.Marshal(model.CreateUserRequest{
		Username: "viewer1", Email: testViewerEmail, Role: model.RoleViewer,
	})
	createReq := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", testBearerPrefix+token)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)

	var createResp model.CreateUserResponse
	json.NewDecoder(createRec.Body).Decode(&createResp)

	// Update role to admin
	body, _ := json.Marshal(model.UpdateRoleRequest{Role: model.RoleAdmin})
	req := httptest.NewRequest("PUT", testUsersPrefix+createResp.User.ID+"/role", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	user := resp["user"].(map[string]interface{})
	if user["role"] != "admin" {
		t.Fatalf("expected role 'admin', got '%v'", user["role"])
	}
}

func TestUpdateUserRole_CannotChangeOwnRole(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Get own user ID from /api/auth/me
	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+token)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)

	var me model.User
	json.NewDecoder(meRec.Body).Decode(&me)

	// Try to change own role
	body, _ := json.Marshal(model.UpdateRoleRequest{Role: model.RoleViewer})
	req := httptest.NewRequest("PUT", testUsersPrefix+me.ID+"/role", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
}

func TestUpdateUserRole_InvalidRole(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Create a user first
	createBody, _ := json.Marshal(model.CreateUserRequest{
		Username: "viewer1", Email: testViewerEmail, Role: model.RoleViewer,
	})
	createReq := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", testBearerPrefix+token)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)

	var createResp model.CreateUserResponse
	json.NewDecoder(createRec.Body).Decode(&createResp)

	// Try invalid role
	body := []byte(`{"role": "superadmin"}`)
	req := httptest.NewRequest("PUT", testUsersPrefix+createResp.User.ID+"/role", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
}

func TestCreateUser(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateUserRequest{
		Username: "viewer1",
		Email:    testViewerEmail,
		Role:     model.RoleViewer,
	})

	req := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp model.CreateUserResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TemporaryPassword == "" {
		t.Fatal("expected temporary_password in response")
	}
	if resp.User.Username != "viewer1" {
		t.Fatalf("expected username 'viewer1', got '%s'", resp.User.Username)
	}
}

func TestCreateUser_InvalidJSON(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("POST", testUsersPath, bytes.NewReader([]byte(testNotJSON)))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestCreateUser_InvalidUsername(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateUserRequest{
		Username: "ab", // too short
		Email:    "test@test.com",
		Role:     model.RoleViewer,
	})
	req := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestCreateUser_InvalidRole(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body := []byte(`{"username":"validuser","email":"test@test.com","role":"superadmin"}`)
	req := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestCreateUser_Duplicate(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateUserRequest{
		Username: "viewer1", Email: testViewerEmail, Role: model.RoleViewer,
	})
	req1 := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(body))
	req1.Header.Set("Authorization", testBearerPrefix+token)
	s.routes().ServeHTTP(httptest.NewRecorder(), req1)

	body2, _ := json.Marshal(model.CreateUserRequest{
		Username: "viewer1", Email: "viewer2@test.com", Role: model.RoleViewer,
	})
	req2 := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(body2))
	req2.Header.Set("Authorization", testBearerPrefix+token)
	rec2 := httptest.NewRecorder()
	s.routes().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestListUsers(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", testUsersPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["users"] == nil {
		t.Fatal("expected users in response")
	}
}

func TestDeleteUser_Success(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Create a viewer user
	createBody, _ := json.Marshal(model.CreateUserRequest{
		Username: "viewer1", Email: testViewerEmail, Role: model.RoleViewer,
	})
	createReq := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", testBearerPrefix+token)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)

	var createResp model.CreateUserResponse
	json.NewDecoder(createRec.Body).Decode(&createResp)

	// Delete user
	delReq := httptest.NewRequest("DELETE", testUsersPrefix+createResp.User.ID, nil)
	delReq.Header.Set("Authorization", testBearerPrefix+token)
	delRec := httptest.NewRecorder()
	s.routes().ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, delRec.Code, delRec.Body.String())
	}
}

func TestDeleteUser_CannotDeleteSelf(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+token)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)

	var me model.User
	json.NewDecoder(meRec.Body).Decode(&me)

	delReq := httptest.NewRequest("DELETE", testUsersPrefix+me.ID, nil)
	delReq.Header.Set("Authorization", testBearerPrefix+token)
	delRec := httptest.NewRecorder()
	s.routes().ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, delRec.Code, delRec.Body.String())
	}
}

func TestDeleteUser_NotFound(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	delReq := httptest.NewRequest("DELETE", "/api/users/nonexistent-id", nil)
	delReq.Header.Set("Authorization", testBearerPrefix+token)
	delRec := httptest.NewRecorder()
	s.routes().ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", delRec.Code, delRec.Body.String())
	}
}

func TestUpdateUserRole_NotFound(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.UpdateRoleRequest{Role: model.RoleAdmin})
	req := httptest.NewRequest("PUT", "/api/users/nonexistent-id/role", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateUserRole_InvalidJSON(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("PUT", "/api/users/some-id/role", bytes.NewReader([]byte(testNotJSON)))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

// TestUpdateUserRole_InvalidatesSessions verifies that demoting a user's role
// also forces re-authentication by incrementing the user's token_generation,
// so the existing access token cannot continue exercising the old role for the
// remainder of its 15-minute TTL.
func TestUpdateUserRole_InvalidatesSessions(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	createBody, _ := json.Marshal(model.CreateUserRequest{
		Username: "demoteme", Email: testViewerEmail, Role: model.RoleAdmin,
	})
	createReq := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", testBearerPrefix+token)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)

	var createResp model.CreateUserResponse
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create user: %v", err)
	}

	before, err := s.store.GetUserByID(createResp.User.ID)
	if err != nil {
		t.Fatalf("get user before: %v", err)
	}

	body, _ := json.Marshal(model.UpdateRoleRequest{Role: model.RoleViewer})
	req := httptest.NewRequest("PUT", testUsersPrefix+createResp.User.ID+"/role", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	after, err := s.store.GetUserByID(createResp.User.ID)
	if err != nil {
		t.Fatalf("get user after: %v", err)
	}
	if after.TokenGeneration <= before.TokenGeneration {
		t.Fatalf("expected token_generation to increase after role update, was %d, now %d",
			before.TokenGeneration, after.TokenGeneration)
	}
}

// TestUpdateUserRole_InvalidateSessionsFailure exercises the 500 error branch
// when token_generation cannot be incremented after a successful role update.
func TestUpdateUserRole_InvalidateSessionsFailure(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	createBody, _ := json.Marshal(model.CreateUserRequest{
		Username: "demoteme2", Email: testViewerEmail, Role: model.RoleAdmin,
	})
	createReq := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", testBearerPrefix+token)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)

	var createResp model.CreateUserResponse
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create user: %v", err)
	}

	// Block the IncrementTokenGeneration UPDATE for the *target* user only.
	// Limiting to a specific id keeps the admin's own session usable so the
	// request can reach the handler in the first place.
	// SQLite triggers do not accept bound parameters in the body, so the id
	// (a server-generated UUID) is interpolated literally.
	if _, err := s.store.DB().Exec(fmt.Sprintf(`
		CREATE TRIGGER block_role_session_invalidation
		BEFORE UPDATE OF token_generation ON users
		WHEN NEW.id = '%s'
		BEGIN
			SELECT RAISE(FAIL, 'token_generation updates blocked');
		END;
	`, createResp.User.ID)); err != nil {
		t.Fatalf("create users trigger: %v", err)
	}

	body, _ := json.Marshal(model.UpdateRoleRequest{Role: model.RoleViewer})
	req := httptest.NewRequest("PUT", testUsersPrefix+createResp.User.ID+"/role", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestViewerCannotAccessAdminEndpoints(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	viewerToken := createViewerAndGetToken(t, s, adminToken)

	// Viewer tries to list users (admin-only)
	req := httptest.NewRequest("GET", testUsersPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}
