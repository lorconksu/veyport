package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
)

func TestRefresh_DeletedUser_Returns401(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Create a viewer user
	createBody, _ := json.Marshal(model.CreateUserRequest{
		Username: "victim", Email: "victim@test.com", Role: model.RoleViewer,
	})
	createReq := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create user: expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}

	var createResp model.CreateUserResponse
	json.NewDecoder(createRec.Body).Decode(&createResp)
	victimID := createResp.User.ID

	// Generate a valid refresh token for this user
	_, refreshToken, err := auth.GenerateTokenPair(s.jwtSecret, victimID, string(model.RoleViewer), 0)
	if err != nil {
		t.Fatalf("generate token pair: %v", err)
	}

	// Delete the user via the store directly
	if err := s.store.DeleteUser(victimID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	// Try to refresh — should get 401
	refreshBody, _ := json.Marshal(model.RefreshRequest{
		RefreshToken: refreshToken,
	})
	refreshReq := httptest.NewRequest("POST", testRefreshPath, bytes.NewReader(refreshBody))
	refreshRec := httptest.NewRecorder()
	s.routes().ServeHTTP(refreshRec, refreshReq)

	if refreshRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for deleted user refresh, got %d: %s", refreshRec.Code, refreshRec.Body.String())
	}
}

func TestRefresh_DemotedUser_GetsCurrentRole(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	// Create an admin user
	createBody, _ := json.Marshal(model.CreateUserRequest{
		Username: "promoted", Email: "promoted@test.com", Role: model.RoleAdmin,
	})
	createReq := httptest.NewRequest("POST", testUsersPath, bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", testBearerPrefix+adminToken)
	createRec := httptest.NewRecorder()
	s.routes().ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create user: expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}

	var createResp model.CreateUserResponse
	json.NewDecoder(createRec.Body).Decode(&createResp)
	userID := createResp.User.ID

	// Generate a refresh token with admin role
	_, refreshToken, err := auth.GenerateTokenPair(s.jwtSecret, userID, string(model.RoleAdmin), 0)
	if err != nil {
		t.Fatalf("generate token pair: %v", err)
	}

	// Demote user to viewer via the store
	if err := s.store.UpdateUserRole(userID, model.RoleViewer); err != nil {
		t.Fatalf("update user role: %v", err)
	}

	// Refresh — new token should have viewer role, not admin
	refreshBody, _ := json.Marshal(model.RefreshRequest{
		RefreshToken: refreshToken,
	})
	refreshReq := httptest.NewRequest("POST", testRefreshPath, bytes.NewReader(refreshBody))
	refreshRec := httptest.NewRecorder()
	s.routes().ServeHTTP(refreshRec, refreshReq)

	if refreshRec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, refreshRec.Code, refreshRec.Body.String())
	}

	var tokenPair model.TokenPair
	json.NewDecoder(refreshRec.Body).Decode(&tokenPair)
	if tokenPair.AccessToken == "" || tokenPair.RefreshToken == "" {
		t.Fatal("expected refresh response body to include rotated tokens")
	}

	accessCookie := findCookie(refreshRec.Result().Cookies(), cookieAccess)
	if accessCookie == nil {
		t.Fatal("expected access cookie after refresh")
	}

	// Parse the new access token and verify the role is viewer
	claims, err := auth.ValidateToken(s.jwtSecret, accessCookie.Value)
	if err != nil {
		t.Fatalf("validate new access token: %v", err)
	}

	if claims.Role != string(model.RoleViewer) {
		t.Fatalf("expected role 'viewer' in new token, got '%s'", claims.Role)
	}

	bodyClaims, err := auth.ValidateToken(s.jwtSecret, tokenPair.AccessToken)
	if err != nil {
		t.Fatalf("validate response access token: %v", err)
	}
	if bodyClaims.Role != string(model.RoleViewer) {
		t.Fatalf("expected role 'viewer' in response token, got '%s'", bodyClaims.Role)
	}
}
