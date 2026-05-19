package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

func createLDAPViewerToken(t *testing.T, s *Server, username string, terminalAccess bool) (string, string) {
	t.Helper()

	user := &model.User{
		ID:             uuid.NewString(),
		Username:       username,
		Email:          username + "@example.com",
		PasswordHash:   "",
		Role:           model.RoleViewer,
		TOTPEnabled:    true,
		AuthProvider:   model.AuthProviderLDAP,
		LDAPUsername:   username,
		LDAPDN:         "uid=" + username + ",ou=people,dc=example,dc=com",
		ExternalID:     "entry-" + username,
		TerminalAccess: terminalAccess,
	}
	if err := s.store.CreateUser(user); err != nil {
		t.Fatalf("create ldap user: %v", err)
	}

	accessToken, _, err := auth.GenerateTokenPair(s.jwtSecret, user.ID, string(user.Role), user.TokenGeneration)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	return user.ID, accessToken
}

func TestHandleCreateTerminalSession_LDAPTerminalUserAssignedServer(t *testing.T) {
	s, _, serverID := testServerWithAgent(t)
	userID, token := createLDAPViewerToken(t, s, "alice", true)
	if _, err := s.store.CreatePermission(userID, serverID, "/"); err != nil {
		t.Fatalf("assign server permission: %v", err)
	}

	sessionID := createTerminalSessionForTest(t, s, token, serverID)

	conn := s.connMgr.GetConn(serverID)
	stream, ok := conn.Stream.(*mockGRPCStream)
	if !ok {
		t.Fatal("expected mockGRPCStream")
	}
	openReq := stream.sent[len(stream.sent)-1].GetTerminalOpenRequest()
	if openReq == nil {
		t.Fatal("expected terminal open request")
	}
	if openReq.SessionId != sessionID {
		t.Fatalf("expected session id %s, got %s", sessionID, openReq.SessionId)
	}
	if openReq.RunAsUser != "alice" {
		t.Fatalf("expected terminal to run as alice, got %q", openReq.RunAsUser)
	}
}

func TestHandleCreateTerminalSession_LDAPTerminalUserUnassignedServerDenied(t *testing.T) {
	s, _, serverID := testServerWithAgent(t)
	_, token := createLDAPViewerToken(t, s, "bob", true)

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]interface{}{"cols": 80, "rows": 24}))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateTerminalSession_LDAPTerminalUserPathOnlyAssignmentDenied(t *testing.T) {
	s, _, serverID := testServerWithAgent(t)
	userID, token := createLDAPViewerToken(t, s, "dave", true)
	if _, err := s.store.CreatePermission(userID, serverID, "/var/log"); err != nil {
		t.Fatalf("assign path permission: %v", err)
	}

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]interface{}{"cols": 80, "rows": 24}))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateTerminalSession_LDAPViewerWithoutTerminalGroupDenied(t *testing.T) {
	s, _, serverID := testServerWithAgent(t)
	userID, token := createLDAPViewerToken(t, s, "carol", false)
	if _, err := s.store.CreatePermission(userID, serverID, "/"); err != nil {
		t.Fatalf("assign server permission: %v", err)
	}

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]interface{}{"cols": 80, "rows": 24}))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}
