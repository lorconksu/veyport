package server

import (
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestAccountPolicyReadFailureDeniesLiveAuthority(t *testing.T) {
	s := testServer(t)
	now := time.Now().UTC().Truncate(time.Second)
	user := &model.User{ID: "policy-user", Username: "policy-user", Email: "policy-user@test", PasswordHash: "hash", Role: model.RoleAdmin, AuthProvider: model.AuthProviderLocal, TOTPEnabled: true}
	if err := s.store.CreateUser(user); err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateServer(&model.Server{ID: "policy-node", Name: "policy-node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateSession(&model.Session{ID: "policy-session", UserID: user.ID, Kind: model.SessionKindWeb, CreatedAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"ALTER TABLE _config RENAME TO unavailable_server_account_config",
		"CREATE VIEW _config AS SELECT key,value FROM missing_server_account_config",
	} {
		if _, err := s.store.DB().Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.accountAccessError(user); err == nil {
		t.Fatal("unavailable account policy authorized an existing credential")
	}
	claims := &auth.Claims{SessionID: "policy-session"}
	if err := s.checkSessionAccess(claims, false); err == nil {
		t.Fatal("unavailable account policy authorized an existing session")
	}
	if _, err := s.newSession(sessionRequest("test"), user); err == nil {
		t.Fatal("unavailable account policy created a new session")
	}
	if _, err := AuthorizeTerminalExecution(s.store, user.ID, "policy-node"); err == nil {
		t.Fatal("unavailable account policy authorized terminal execution")
	}
}
