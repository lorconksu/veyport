package server

import (
	"context"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

// Keep the watcher's bounded SQL predicate aligned with shell/exec admission.
func TestTerminalAuthorizationPredicateMatchesAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, provider, ldapName, path, executionUser string
		role                                          model.Role
		terminal, revokeCanonicalAdmin                bool
	}{
		{name: "local admin", provider: "local", role: model.RoleAdmin},
		{name: "local viewer with root", provider: "local", role: model.RoleViewer, terminal: true, path: "/"},
		{name: "LDAP admin", provider: "ldap", role: model.RoleAdmin, ldapName: "operator", executionUser: "operator"},
		{name: "LDAP fallback username", provider: "ldap", role: model.RoleViewer, terminal: true, path: "/", executionUser: "actor"},
		{name: "LDAP assigned viewer", provider: "ldap", role: model.RoleViewer, terminal: true, path: "/", ldapName: "operator", executionUser: "operator"},
		{name: "LDAP missing terminal grant", provider: "ldap", role: model.RoleViewer, path: "/", ldapName: "operator", executionUser: "operator"},
		{name: "LDAP subtree only", provider: "ldap", role: model.RoleViewer, terminal: true, path: "/var/log", ldapName: "operator", executionUser: "operator"},
		{name: "LDAP root-like path", provider: "ldap", role: model.RoleViewer, terminal: true, path: "//", ldapName: "operator", executionUser: "operator"},
		{name: "canonical admin removed", provider: "local", role: model.RoleAdmin, revokeCanonicalAdmin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTerminalAuthzServer(t)
			secret := "enrolled"
			u := &model.User{ID: "actor", Username: "actor", Email: "actor@test", PasswordHash: "h", AuthProvider: model.AuthProvider(tc.provider), Role: tc.role, TerminalAccess: tc.terminal, LDAPUsername: tc.ldapName, TOTPEnabled: true, TOTPSecret: &secret}
			if err := s.store.CreateUser(u); err != nil {
				t.Fatal(err)
			}
			// CreateUser fills the LDAP username; explicitly exercise legacy fallback.
			if tc.provider == "ldap" && tc.ldapName == "" {
				managementServerExec(t, s, "UPDATE users SET ldap_username='' WHERE id=?", u.ID)
			}
			if tc.path != "" {
				grantTerminalAuthzPath(t, s, u.ID, terminalAuthzServerA, tc.path)
			}
			if tc.revokeCanonicalAdmin {
				managementServerExec(t, s, "DELETE FROM user_roles WHERE user_id=? AND role='admin'", u.ID)
			}
			for _, node := range []string{terminalAuthzServerA, terminalAuthzServerB} {
				runAs, err := AuthorizeTerminalExecution(s.store, u.ID, node)
				want := err == nil
				for _, ssh := range []bool{false, true} {
					if got := s.store.TerminalAuthorizationLive(context.Background(), u.ID, node, tc.executionUser, 0, ssh); got != want {
						t.Fatalf("bounded predicate=%t admission=%t node=%s SSH=%t: %v", got, want, node, ssh, err)
					}
					if want && runAs != tc.executionUser {
						t.Fatalf("execution username differs: %q vs %q", runAs, tc.executionUser)
					}
					if want && s.store.TerminalAuthorizationLive(context.Background(), u.ID, node, "changed-user", 0, ssh) {
						t.Fatal("watcher retained a different execution identity")
					}
				}
			}
		})
	}
}
