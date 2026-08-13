package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

// This file is the regression lock for web-terminal authorization (SC-003, and the
// SC-009 disabled-user clause). It captures the decisions made by
// (*Server).resolveTerminalExecutionUser BEFORE the SSH-gateway authorization-core
// refactor and must keep passing UNMODIFIED afterwards. If a change to the
// authorization ladder requires editing this file, behavior has changed.

const (
	terminalAuthzServerA = "authz-srv-a"
	terminalAuthzServerB = "authz-srv-b"

	terminalAuthzErrAccessRequired = "terminal access required"
	terminalAuthzErrNoAssignment   = "root server assignment required for terminal access"
	terminalAuthzErrNoExecUser     = "LDAP execution user not available"
	terminalAuthzErrLookupFailed   = "failed to check server assignment"
)

// terminalAuthzOutcome is the full observable result of one authorization decision:
// whether it was allowed, the execution username handed to the agent, and — on
// denial — the HTTP status code and error message written to the client.
type terminalAuthzOutcome struct {
	allowed       bool
	executionUser string
	status        int
	errMessage    string
}

// callResolveTerminalExecutionUser exercises the HTTP authorization entry point for
// one (user, server) pair and records everything the caller can observe.
func callResolveTerminalExecutionUser(t *testing.T, s *Server, userID, serverID string) terminalAuthzOutcome {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, testServersPrefix+serverID+"/terminal/sessions", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxUserID, userID))
	rec := httptest.NewRecorder()

	executionUser, ok := s.resolveTerminalExecutionUser(rec, req, serverID)
	outcome := terminalAuthzOutcome{allowed: ok, executionUser: executionUser}
	if ok {
		if rec.Body.Len() != 0 {
			t.Fatalf("allowed decision should not write a response body, got %q", rec.Body.String())
		}
		return outcome
	}

	outcome.status = rec.Code
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode denial body %q: %v", rec.Body.String(), err)
	}
	outcome.errMessage = body["error"]
	return outcome
}

func createTerminalAuthzUser(t *testing.T, s *Server, u *model.User) string {
	t.Helper()
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if err := s.store.CreateUser(u); err != nil {
		t.Fatalf("create user %q: %v", u.Username, err)
	}
	return u.ID
}

func grantTerminalAuthzPath(t *testing.T, s *Server, userID, serverID, path string) {
	t.Helper()
	if _, err := s.store.CreatePermission(userID, serverID, path); err != nil {
		t.Fatalf("create permission %s %s: %v", serverID, path, err)
	}
}

func newTerminalAuthzServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	for _, id := range []string{terminalAuthzServerA, terminalAuthzServerB} {
		if err := s.store.CreateServer(&model.Server{ID: id, Name: id, Status: "online", Labels: "{}"}); err != nil {
			t.Fatalf("create server %s: %v", id, err)
		}
	}
	return s
}

// TestTerminalAuthzParityMatrix pins today's decision for every
// (principal) x (server A, server B) cell, including the execution username and the
// exact denial status code and message.
func TestTerminalAuthzParityMatrix(t *testing.T) {
	s := newTerminalAuthzServer(t)

	// Local admin: bypasses assignment checks entirely and — the quirk we must
	// preserve — gets an EMPTY execution user because ldapExecutionUsername
	// returns "" for non-LDAP providers.
	localAdminID := createTerminalAuthzUser(t, s, &model.User{
		Username:     "localadmin",
		Email:        "localadmin@test.com",
		PasswordHash: "hashedpw",
		Role:         model.RoleAdmin,
		AuthProvider: model.AuthProviderLocal,
	})

	// LDAP admin: bypasses assignment checks and gets its LDAP username.
	ldapAdminID := createTerminalAuthzUser(t, s, &model.User{
		Username:     "ldapadmin",
		Email:        "ldapadmin@test.com",
		Role:         model.RoleAdmin,
		AuthProvider: model.AuthProviderLDAP,
		LDAPUsername: "ldapadmin",
		LDAPDN:       "uid=ldapadmin,ou=people,dc=example,dc=com",
		ExternalID:   "entry-ldapadmin",
	})

	// Permitted LDAP user: terminal access + root assignment on server A only.
	permittedID := createTerminalAuthzUser(t, s, &model.User{
		Username:       "alice",
		Email:          "alice@test.com",
		Role:           model.RoleViewer,
		AuthProvider:   model.AuthProviderLDAP,
		LDAPUsername:   "alice",
		LDAPDN:         "uid=alice,ou=people,dc=example,dc=com",
		ExternalID:     "entry-alice",
		TerminalAccess: true,
	})
	grantTerminalAuthzPath(t, s, permittedID, terminalAuthzServerA, "/")

	// LDAP user WITHOUT terminal_access: root assignments on both servers must
	// not help — the terminal_access gate is evaluated first.
	noTerminalID := createTerminalAuthzUser(t, s, &model.User{
		Username:       "bob",
		Email:          "bob@test.com",
		Role:           model.RoleViewer,
		AuthProvider:   model.AuthProviderLDAP,
		LDAPUsername:   "bob",
		LDAPDN:         "uid=bob,ou=people,dc=example,dc=com",
		ExternalID:     "entry-bob",
		TerminalAccess: false,
	})
	grantTerminalAuthzPath(t, s, noTerminalID, terminalAuthzServerA, "/")
	grantTerminalAuthzPath(t, s, noTerminalID, terminalAuthzServerB, "/")

	// LDAP user WITH terminal_access but no root ("/") assignment: a subtree
	// grant on server A, nothing on server B.
	noRootID := createTerminalAuthzUser(t, s, &model.User{
		Username:       "carol",
		Email:          "carol@test.com",
		Role:           model.RoleViewer,
		AuthProvider:   model.AuthProviderLDAP,
		LDAPUsername:   "carol",
		LDAPDN:         "uid=carol,ou=people,dc=example,dc=com",
		ExternalID:     "entry-carol",
		TerminalAccess: true,
	})
	grantTerminalAuthzPath(t, s, noRootID, terminalAuthzServerA, testVarLog)

	// Disabled/deleted user: an identity that no longer resolves in the store,
	// e.g. a still-valid credential presented after the account is removed.
	deletedID := createTerminalAuthzUser(t, s, &model.User{
		Username:       "dave",
		Email:          "dave@test.com",
		Role:           model.RoleViewer,
		AuthProvider:   model.AuthProviderLDAP,
		LDAPUsername:   "dave",
		LDAPDN:         "uid=dave,ou=people,dc=example,dc=com",
		ExternalID:     "entry-dave",
		TerminalAccess: true,
	})
	grantTerminalAuthzPath(t, s, deletedID, terminalAuthzServerA, "/")
	grantTerminalAuthzPath(t, s, deletedID, terminalAuthzServerB, "/")
	if err := s.store.DeleteUser(deletedID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	tests := []struct {
		name     string
		userID   string
		serverID string
		want     terminalAuthzOutcome
	}{
		{"local admin / server A", localAdminID, terminalAuthzServerA, terminalAuthzOutcome{allowed: true, executionUser: ""}},
		{"local admin / server B", localAdminID, terminalAuthzServerB, terminalAuthzOutcome{allowed: true, executionUser: ""}},

		{"ldap admin / server A", ldapAdminID, terminalAuthzServerA, terminalAuthzOutcome{allowed: true, executionUser: "ldapadmin"}},
		{"ldap admin / server B", ldapAdminID, terminalAuthzServerB, terminalAuthzOutcome{allowed: true, executionUser: "ldapadmin"}},

		{"permitted ldap user / server A", permittedID, terminalAuthzServerA, terminalAuthzOutcome{allowed: true, executionUser: "alice"}},
		{"permitted ldap user / server B", permittedID, terminalAuthzServerB, terminalAuthzOutcome{
			status: http.StatusForbidden, errMessage: terminalAuthzErrNoAssignment,
		}},

		{"ldap user without terminal_access / server A", noTerminalID, terminalAuthzServerA, terminalAuthzOutcome{
			status: http.StatusForbidden, errMessage: terminalAuthzErrAccessRequired,
		}},
		{"ldap user without terminal_access / server B", noTerminalID, terminalAuthzServerB, terminalAuthzOutcome{
			status: http.StatusForbidden, errMessage: terminalAuthzErrAccessRequired,
		}},

		{"ldap terminal user without root assignment / server A", noRootID, terminalAuthzServerA, terminalAuthzOutcome{
			status: http.StatusForbidden, errMessage: terminalAuthzErrNoAssignment,
		}},
		{"ldap terminal user without root assignment / server B", noRootID, terminalAuthzServerB, terminalAuthzOutcome{
			status: http.StatusForbidden, errMessage: terminalAuthzErrNoAssignment,
		}},

		{"deleted user / server A", deletedID, terminalAuthzServerA, terminalAuthzOutcome{
			status: http.StatusForbidden, errMessage: terminalAuthzErrAccessRequired,
		}},
		{"deleted user / server B", deletedID, terminalAuthzServerB, terminalAuthzOutcome{
			status: http.StatusForbidden, errMessage: terminalAuthzErrAccessRequired,
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := callResolveTerminalExecutionUser(t, s, tc.userID, tc.serverID)
			if got != tc.want {
				t.Fatalf("authorization decision changed:\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// TestTerminalAuthzParityNoExecutionUser pins the last rung of the ladder: an LDAP
// user who clears every access check but has no resolvable execution username.
func TestTerminalAuthzParityNoExecutionUser(t *testing.T) {
	s := newTerminalAuthzServer(t)

	userID := createTerminalAuthzUser(t, s, &model.User{
		Username:       "",
		Email:          "nameless@test.com",
		Role:           model.RoleViewer,
		AuthProvider:   model.AuthProviderLDAP,
		LDAPUsername:   "",
		LDAPDN:         "uid=nameless,ou=people,dc=example,dc=com",
		ExternalID:     "entry-nameless",
		TerminalAccess: true,
	})
	grantTerminalAuthzPath(t, s, userID, terminalAuthzServerA, "/")

	got := callResolveTerminalExecutionUser(t, s, userID, terminalAuthzServerA)
	want := terminalAuthzOutcome{status: http.StatusForbidden, errMessage: terminalAuthzErrNoExecUser}
	if got != want {
		t.Fatalf("authorization decision changed:\n got %+v\nwant %+v", got, want)
	}
}

// TestTerminalAuthzParityAssignmentLookupFailure pins the only non-403 outcome: a
// failure while reading the user's server assignments surfaces as a 500.
func TestTerminalAuthzParityAssignmentLookupFailure(t *testing.T) {
	s := newTerminalAuthzServer(t)

	userID := createTerminalAuthzUser(t, s, &model.User{
		Username:       "erin",
		Email:          "erin@test.com",
		Role:           model.RoleViewer,
		AuthProvider:   model.AuthProviderLDAP,
		LDAPUsername:   "erin",
		LDAPDN:         "uid=erin,ou=people,dc=example,dc=com",
		ExternalID:     "entry-erin",
		TerminalAccess: true,
	})
	grantTerminalAuthzPath(t, s, userID, terminalAuthzServerA, "/")

	// Break the assignment lookup only — the user record must still resolve.
	if _, err := s.store.DB().Exec("DROP TABLE permissions"); err != nil {
		t.Fatalf("drop permissions table: %v", err)
	}

	got := callResolveTerminalExecutionUser(t, s, userID, terminalAuthzServerA)
	want := terminalAuthzOutcome{status: http.StatusInternalServerError, errMessage: terminalAuthzErrLookupFailed}
	if got != want {
		t.Fatalf("authorization decision changed:\n got %+v\nwant %+v", got, want)
	}
}

// TestTerminalAuthzParityExecutionUsernameFallback pins the execution-username
// resolution itself, including the local-provider empty-string quirk.
func TestTerminalAuthzParityExecutionUsernameFallback(t *testing.T) {
	tests := []struct {
		name string
		user model.User
		want string
	}{
		{"local provider yields empty execution user", model.User{
			Username: "localadmin", AuthProvider: model.AuthProviderLocal,
		}, ""},
		{"local provider ignores ldap username", model.User{
			Username: "localadmin", LDAPUsername: "ignored", AuthProvider: model.AuthProviderLocal,
		}, ""},
		{"ldap username preferred", model.User{
			Username: "alice@corp", LDAPUsername: "alice", AuthProvider: model.AuthProviderLDAP,
		}, "alice"},
		{"falls back to username when ldap username empty", model.User{
			Username: "alice", AuthProvider: model.AuthProviderLDAP,
		}, "alice"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user := tc.user
			if got := ldapExecutionUsername(&user); got != tc.want {
				t.Fatalf("ldapExecutionUsername = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTerminalAuthzParityRootAssignmentDetection pins which path grants count as a
// terminal-capable server assignment.
func TestTerminalAuthzParityRootAssignmentDetection(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  bool
	}{
		{"no paths", nil, false},
		{"root only", []string{"/"}, true},
		{"subtree only", []string{testVarLog}, false},
		{"subtree and root", []string{testVarLog, "/"}, true},
		{"root-like prefix is not root", []string{"/root", "//"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasTerminalServerAssignment(tc.paths); got != tc.want {
				t.Fatalf("hasTerminalServerAssignment(%v) = %v, want %v", tc.paths, got, tc.want)
			}
		})
	}
}
