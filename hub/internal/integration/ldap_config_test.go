package integration

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
)

const (
	ldapSettingsPath = "/api/settings/ldap"
	ldapUserBaseDN   = "ou=people,dc=test,dc=local"
	ldapGroupBaseDN  = "ou=groups,dc=test,dc=local"
	ldapServiceDN    = "uid=veyport,ou=services,dc=test,dc=local"
	ldapServicePW    = "svc-secret"
)

// fakeDirUser is one account in the fake directory.
type fakeDirUser struct {
	dn       string
	password string
	email    string
	uuid     string
	groups   []string
}

// fakeDirectory emulates the small slice of LDAP behavior the hub exercises:
// service-account bind, user search by username, user bind, group search.
type fakeDirectory struct {
	users map[string]fakeDirUser // keyed by username
}

func (d *fakeDirectory) dial(server.LDAPConfig) (server.LDAPConnection, error) {
	return &fakeDirConn{dir: d}, nil
}

type fakeDirConn struct {
	dir *fakeDirectory
}

func (c *fakeDirConn) Bind(dn, password string) error {
	if dn == ldapServiceDN && password == ldapServicePW {
		return nil
	}
	for _, u := range c.dir.users {
		if u.dn == dn && u.password == password {
			return nil
		}
	}
	return fmt.Errorf("invalid credentials for %s", dn)
}

func (c *fakeDirConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	switch req.BaseDN {
	case ldapUserBaseDN:
		for username, u := range c.dir.users {
			if strings.Contains(req.Filter, "(uid="+username+")") {
				entry := ldap.NewEntry(u.dn, map[string][]string{
					"uid":       {username},
					"mail":      {u.email},
					"entryUUID": {u.uuid},
				})
				return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
			}
		}
		return &ldap.SearchResult{}, nil
	case ldapGroupBaseDN:
		for _, u := range c.dir.users {
			if strings.Contains(req.Filter, u.dn) {
				entries := make([]*ldap.Entry, 0, len(u.groups))
				for _, g := range u.groups {
					entries = append(entries, ldap.NewEntry(
						"cn="+g+","+ldapGroupBaseDN,
						map[string][]string{"cn": {g}},
					))
				}
				return &ldap.SearchResult{Entries: entries}, nil
			}
		}
		return &ldap.SearchResult{}, nil
	default:
		return nil, fmt.Errorf("unexpected search base %q", req.BaseDN)
	}
}

func (c *fakeDirConn) Close() error               { return nil }
func (c *fakeDirConn) SetTimeout(time.Duration)   {}
func (c *fakeDirConn) StartTLS(*tls.Config) error { return nil }

// ldapConfigBody builds a PUT /api/settings/ldap request body. Group mapping
// fields are supplied by the caller.
func ldapConfigBody(adminGroups, auditorGroups, viewerGroups, terminalGroups []string) map[string]interface{} {
	return map[string]interface{}{
		"enabled":         true,
		"url":             "ldaps://dir.test.local:636",
		"bind_dn":         ldapServiceDN,
		"bind_password":   ldapServicePW,
		"user_base_dn":    ldapUserBaseDN,
		"group_base_dn":   ldapGroupBaseDN,
		"admin_groups":    adminGroups,
		"auditor_groups":  auditorGroups,
		"viewer_groups":   viewerGroups,
		"terminal_groups": terminalGroups,
	}
}

func putLDAPConfig(t *testing.T, h *TestHarness, token string, body map[string]interface{}) {
	t.Helper()
	resp := h.HTTPPut(t, ldapSettingsPath, body, token)
	defer resp.Body.Close()
	requireStatusOK(t, resp, "put ldap config")
}

func loginLDAP(t *testing.T, h *TestHarness, username, password string) *http.Response {
	t.Helper()
	return h.HTTPPost(t, "/api/auth/login", model.LoginRequest{
		Username: username,
		Password: password,
	}, "")
}

// TestLDAPConfigSaveAndDirectorySignIn covers tasks.md T015 (spec FR-002,
// FR-004, FR-010): configuration saved through the API is persisted with the
// bind password encrypted and write-only, and a subsequent directory sign-in
// consumes the stored configuration end to end (provisioning the user with
// the mapped role).
func TestLDAPConfigSaveAndDirectorySignIn(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)

	dir := &fakeDirectory{users: map[string]fakeDirUser{
		"dana": {
			dn:       "uid=dana," + ldapUserBaseDN,
			password: "user-secret",
			email:    "dana@test.local",
			uuid:     "11111111-2222-3333-4444-555555555555",
			groups:   []string{"ldap-auditors", "bastion-users"},
		},
	}}
	h.HTTPServer.SetLDAPDialer(dir.dial)

	putLDAPConfig(t, h, adminToken, ldapConfigBody(
		[]string{"ldap-admins"},
		[]string{"ldap-auditors"},
		[]string{"ldap-viewers"},
		[]string{"bastion-users"},
	))

	// Persistence: GET returns the saved config with the password write-only.
	getResp := h.HTTPGet(t, ldapSettingsPath, adminToken)
	defer getResp.Body.Close()
	requireStatusOK(t, getResp, "get ldap config")
	var cfg map[string]interface{}
	decodeJSON(t, getResp, &cfg, "ldap config")
	if cfg["url"] != "ldaps://dir.test.local:636" {
		t.Fatalf("saved URL not returned, got %v", cfg["url"])
	}
	if cfg["bind_password"] != "" {
		t.Fatalf("bind_password must never be returned, got %q", cfg["bind_password"])
	}
	if cfg["bind_password_set"] != true {
		t.Fatalf("expected bind_password_set=true, got %v", cfg["bind_password_set"])
	}

	// At rest: the stored password is encrypted, never plaintext.
	stored, ok, err := h.Store.LookupConfig("ldap.bind_password")
	if err != nil || !ok {
		t.Fatalf("lookup stored bind password: ok=%v err=%v", ok, err)
	}
	if !strings.HasPrefix(stored, "enc:") {
		t.Fatalf("bind password not encrypted at rest: %q", stored)
	}
	if strings.Contains(stored, ldapServicePW) {
		t.Fatalf("bind password stored in plaintext")
	}

	// Sign-in consumes the stored config: dana authenticates against the
	// directory and is provisioned with the mapped auditor role.
	loginResp := loginLDAP(t, h, "dana", "user-secret")
	defer loginResp.Body.Close()
	requireStatusOK(t, loginResp, "ldap login")
	var login model.LoginResponse
	decodeJSON(t, loginResp, &login, "ldap login")
	if !login.RequiresTOTPSetup || login.SetupToken == "" {
		t.Fatalf("expected first LDAP login to require TOTP setup, got %+v", login)
	}

	user, err := h.Store.GetUserByUsername("dana")
	if err != nil {
		t.Fatalf("ldap user not provisioned: %v", err)
	}
	if user.Role != model.RoleAuditor {
		t.Fatalf("expected auditor role from group mapping, got %s", user.Role)
	}
	if !user.TerminalAccess {
		t.Fatalf("expected terminal access from bastion-users mapping")
	}

	// Wrong directory password is rejected.
	badResp := loginLDAP(t, h, "dana", "wrong-password")
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad LDAP password, got %d", badResp.StatusCode)
	}
}

// TestLDAPGroupRoleMappingPrecedence covers tasks.md T025 (spec FR-009,
// FR-010, acceptance scenario US3-2): a user in groups mapped to multiple
// roles receives the highest-privilege role, and terminal access is granted
// only via a mapped terminal group.
func TestLDAPGroupRoleMappingPrecedence(t *testing.T) {
	h := StartHarness(t)
	adminToken := h.SetupAdmin(t)

	dir := &fakeDirectory{users: map[string]fakeDirUser{
		"alex": {
			dn:       "uid=alex," + ldapUserBaseDN,
			password: "alex-secret",
			email:    "alex@test.local",
			uuid:     "aaaaaaaa-1111-2222-3333-444444444444",
			// Member of both an admin-mapped and a viewer-mapped group.
			groups: []string{"ldap-viewers", "ldap-admins"},
		},
		"vera": {
			dn:       "uid=vera," + ldapUserBaseDN,
			password: "vera-secret",
			email:    "vera@test.local",
			uuid:     "bbbbbbbb-1111-2222-3333-444444444444",
			groups:   []string{"ldap-viewers"},
		},
	}}
	h.HTTPServer.SetLDAPDialer(dir.dial)

	putLDAPConfig(t, h, adminToken, ldapConfigBody(
		[]string{"ldap-admins"},
		[]string{"ldap-auditors"},
		[]string{"ldap-viewers"},
		[]string{"bastion-users"},
	))

	resp := loginLDAP(t, h, "alex", "alex-secret")
	defer resp.Body.Close()
	requireStatusOK(t, resp, "alex login")
	alex, err := h.Store.GetUserByUsername("alex")
	if err != nil {
		t.Fatalf("alex not provisioned: %v", err)
	}
	if alex.Role != model.RoleAdmin {
		t.Fatalf("expected highest-privilege role admin, got %s", alex.Role)
	}
	if alex.TerminalAccess {
		t.Fatalf("alex should not have terminal access (not in bastion-users)")
	}

	resp = loginLDAP(t, h, "vera", "vera-secret")
	defer resp.Body.Close()
	requireStatusOK(t, resp, "vera login")
	vera, err := h.Store.GetUserByUsername("vera")
	if err != nil {
		t.Fatalf("vera not provisioned: %v", err)
	}
	if vera.Role != model.RoleViewer {
		t.Fatalf("expected viewer role, got %s", vera.Role)
	}
}
