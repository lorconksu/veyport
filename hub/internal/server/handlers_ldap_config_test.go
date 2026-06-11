package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestHandleGetLDAPConfigRedactsBindPasswordAndReturnsMappings(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	encrypted, err := encryptConfigSecret(s.jwtSecret, "bind-password")
	if err != nil {
		t.Fatalf("encrypt bind password: %v", err)
	}
	setLDAPConfigForTest(t, s, map[string]string{
		"ldap.enabled":                  "true",
		"ldap.url":                      "ldaps://freeipa.yiucloud.com:636",
		"ldap.bind_dn":                  "uid=veyport,cn=sysaccounts,cn=etc,dc=yiucloud,dc=com",
		"ldap.bind_password":            encrypted,
		"ldap.user_base_dn":             "cn=users,cn=accounts,dc=yiucloud,dc=com",
		"ldap.group_base_dn":            "cn=groups,cn=accounts,dc=yiucloud,dc=com",
		"ldap.admin_groups":             `["ipa-veyport-admins"]`,
		"ldap.auditor_groups":           `["ipa-auditors"]`,
		"ldap.viewer_groups":            `["ipa-viewers"]`,
		"ldap.terminal_groups":          `["bastion-users","ssh-users"]`,
		"ldap.allow_insecure_transport": "false",
	})

	req := httptest.NewRequest("GET", testLDAPPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	var resp ldapConfigResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode LDAP config response: %v", err)
	}
	if resp.BindPassword != "" {
		t.Fatalf("expected bind password to be redacted, got %q", resp.BindPassword)
	}
	if !resp.BindPasswordSet {
		t.Fatal("expected bind_password_set=true")
	}
	if resp.AdminGroups[0] != "ipa-veyport-admins" || resp.TerminalGroups[1] != "ssh-users" {
		t.Fatalf("unexpected group mappings: %+v", resp)
	}
}

func TestHandleGetLDAPConfigDoesNotReportEmptyBindPasswordAsSet(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	setLDAPConfigForTest(t, s, map[string]string{"ldap.bind_password": ""})

	req := httptest.NewRequest("GET", testLDAPPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	var resp ldapConfigResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode LDAP config response: %v", err)
	}
	if resp.BindPasswordSet {
		t.Fatal("expected empty bind password value to report bind_password_set=false")
	}
}

func TestHandleUpdateLDAPConfigEncryptsSecretAndSavesGroupMappings(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	reqBody := ldapConfigRequest{
		Enabled:           true,
		URL:               "ldaps://freeipa.yiucloud.com:636",
		BindDN:            "uid=veyport,cn=sysaccounts,cn=etc,dc=yiucloud,dc=com",
		BindPassword:      "new-bind-secret",
		UserBaseDN:        "cn=users,cn=accounts,dc=yiucloud,dc=com",
		GroupBaseDN:       "cn=groups,cn=accounts,dc=yiucloud,dc=com",
		UserSearchFilter:  "(uid={username})",
		GroupSearchFilter: "(member={dn})",
		UsernameAttribute: "uid",
		EmailAttribute:    "mail",
		AdminGroups:       []string{"ipa-veyport-admins"},
		AuditorGroups:     []string{"ipa-auditors"},
		ViewerGroups:      []string{"ipa-viewers"},
		TerminalGroups:    []string{"bastion-users"},
	}
	req := httptest.NewRequest("PUT", testLDAPPath, mustJSON(t, reqBody))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	storedPassword, err := s.store.GetConfig("ldap.bind_password")
	if err != nil {
		t.Fatalf("get stored bind password: %v", err)
	}
	if !strings.HasPrefix(storedPassword, "enc:") || strings.Contains(storedPassword, "new-bind-secret") {
		t.Fatalf("expected encrypted bind password, got %q", storedPassword)
	}
	decrypted, err := decryptConfigSecret(s.jwtSecret, storedPassword)
	if err != nil {
		t.Fatalf("decrypt stored bind password: %v", err)
	}
	if decrypted != "new-bind-secret" {
		t.Fatalf("unexpected decrypted bind password %q", decrypted)
	}
	storedGroups, err := s.store.GetConfig("ldap.terminal_groups")
	if err != nil {
		t.Fatalf("get terminal groups: %v", err)
	}
	if storedGroups != `["bastion-users"]` {
		t.Fatalf("unexpected stored terminal groups %q", storedGroups)
	}

	action := model.AuditLDAPConfigUpdated
	entries, total, err := s.store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 10})
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}
	if total != 1 || len(entries) != 1 {
		t.Fatalf("expected one LDAP config audit entry, total=%d len=%d", total, len(entries))
	}
}

func TestHandleUpdateLDAPConfigUsesExistingBindPasswordWhenBlank(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	encrypted, err := encryptConfigSecret(s.jwtSecret, "existing-secret")
	if err != nil {
		t.Fatalf("encrypt bind password: %v", err)
	}
	setLDAPConfigForTest(t, s, map[string]string{"ldap.bind_password": encrypted})

	reqBody := ldapConfigRequest{
		Enabled:           true,
		URL:               "ldaps://freeipa.yiucloud.com:636",
		BindDN:            "uid=veyport,cn=sysaccounts,cn=etc,dc=yiucloud,dc=com",
		BindPassword:      "",
		UserBaseDN:        "cn=users,cn=accounts,dc=yiucloud,dc=com",
		GroupBaseDN:       "cn=groups,cn=accounts,dc=yiucloud,dc=com",
		UserSearchFilter:  "(uid={username})",
		GroupSearchFilter: "(member={dn})",
		UsernameAttribute: "uid",
		EmailAttribute:    "mail",
		AdminGroups:       []string{"ipa-veyport-admins"},
		AuditorGroups:     []string{"ipa-auditors"},
		ViewerGroups:      []string{"ipa-viewers"},
		TerminalGroups:    []string{"bastion-users"},
	}
	req := httptest.NewRequest("PUT", testLDAPPath, mustJSON(t, reqBody))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	stored, err := s.store.GetConfig("ldap.bind_password")
	if err != nil {
		t.Fatalf("get stored bind password: %v", err)
	}
	if stored != encrypted {
		t.Fatalf("expected existing bind password to be preserved, got %q", stored)
	}
}

func TestHandleUpdateLDAPConfigPreservesExistingBindPasswordWhenBlank(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	encrypted, err := encryptConfigSecret(s.jwtSecret, "existing-secret")
	if err != nil {
		t.Fatalf("encrypt bind password: %v", err)
	}
	setLDAPConfigForTest(t, s, map[string]string{"ldap.bind_password": encrypted})

	reqBody := ldapConfigRequest{
		Enabled:           false,
		URL:               "ldaps://freeipa.yiucloud.com:636",
		BindPassword:      "",
		UserSearchFilter:  "(uid={username})",
		GroupSearchFilter: "(member={dn})",
		UsernameAttribute: "uid",
		EmailAttribute:    "mail",
		AdminGroups:       []string{"ipa-veyport-admins"},
		AuditorGroups:     []string{"ipa-auditors"},
		ViewerGroups:      []string{"ipa-viewers"},
		TerminalGroups:    []string{"bastion-users"},
	}
	req := httptest.NewRequest("PUT", testLDAPPath, mustJSON(t, reqBody))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	stored, err := s.store.GetConfig("ldap.bind_password")
	if err != nil {
		t.Fatalf("get stored bind password: %v", err)
	}
	if stored != encrypted {
		t.Fatalf("expected existing bind password to be preserved, got %q", stored)
	}
}

func TestHandleUpdateLDAPConfigRejectsInsecureEnabledLDAP(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	reqBody := ldapConfigRequest{
		Enabled:       true,
		URL:           "ldap://freeipa.yiucloud.com:389",
		UserBaseDN:    "cn=users,cn=accounts,dc=yiucloud,dc=com",
		GroupBaseDN:   "cn=groups,cn=accounts,dc=yiucloud,dc=com",
		AdminGroups:   []string{"ipa-veyport-admins"},
		AuditorGroups: []string{"ipa-auditors"},
		ViewerGroups:  []string{"ipa-viewers"},
	}

	req := httptest.NewRequest("PUT", testLDAPPath, mustJSON(t, reqBody))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "secure transport required") {
		t.Fatalf("expected secure transport error, got %s", rec.Body.String())
	}
}

func TestHandleTestLDAPConfigBindsServiceAccount(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	conn := &fakeLDAPConn{}
	s.ldapDial = func(cfg LDAPConfig) (LDAPConnection, error) {
		if cfg.URL != "ldaps://freeipa.yiucloud.com:636" {
			t.Fatalf("unexpected LDAP URL %q", cfg.URL)
		}
		return conn, nil
	}

	reqBody := ldapConfigRequest{
		Enabled:       true,
		URL:           "ldaps://freeipa.yiucloud.com:636",
		BindDN:        "uid=veyport,cn=sysaccounts,cn=etc,dc=yiucloud,dc=com",
		BindPassword:  "bind-secret",
		UserBaseDN:    "cn=users,cn=accounts,dc=yiucloud,dc=com",
		GroupBaseDN:   "cn=groups,cn=accounts,dc=yiucloud,dc=com",
		AdminGroups:   []string{"ipa-veyport-admins"},
		AuditorGroups: []string{"ipa-auditors"},
		ViewerGroups:  []string{"ipa-viewers"},
	}
	req := httptest.NewRequest("POST", testLDAPTestPath, mustJSON(t, reqBody))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	if len(conn.binds) != 1 || conn.binds[0] != "uid=veyport,cn=sysaccounts,cn=etc,dc=yiucloud,dc=com\x00bind-secret" {
		t.Fatalf("expected service account bind, got %#v", conn.binds)
	}
	if conn.timeout != 10*time.Second || !conn.closed {
		t.Fatalf("expected timeout and close, timeout=%s closed=%v", conn.timeout, conn.closed)
	}
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode LDAP test response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("unexpected LDAP test response: %+v", resp)
	}
}

func TestAuthenticateLDAPLoginUsesConfiguredGroups(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)
	setLDAPConfigForTest(t, s, map[string]string{
		"ldap.admin_groups":    `["freeipa-admins"]`,
		"ldap.auditor_groups":  `["freeipa-auditors"]`,
		"ldap.viewer_groups":   `["freeipa-viewers"]`,
		"ldap.terminal_groups": `["bastion-users"]`,
	})
	s.ldapAuthenticator = fakeLDAPAuthenticator{
		identity: LDAPIdentity{
			Username: "dana",
			Email:    "dana@example.com",
			Groups:   []string{"freeipa-admins", "bastion-users"},
		},
	}

	user, err := s.authenticateLDAPLogin(context.Background(), "dana", "ldap-password")
	if err != nil {
		t.Fatalf("authenticate LDAP login: %v", err)
	}
	if user.Role != model.RoleAdmin {
		t.Fatalf("expected admin from configured group, got %s", user.Role)
	}
	if !user.TerminalAccess {
		t.Fatal("expected terminal access from configured group")
	}
}

func TestMapLDAPRoleUsesConfiguredMappings(t *testing.T) {
	mappings := LDAPGroupMappings{
		RoleGroups: map[model.Role][]string{
			model.RoleAdmin:   {"freeipa-admins"},
			model.RoleAuditor: {"freeipa-auditors"},
			model.RoleViewer:  {"freeipa-viewers"},
		},
		TerminalGroups: []string{"bastion-users"},
	}
	role, ok := mapLDAPRole([]string{"freeipa-viewers", "freeipa-admins"}, mappings)
	if !ok || role != model.RoleAdmin {
		t.Fatalf("expected admin role priority, got role=%s ok=%v", role, ok)
	}
	role, ok = mapLDAPRole([]string{"veyport-admins"}, mappings)
	if ok || role != "" {
		t.Fatalf("expected default group to be ignored when custom mappings are configured, got role=%s ok=%v", role, ok)
	}
}
