package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// coverageFakeConn is a minimal LDAPConnection whose bind outcome is scripted.
type coverageFakeConn struct {
	bindErr error
}

func (c *coverageFakeConn) Bind(string, string) error { return c.bindErr }
func (c *coverageFakeConn) Search(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	return &ldap.SearchResult{}, nil
}
func (c *coverageFakeConn) Close() error               { return nil }
func (c *coverageFakeConn) SetTimeout(time.Duration)   {}
func (c *coverageFakeConn) StartTLS(*tls.Config) error { return nil }

func enabledLDAPConfigRequest() ldapConfigRequest {
	return ldapConfigRequest{
		Enabled:     true,
		URL:         "ldaps://dir.example.com:636",
		UserBaseDN:  "ou=people,dc=example,dc=com",
		GroupBaseDN: "ou=groups,dc=example,dc=com",
		AdminGroups: []string{"admins"},
	}
}

func TestSetLDAPDialer(t *testing.T) {
	s := testServer(t)
	s.SetLDAPDialer(func(LDAPConfig) (LDAPConnection, error) {
		return &coverageFakeConn{}, nil
	})
	if s.ldapDial == nil {
		t.Fatal("expected dialer to be set")
	}
	s.SetLDAPDialer(nil)
	if s.ldapDial != nil {
		t.Fatal("expected dialer to be cleared")
	}
}

func TestDialLDAPInvalidURL(t *testing.T) {
	_, err := dialLDAP(LDAPConfig{URL: "://not-a-url"})
	if err == nil || !strings.Contains(err.Error(), "invalid LDAP URL") {
		t.Fatalf("expected invalid URL error, got %v", err)
	}
}

func TestDialLDAPConnectionRefused(t *testing.T) {
	_, err := dialLDAP(LDAPConfig{URL: "ldaps://127.0.0.1:1", AllowInsecure: true})
	if err == nil {
		t.Fatal("expected connection error for closed port")
	}
}

func TestDialLDAPStartTLSFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Close immediately: StartTLS negotiation fails with EOF.
			conn.Close()
		}
	}()

	_, err = dialLDAP(LDAPConfig{
		URL:           "ldap://" + ln.Addr().String(),
		StartTLS:      true,
		AllowInsecure: true,
	})
	if err == nil {
		t.Fatal("expected StartTLS failure against non-LDAP listener")
	}
}

func TestLDAPBindAuthenticatorDefaultDialConnectError(t *testing.T) {
	a := &ldapBindAuthenticator{cfg: LDAPConfig{
		URL:           "ldaps://127.0.0.1:1",
		UserBaseDN:    "ou=people,dc=example,dc=com",
		AllowInsecure: true,
	}}
	_, err := a.Authenticate(t.Context(), "user", "secret")
	if err == nil || !strings.Contains(err.Error(), "connect LDAP") {
		t.Fatalf("expected connect error via default dialer, got %v", err)
	}
}

func TestValidateLDAPSettingsBranches(t *testing.T) {
	base := enabledLDAPConfigRequest()

	cases := []struct {
		name    string
		mutate  func(*ldapConfigRequest)
		wantErr string
	}{
		{"disabled skips validation", func(r *ldapConfigRequest) { r.Enabled = false; r.URL = "" }, ""},
		{"missing user base dn", func(r *ldapConfigRequest) { r.UserBaseDN = "" }, "user base DN"},
		{"missing group base dn", func(r *ldapConfigRequest) { r.GroupBaseDN = "" }, "group base DN"},
		{"bind dn without password", func(r *ldapConfigRequest) { r.BindDN = "uid=svc,dc=example,dc=com" }, "bind password"},
		{"no role groups", func(r *ldapConfigRequest) { r.AdminGroups = nil }, "at least one LDAP role group"},
		{"too many groups", func(r *ldapConfigRequest) {
			groups := make([]string, 65)
			for i := range groups {
				groups[i] = fmt.Sprintf("group-%d", i)
			}
			r.ViewerGroups = groups
		}, "more than 64 groups"},
		{"group name too long", func(r *ldapConfigRequest) {
			r.AuditorGroups = []string{strings.Repeat("g", 256)}
		}, "255 characters"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			cfg := ldapConfigFromRequest(req, "")
			err := validateLDAPSettings(cfg, req)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestParseLDAPGroupListFormats(t *testing.T) {
	if got := parseLDAPGroupList("   "); got != nil {
		t.Fatalf("expected nil for blank value, got %v", got)
	}
	if got := parseLDAPGroupList(`["a","b"]`); len(got) != 2 || got[0] != "a" {
		t.Fatalf("expected JSON list parsed, got %v", got)
	}
	// Invalid JSON falls back to the separator-based legacy format.
	if got := parseLDAPGroupList(`["broken`); len(got) != 1 || got[0] != `["broken` {
		t.Fatalf("expected legacy fallback for invalid JSON, got %v", got)
	}
	got := parseLDAPGroupList("one, two\nthree")
	if len(got) != 3 || got[2] != "three" {
		t.Fatalf("expected comma/newline separated list, got %v", got)
	}
}

func TestLDAPGroupListStoreValueNil(t *testing.T) {
	if got := ldapGroupListStoreValue(nil); got != "[]" {
		t.Fatalf("expected empty JSON array for nil, got %q", got)
	}
}

func TestEncryptDecryptConfigSecretRoundTrip(t *testing.T) {
	encrypted, err := encryptConfigSecret(testJWTSecret, "bind-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(encrypted, "enc:") || strings.Contains(encrypted, "bind-secret") {
		t.Fatalf("unexpected ciphertext %q", encrypted)
	}
	decrypted, err := decryptConfigSecret(testJWTSecret, encrypted)
	if err != nil || decrypted != "bind-secret" {
		t.Fatalf("round trip failed: %q %v", decrypted, err)
	}
}

func TestDecryptConfigSecretRejectsInvalidHex(t *testing.T) {
	if _, err := decryptConfigSecret(testJWTSecret, "enc:zz-not-hex"); err == nil {
		t.Fatal("expected error for invalid hex payload")
	}
}

func TestHandleTestLDAPConfigInvalidBody(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("POST", testLDAPTestPath, strings.NewReader(testNotJSON))
	rec := httptest.NewRecorder()
	s.handleTestLDAPConfig(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
}

func TestHandleTestLDAPConfigValidationFailure(t *testing.T) {
	s := testServer(t)
	body := enabledLDAPConfigRequest()
	body.URL = ""
	req := httptest.NewRequest("POST", testLDAPTestPath, mustJSON(t, body))
	rec := httptest.NewRecorder()
	s.handleTestLDAPConfig(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "LDAP URL is required") {
		t.Fatalf("expected named validation error, got %s", rec.Body.String())
	}
}

func TestHandleTestLDAPConfigDialFailure(t *testing.T) {
	s := testServer(t)
	s.SetLDAPDialer(func(LDAPConfig) (LDAPConnection, error) {
		return nil, fmt.Errorf("dial refused")
	})
	req := httptest.NewRequest("POST", testLDAPTestPath, mustJSON(t, enabledLDAPConfigRequest()))
	rec := httptest.NewRecorder()
	s.handleTestLDAPConfig(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "failed to connect to LDAP") {
		t.Fatalf("expected connect error, got %s", rec.Body.String())
	}
}

func TestHandleTestLDAPConfigServiceBindFailure(t *testing.T) {
	s := testServer(t)
	s.SetLDAPDialer(func(LDAPConfig) (LDAPConnection, error) {
		return &coverageFakeConn{bindErr: fmt.Errorf("invalid credentials")}, nil
	})
	body := enabledLDAPConfigRequest()
	body.BindDN = "uid=svc,dc=example,dc=com"
	body.BindPassword = "wrong"
	req := httptest.NewRequest("POST", testLDAPTestPath, mustJSON(t, body))
	rec := httptest.NewRecorder()
	s.handleTestLDAPConfig(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "bind LDAP service account") {
		t.Fatalf("expected bind error, got %s", rec.Body.String())
	}
}

// A stored bind password that fails to decrypt surfaces as a 500 on every
// endpoint that must load the existing secret.
func TestLDAPConfigHandlersFailOnCorruptStoredPassword(t *testing.T) {
	s := testServer(t)
	setLDAPConfigForTest(t, s, map[string]string{
		"ldap.bind_password": "enc:not-valid-hex",
	})

	rec := httptest.NewRecorder()
	s.handleGetLDAPConfig(rec, httptest.NewRequest("GET", testLDAPPath, nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET: expected 500, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.handleUpdateLDAPConfig(rec, httptest.NewRequest("PUT", testLDAPPath, mustJSON(t, enabledLDAPConfigRequest())))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT: expected 500, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.handleTestLDAPConfig(rec, httptest.NewRequest("POST", testLDAPTestPath, mustJSON(t, enabledLDAPConfigRequest())))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("TEST: expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleUpdateLDAPConfigClearsBindPassword(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	encrypted, err := encryptConfigSecret(s.jwtSecret, "old-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	setLDAPConfigForTest(t, s, map[string]string{
		"ldap.bind_password": encrypted,
	})

	body := ldapConfigRequest{Enabled: false, ClearBindPassword: true}
	req := httptest.NewRequest("PUT", testLDAPPath, mustJSON(t, body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	stored, _, err := s.store.LookupConfig("ldap.bind_password")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if stored != "" {
		t.Fatalf("expected cleared bind password, got %q", stored)
	}

	getReq := httptest.NewRequest("GET", testLDAPPath, nil)
	getReq.Header.Set("Authorization", testBearerPrefix+token)
	getRec := httptest.NewRecorder()
	s.routes().ServeHTTP(getRec, getReq)
	if !strings.Contains(getRec.Body.String(), `"bind_password_set":false`) {
		t.Fatalf("expected bind_password_set=false after clear, got %s", getRec.Body.String())
	}
}

func TestHandleUpdateLDAPConfigInvalidBody(t *testing.T) {
	s := testServer(t)
	rec := httptest.NewRecorder()
	s.handleUpdateLDAPConfig(rec, httptest.NewRequest("PUT", testLDAPPath, strings.NewReader(testNotJSON)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
}
