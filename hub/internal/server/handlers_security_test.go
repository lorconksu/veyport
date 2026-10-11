package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
)

func quickSecurityUser(t *testing.T, s *Server, id string, role model.Role) (*model.User, string, string, string) {
	t.Helper()
	secret := "JBSWY3DPEHPK3PXP"
	u := &model.User{ID: id, Username: id, Email: id + "@test.invalid", Role: role, TOTPSecret: &secret, TOTPEnabled: true}
	if err := s.store.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	access, refresh, session := sessionTokenPair(t, s, id)
	return u, access, refresh, session
}
func securityCall(s *Server, method, path, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}
func TestSecurityJWTClaimsCannotGrantLiveAuthority(t *testing.T) {
	s := testServer(t)
	u, _, _, sid := quickSecurityUser(t, s, "live-viewer", model.RoleViewer)
	forged, _, err := auth.GenerateSessionTokenPair(s.jwtSecret, u.ID, "admin", 0, sid)
	if err != nil {
		t.Fatal(err)
	}
	response := securityCall(s, "GET", "/api/users", forged, nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("stale role claim authorized: %d %s", response.Code, response.Body.String())
	}
	response = securityCall(s, "GET", "/api/auth/me", forged, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"roles":["viewer"]`) || strings.Contains(response.Body.String(), "operations.admin") {
		t.Fatalf("live roles response: %d %s", response.Code, response.Body.String())
	}
}
func TestSecurityPreviewStrictJSONAndActionBoundMFASurvivesRefresh(t *testing.T) {
	s := testServer(t)
	u, token, refresh, sid := quickSecurityUser(t, s, "preview-admin", model.RoleAdmin)
	change := model.SecurityChangePayload{Kind: "policy", Policy: &model.AuditPolicy{Profile: "standard", RuntimeSeconds: 3600, RetentionHours: 24}}
	raw, _ := json.Marshal(change)
	proposal := authorization.Proposal{Reason: "Review policy", ExpectedVersion: 1, Change: raw}
	body, _ := json.Marshal(proposal)
	response := securityCall(s, "POST", "/api/security/changes/preview", token, body)
	if response.Code != 200 {
		t.Fatalf("preview: %d %s", response.Code, response.Body.String())
	}
	var preview authorization.Preview
	if err := json.Unmarshal(response.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"Reason":"Review","expected_version":1,"change":{"kind":"policy"}}`, `{"reason":"first","reason":"second","expected_version":1,"change":{"kind":"policy"}}`, `{"reason":"Review","expected_version":1,"change":{"kind":"policy","Kind":"bootstrap"}}`} {
		response = securityCall(s, "POST", "/api/security/changes/preview", token, []byte(bad))
		if response.Code != 400 {
			t.Fatalf("ambiguous JSON accepted: %d %s", response.Code, response.Body.String())
		}
	}
	code, _ := auth.GenerateValidCode(*u.TOTPSecret)
	body, _ = json.Marshal(map[string]string{"action": authorization.ActionRequest, "digest": preview.Digest, "code": code})
	response = securityCall(s, "POST", "/api/security/step-up", token, body)
	if response.Code != 200 {
		t.Fatalf("stepup: %d %s", response.Code, response.Body.String())
	}
	var result struct {
		Proof string `json:"proof"`
	}
	json.Unmarshal(response.Body.Bytes(), &result)
	before, _ := s.store.GetUserByID(u.ID)
	response = securityCall(s, "POST", "/api/auth/refresh", "", mustMarshal(t, model.RefreshRequest{RefreshToken: refresh}))
	if response.Code != 200 {
		t.Fatalf("real refresh: %d %s", response.Code, response.Body.String())
	}
	after, _ := s.store.GetUserByID(u.ID)
	if after.SecurityRevision != before.SecurityRevision || after.TokenGeneration != before.TokenGeneration {
		t.Fatal("routine refresh changed security or user revocation authority")
	}
	if err := s.store.ConsumeStepup(result.Proof, u.ID, sid, authorization.ActionApprove, preview.Digest, s.now()); err == nil {
		t.Fatal("proof moved to approval")
	}
	if err := s.store.ConsumeStepup(result.Proof, u.ID, sid, authorization.ActionRequest, preview.Digest, s.now()); err != nil {
		t.Fatalf("refresh invalidated fresh proof: %v", err)
	}
	if err := s.store.ConsumeStepup(result.Proof, u.ID, sid, authorization.ActionRequest, preview.Digest, s.now()); err == nil {
		t.Fatal("proof reused")
	}
}
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestSecurityNoAPITokenOrLegacyResetBypass(t *testing.T) {
	s := testServer(t)
	_, admin, _, _ := quickSecurityUser(t, s, "operations-admin", model.RoleAdmin)
	u, _, _, _ := quickSecurityUser(t, s, "security-principal", model.RoleAuditor)
	if _, err := s.store.DB().Exec("INSERT INTO user_roles(user_id,role) VALUES(?,'security-officer')", u.ID); err != nil {
		t.Fatal(err)
	}
	response := securityCall(s, "PUT", "/api/users/"+u.ID+"/role", admin, []byte(`{"role":"viewer"}`))
	if response.Code != 403 || !strings.Contains(response.Body.String(), "/api/security/changes") {
		t.Fatalf("legacy role bypass: %d %s", response.Code, response.Body.String())
	}
	response = securityCall(s, "POST", "/api/auth/totp/disable", admin, mustMarshal(t, model.TOTPDisableRequest{UserID: u.ID}))
	if response.Code != 403 {
		t.Fatalf("legacy MFA reset bypass: %d %s", response.Code, response.Body.String())
	}
	token, hash, _, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateAPIToken(&model.APIToken{ID: "automation-token", UserID: u.ID, Name: "automation", TokenHash: hash, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	response = securityCall(s, "POST", "/api/security/step-up", token, []byte(`{"action":"security.request","digest":"`+authorization.Digest([]byte("request"))+`","code":"000000"}`))
	if response.Code != 403 {
		t.Fatalf("API token supplied fresh MFA: %d %s", response.Code, response.Body.String())
	}
}
func TestSecurityPolicyDetailsAndActualReadiness(t *testing.T) {
	s := testServer(t)
	_, viewer, _, _ := quickSecurityUser(t, s, "readiness-viewer", model.RoleViewer)
	_, admin, _, _ := quickSecurityUser(t, s, "readiness-admin", model.RoleAdmin)
	s.securityTransition.Evidence = &authorization.ReceiptEvidence{}
	s.securityDestinationTester = acceptingSecurityTester{}
	response := securityCall(s, "GET", "/api/audit-policy", viewer, nil)
	if response.Code != 200 || strings.Contains(response.Body.String(), "credential_ref") || strings.Contains(response.Body.String(), "destination") {
		t.Fatalf("policy secrets/references disclosed: %s", response.Body.String())
	}
	response = securityCall(s, "GET", "/api/audit-policy", admin, nil)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"archive_and_transport":false`) {
		t.Fatalf("unqualified transport advertised ready: %s", response.Body.String())
	}
}

type acceptingSecurityTester struct{}

func (acceptingSecurityTester) Test(context.Context, model.AuditPolicy) error { return nil }
func TestSecuritySecretsWriteOnlyAndDestinationAllowlist(t *testing.T) {
	s := testServer(t)
	_, token, _, _ := quickSecurityUser(t, s, "destination-admin", model.RoleAdmin)
	s.securityAllowedHosts = []string{"audit.test.invalid:443"}
	s.securityDestinationTester = acceptingSecurityTester{}
	canary := "synthetic-write-only-secret-canary"
	response := securityCall(s, "POST", "/api/security/secrets", token, mustMarshal(t, map[string]string{"kind": "destination", "value": canary}))
	if response.Code != 201 || strings.Contains(response.Body.String(), canary) {
		t.Fatalf("secret not write-only %d %s", response.Code, response.Body.String())
	}
	var secret struct {
		Ref string `json:"credential_ref"`
	}
	json.Unmarshal(response.Body.Bytes(), &secret)
	stored, err := s.store.SecuritySecret(secret.Ref)
	if err != nil || bytes.Contains(stored, []byte(canary)) {
		t.Fatal("secret stored unencrypted")
	}
	for _, destination := range []string{"http://audit.test.invalid:443", "https://169.254.169.254", "https://127.0.0.1", "https://user:pass@audit.test.invalid:443", "https://audit.test.invalid:443/path", "https://audit.test.invalid:443?secret=value"} {
		response = securityCall(s, "POST", "/api/audit-policy/test", token, mustMarshal(t, model.AuditPolicy{Destination: destination}))
		if response.Code == 200 {
			t.Fatalf("unsafe destination accepted %s", destination)
		}
	}
	response = securityCall(s, "POST", "/api/audit-policy/test", token, mustMarshal(t, model.AuditPolicy{Destination: "https://audit.test.invalid:443"}))
	if response.Code != 200 {
		t.Fatalf("operator allowed endpoint refused %d %s", response.Code, response.Body.String())
	}
}
