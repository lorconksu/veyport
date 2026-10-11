package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

func grantSelectorRole(t *testing.T, s *Server, id string, role model.Role) string {
	t.Helper()
	if _, err := s.store.DB().Exec("INSERT INTO user_roles(user_id,role) VALUES(?,?)", id, role); err != nil {
		t.Fatal(err)
	}
	access, _, _ := sessionTokenPair(t, s, id)
	return access
}

func TestSecurityPrincipalSelectorIsBoundedAndMinimal(t *testing.T) {
	s := testServer(t)
	operator, _, _, _ := quickSecurityUser(t, s, "selector-officer", model.RoleViewer)
	token := grantSelectorRole(t, s, operator.ID, model.RoleSecurityOfficer)
	for _, id := range []string{"target-a", "target-b", "target-c", "target%literal"} {
		secret := "CANARY_TOTP_SECRET"
		if err := s.store.CreateUser(&model.User{ID: id, Username: id, Email: "CANARY_EMAIL_" + id, PasswordHash: "CANARY_PASSWORD_HASH", Role: model.RoleViewer, TOTPSecret: &secret, TOTPEnabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	response := securityCall(s, "GET", "/api/security/principals?search=target-&limit=1&offset=1", token, nil)
	var page struct {
		Principals           []securityPrincipal `json:"principals"`
		Total, Limit, Offset int
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.Total != 3 || page.Limit != 1 || page.Offset != 1 || len(page.Principals) != 1 || page.Principals[0].ID != "target-b" || !page.Principals[0].TOTPEnabled || page.Principals[0].PersonID != "user:target-b" || len(page.Principals[0].Roles) != 1 {
		t.Fatalf("minimal selector: %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "CANARY") || strings.Contains(response.Body.String(), "email") || strings.Contains(response.Body.String(), "password") || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("selector exposed credentials/history or permitted caching")
	}
	response = securityCall(s, "GET", "/api/security/principals?search=target%25", token, nil)
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.Total != 1 || len(page.Principals) != 1 || page.Principals[0].ID != "target%literal" {
		t.Fatal("search wildcard broadened enumeration")
	}
	if response := securityCall(s, "GET", "/api/users", token, nil); response.Code != http.StatusForbidden {
		t.Fatal("security selector authority became operations admin")
	}
	for _, query := range []string{"limit=101", "limit=0", "limit=-1", "limit=wrong", "offset=-1", "offset=1000001", "offset=wrong", "search=" + strings.Repeat("x", 129), "search=line%0Abreak", "limit=1&limit=2", "fields=password_hash"} {
		if response := securityCall(s, "GET", "/api/security/principals?"+query, token, nil); response.Code != 400 {
			t.Fatalf("unbounded query accepted: %s %d", query, response.Code)
		}
	}
}

func TestSecurityPrincipalSelectorInitialBootstrapDoesNotReopenAfterEnrollment(t *testing.T) {
	s := testServer(t)
	_, token, _, _ := quickSecurityUser(t, s, "selector-admin", model.RoleAdmin)
	if response := securityCall(s, "GET", "/api/security/principals", token, nil); response.Code != 200 {
		t.Fatal("initial Standard bootstrap could not nominate principals")
	}
	// Historical Enhanced enrollment remains authoritative even after a
	// legitimate later Standard policy; this is an isolated SQL fixture only.
	if _, err := s.store.DB().Exec(`INSERT INTO audit_policy_versions(version,payload,digest) VALUES(2,'{"profile":"enhanced"}','fixture')`); err != nil {
		t.Fatal(err)
	}
	if response := securityCall(s, "GET", "/api/security/principals", token, nil); response.Code != 403 {
		t.Fatal("Standard disable reopened administrative security visibility")
	}
	_, approver, _, _ := quickSecurityUser(t, s, "selector-approver", model.RoleViewer)
	_ = approver
	approver = grantSelectorRole(t, s, "selector-approver", model.RoleSecurityApprover)
	if response := securityCall(s, "GET", "/api/security/principals", approver, nil); response.Code != 200 {
		t.Fatal("live approver could not use safe selector")
	}
	_, viewer, _, _ := quickSecurityUser(t, s, "selector-viewer", model.RoleViewer)
	if response := securityCall(s, "GET", "/api/security/principals", viewer, nil); response.Code != 403 {
		t.Fatal("viewer enumerated principals")
	}
	if response := securityCall(s, "GET", "/api/security/principals", "", nil); response.Code != 401 {
		t.Fatal("unauthenticated caller enumerated principals")
	}
}
