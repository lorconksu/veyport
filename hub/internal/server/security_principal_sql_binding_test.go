package server

import (
	"encoding/json"
	"github.com/wyiu/veyport/hub/internal/model"
	"net/url"
	"testing"
)

func TestSecurityPrincipalSearchTreatsSQLSyntaxAsData(t *testing.T) {
	s := testServer(t)
	u, _, _, _ := quickSecurityUser(t, s, "sonar-officer", model.RoleViewer)
	token := grantSelectorRole(t, s, u.ID, model.RoleSecurityOfficer)
	poison := "' OR 1=1 --"
	var page struct {
		Principals []securityPrincipal
		Total      int
	}
	r := securityCall(s, "GET", "/api/security/principals?search="+url.QueryEscape(poison), token, nil)
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &page) != nil || page.Total != 0 || len(page.Principals) != 0 {
		t.Fatalf("quoted search broadened query: %d %s", r.Code, r.Body.String())
	}
	if err := s.store.CreateUser(&model.User{ID: poison, Username: poison, Email: "literal@test.invalid", Role: model.RoleViewer}); err != nil {
		t.Fatal(err)
	}
	r = securityCall(s, "GET", "/api/security/principals?search="+url.QueryEscape(poison), token, nil)
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &page) != nil || page.Total != 1 || len(page.Principals) != 1 || page.Principals[0].ID != poison {
		t.Fatalf("literal quoted search failed: %d %s", r.Code, r.Body.String())
	}
}
