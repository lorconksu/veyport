package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestApplicationManagementAPIsAndLaunch(t *testing.T) {
	s := testServer(t)
	s.applicationDomain = "apps.example.test"
	s.applicationPortalOrigin = "https://portal.example.test"
	u := &model.User{ID: "admin", Username: "admin", Email: "admin@example.test", Role: model.RoleAdmin, TOTPEnabled: true}
	if e := s.store.CreateUser(u); e != nil {
		t.Fatal(e)
	}
	now := s.now()
	if e := s.store.CreateSession(&model.Session{ID: "source", UserID: u.ID, Kind: model.SessionKindWeb, CreatedAt: now, LastSeenAt: now}); e != nil {
		t.Fatal(e)
	}
	token, _, e := auth.GenerateSessionTokenPair(s.jwtSecret, u.ID, "admin", 0, "source")
	if e != nil {
		t.Fatal(e)
	}
	request := func(method, path string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, s.applicationPortalOrigin+path, bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s got%d want%d: %s", method, path, w.Code, want, w.Body.String())
		}
		return w
	}
	request("GET", "/api/admin/application-subjects/users?limit=1&q=admin", nil, 200)
	groupResponse := request("POST", "/api/admin/application-groups", map[string]any{"name": "Operators", "user_ids": []string{u.ID}}, 201)
	var group model.ApplicationGroup
	json.Unmarshal(groupResponse.Body.Bytes(), &group)
	request("GET", "/api/admin/application-groups?limit=1", nil, 200)
	request("GET", "/api/admin/application-groups/"+group.ID, nil, 200)
	request("PUT", "/api/admin/application-groups/"+group.ID, map[string]any{"name": "Operators2", "user_ids": []string{u.ID}, "expected_version": 1}, 200)
	appResponse := request("POST", "/api/admin/applications", map[string]any{"name": "Demo", "slug": "demo", "route": "hub", "backend_url": "http://127.0.0.1:9999/base", "allowed_cidrs": []string{"127.0.0.0/8"}, "enabled": true}, 201)
	var app model.Application
	json.Unmarshal(appResponse.Body.Bytes(), &app)
	path := "/api/admin/applications/" + app.ID
	request("GET", "/api/admin/applications", nil, 200)
	request("GET", path, nil, 200)
	request("PUT", path+"/grants", map[string]any{"expected_version": 1, "grants": []model.ApplicationGrant{{Kind: "user", SubjectID: u.ID}, {Kind: "role", SubjectID: "viewer"}, {Kind: "local_group", SubjectID: group.ID}, {Kind: "directory_group", SubjectID: "ldap:group-id"}}}, 200)
	request("GET", path+"/grants", nil, 200)
	request("GET", "/api/applications", nil, 200)
	launch := request("POST", "/api/applications/"+app.ID+"/launch", map[string]string{"path": "/native?x=1"}, 200)
	var result struct{ Ticket, LaunchURL string }
	var payload map[string]string
	json.Unmarshal(launch.Body.Bytes(), &payload)
	result.Ticket = payload["ticket"]
	result.LaunchURL = payload["launch_url"]
	if result.Ticket == "" {
		t.Fatal("launch missing ticket")
	}
	form := bytes.NewBufferString("ticket=" + result.Ticket)
	r := httptest.NewRequest("POST", result.LaunchURL, form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", s.applicationPortalOrigin)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/native?x=1" {
		t.Fatalf("exchange %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != applicationCookie || cookies[0].Domain != "" {
		t.Fatal("launch credential boundary")
	}
	sessions := request("GET", "/api/auth/application-sessions", nil, 200)
	var listed struct {
		Sessions []model.ApplicationSession `json:"sessions"`
	}
	json.Unmarshal(sessions.Body.Bytes(), &listed)
	if len(listed.Sessions) != 1 || listed.Sessions[0].ApplicationName != "Demo" || listed.Sessions[0].IdleDeadlineAt == nil {
		t.Fatal("session display incomplete")
	}
	request("DELETE", "/api/auth/application-sessions/"+listed.Sessions[0].ID, nil, 200)
	request("GET", "/api/admin/application-settings", nil, 200)
	request("PUT", "/api/admin/application-settings", map[string]any{"idle_seconds": 1800, "max_seconds": 3600, "expected_version": 1}, 200)
	request("PUT", "/api/admin/application-settings", map[string]any{"idle_seconds": 1800, "max_seconds": 3600, "expected_version": 1}, 409)
	app.ConfigVersion = 2
	app.Name = "Edited"
	request("PUT", path, app, 200)
	request("PUT", path, app, 409)
	request("DELETE", path, nil, 200)
	request("DELETE", "/api/admin/application-groups/"+group.ID, nil, 200)
	request("GET", "/api/admin/application-subjects/directory-groups", nil, 503)
}

type applicationMemberReaderFunc func(context.Context, *model.User) (ApplicationMembership, error)

func (f applicationMemberReaderFunc) LookupMembership(ctx context.Context, u *model.User) (ApplicationMembership, error) {
	return f(ctx, u)
}
func TestApplicationLDAPFreshnessAppliesToDirectUserAndRoleGrants(t *testing.T) {
	s, a, cookie := applicationFixture(t, "http://127.0.0.1:9999")
	ss, _ := s.store.GetApplicationSession(refreshDigest(cookie))
	_, e := s.store.DB().Exec(`UPDATE users SET auth_provider='ldap',ldap_username='alice',ldap_dn='uid=alice,dc=example',external_id='identity' WHERE id=?`, ss.UserID)
	if e != nil {
		t.Fatal(e)
	}
	user, _ := s.store.GetUserByID(ss.UserID)
	now := s.now()
	failed := false
	s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
		if failed {
			return ApplicationMembership{}, fmt.Errorf("directory failed")
		}
		return ApplicationMembership{Groups: []string{"ldap:group"}, Role: model.RoleViewer}, nil
	})
	_, fp, e := s.applicationAuthorization(context.Background(), user, a)
	if e != nil || fp == "" {
		t.Fatal("direct LDAP grant lacked fresh identity", e)
	}
	failed = true
	s.SetClock(func() time.Time { return now.Add(3 * time.Second) })
	if _, _, e = s.applicationAuthorization(context.Background(), user, a); e == nil {
		t.Fatal("stale LDAP direct grant survives lookup failure")
	}
	failed = false
	if e = s.store.ReplaceApplicationGrants(a.ID, []model.ApplicationGrant{{Kind: "role", SubjectID: "viewer"}}, a.ConfigVersion, s.now()); e != nil {
		t.Fatal(e)
	}
	a, _ = s.store.GetApplication(a.ID)
	s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
		return ApplicationMembership{Role: model.RoleAuditor}, nil
	})
	s.SetClock(func() time.Time { return now.Add(6 * time.Second) })
	if _, _, e = s.applicationAuthorization(context.Background(), user, a); e == nil {
		t.Fatal("stale persisted LDAP role granted app")
	}
}
func TestApplicationRefusedRequestsDoNotTouchIdle(t *testing.T) {
	s, a, c := applicationFixture(t, "http://127.0.0.1:9999")
	before, _ := s.store.GetApplicationSession(refreshDigest(c))
	now := s.now()
	s.SetClock(func() time.Time { return now.Add(time.Minute) })
	r := appRequest(a, c, "POST", "/native")
	r.Header.Set("Origin", "https://sibling.apps.example.test")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	after, _ := s.store.GetApplicationSession(refreshDigest(c))
	if !before.LastSeenAt.Equal(after.LastSeenAt) {
		t.Fatal("refusal extended idle")
	}
}
func TestApplicationInvalidAdministrationInputsFailClosed(t *testing.T) {
	s, a, _ := applicationFixture(t, "http://127.0.0.1:9999")
	handlers := []http.HandlerFunc{s.handleApplicationCreate, s.handleApplicationUpdate, s.handleApplicationGrantsUpdate, s.handleApplicationGroupCreate, s.handleApplicationSettingsUpdate, s.handleApplicationLaunch}
	for _, handler := range handlers {
		r := httptest.NewRequest("POST", "https://portal.example.test/api/admin/applications", strings.NewReader("{"))
		r.SetPathValue("id", a.ID)
		r = r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxUserID, "missing"), ctxSessionID, "missing"))
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code < 400 {
			t.Fatal("invalid mutation accepted")
		}
	}
	for _, input := range []struct{ field, value string }{{"backend_url", "http://user:pass@private.test"}, {"backend_url", "http://private.test/app?query=secret"}, {"backend_url", "file:///private"}, {"backend_url", "https://private.test/../secret"}, {"slug", "Bad Slug"}, {"route", "automatic"}, {"node_id", "unconfigured"}} {
		copy := *a
		switch input.field {
		case "backend_url":
			copy.BackendURL = input.value
		case "slug":
			copy.Slug = input.value
		case "route":
			copy.Route = input.value
		case "node_id":
			copy.NodeID = input.value
		}
		if e := s.validateApplication(&copy); e == nil {
			t.Errorf("invalid %+v accepted", input)
		}
	}
	for _, grants := range [][]model.ApplicationGrant{{{Kind: "unknown", SubjectID: "id"}}, {{Kind: "user", SubjectID: "missing"}}, {{Kind: "role", SubjectID: "arbitrary"}}, {{Kind: "local_group", SubjectID: "missing"}}, {{Kind: "directory_group", SubjectID: "UpperCase"}}, {{Kind: "user", SubjectID: "x"}, {Kind: "user", SubjectID: "x"}}} {
		if s.validApplicationGrants(grants) {
			t.Fatal("invalid grants accepted", grants)
		}
	}
	_ = s.store.Close()
	for _, handler := range []http.HandlerFunc{s.handleAdminApplications, s.handleApplicationGet, s.handleApplicationDelete, s.handleApplicationGrants, s.handleApplicationGroups, s.handleApplicationGroup, s.handleApplicationGroupDelete, s.handleApplicationUserSubjects, s.handleApplicationSessions, s.handleApplicationSessionEnd, s.handleApplications} {
		r := httptest.NewRequest("GET", "https://portal.example.test/api/admin/applications", nil)
		r.SetPathValue("id", a.ID)
		r = r.WithContext(context.WithValue(r.Context(), ctxUserID, "u"))
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code < 400 {
			t.Fatal("persistence outage allowed operation")
		}
	}
}
func TestApplicationAdministrationRejectsStaleAndMalformedState(t *testing.T) {
	s, a, _ := applicationFixture(t, "http://127.0.0.1:9999")
	cases := []struct {
		handler http.HandlerFunc
		body    string
		id      string
		want    int
	}{{s.handleApplicationCreate, `{"name":"Demo","slug":"demo","route":"hub","backend_url":"http://127.0.0.1:9999","allowed_cidrs":["127.0.0.0/8"],"enabled":true}`, "", 409}, {s.handleApplicationUpdate, `{"name":"Demo","slug":"demo","route":"hub","backend_url":"file:///secret"}`, a.ID, 400}, {s.handleApplicationUpdate, `{}`, "missing", 404}, {s.handleApplicationGrantsUpdate, `{"grants":[],"expected_version":99}`, a.ID, 409}, {s.handleApplicationGroupUpdate, `{"name":"Group","user_ids":[],"expected_version":2}`, "missing", 409}, {s.handleApplicationSettingsUpdate, `{"idle_seconds":0,"max_seconds":43200,"expected_version":1}`, "", 400}, {s.handleApplicationSettingsUpdate, `{"idle_seconds":2700,"max_seconds":43200,"expected_version":99}`, "", 409}}
	for _, tc := range cases {
		r := httptest.NewRequest("POST", "https://portal.example.test/api/admin/applications", strings.NewReader(tc.body))
		r.SetPathValue("id", tc.id)
		w := httptest.NewRecorder()
		tc.handler(w, r)
		if w.Code != tc.want {
			t.Fatalf("invalid/stale admin case got%d want%d: %s", w.Code, tc.want, w.Body.String())
		}
	}
	r := httptest.NewRequest("GET", "https://portal.example.test/?q="+strings.Repeat("x", 121), nil)
	w := httptest.NewRecorder()
	s.handleApplicationUserSubjects(w, r)
	if w.Code != 400 {
		t.Fatal("unbounded subject search")
	}
	if l, o := appPagination(httptest.NewRequest("GET", "/?limit=999&offset=-1", nil)); l != 50 || o != 0 {
		t.Fatal("pagination bounds")
	}
	s.applicationDomain = ""
	if e := s.validateApplication(a); e == nil {
		t.Fatal("unconfigured namespace accepted")
	}
}
func TestApplicationTLSConfigAndDestinationValidation(t *testing.T) {
	s, a, _ := applicationFixture(t, "http://127.0.0.1:9999")
	for _, change := range []func(*model.Application){func(v *model.Application) { v.CAPEM = "private key" }, func(v *model.Application) { v.CAPEM = strings.Repeat("x", 65537) }, func(v *model.Application) { v.Name = "" }, func(v *model.Application) { v.Description = strings.Repeat("x", 1001) }, func(v *model.Application) { v.AllowedCIDRs = nil }, func(v *model.Application) { v.Route = "node"; v.NodeID = "missing" }, func(v *model.Application) { v.BackendURL = "http://127.0.0.1:invalid" }} {
		copy := *a
		change(&copy)
		if e := s.validateApplication(&copy); e == nil {
			t.Fatal("invalid backend configuration accepted")
		}
	}
	target, e := applicationTarget(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.ValidateApplicationTarget(context.Background(), target); e != nil {
		t.Fatal(e)
	}
	target.ConfigVersion++
	if e = s.ValidateApplicationTarget(context.Background(), target); e == nil {
		t.Fatal("stale target authority accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = s.ValidateApplicationTarget(ctx, target); e == nil {
		t.Fatal("cancelled admission accepted")
	}
	a, _ = s.store.GetApplication(a.ID)
	a.AllowedCIDRs = []string{"127.0.0.0/8"}
	target, _ = applicationTarget(a)
	target.AllowedCIDRs = []string{"0.0.0.0/0"}
	if e = s.ValidateApplicationTarget(context.Background(), target); e == nil {
		t.Fatal("browser widened target network")
	}
}
