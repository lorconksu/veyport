package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/applicationtransport"
	"github.com/wyiu/veyport/hub/internal/model"
)

func applicationManagementRequest(s *Server, appID, userID, sourceID, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, s.applicationPortalOrigin+"/api/applications/"+appID+"/launch", strings.NewReader(body))
	r.SetPathValue("id", appID)
	return r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxUserID, userID), ctxSessionID, sourceID))
}

func TestApplicationLaunchFailureStagesNeverIssueAuthority(t *testing.T) {
	for _, scenario := range []struct {
		name string
		want int
	}{
		{"missing_application", 404}, {"disabled_application", 403}, {"lost_grant", 403},
		{"CLI_source", 403}, {"maximum_elapsed", 401}, {"malformed_body", 400},
		{"invalid_destination", 400}, {"revoked_anchor", 403}, {"ticket_storage_failure", 500},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s, app, credential := applicationFixture(t, "http://127.0.0.1:9999")
			s.stopSessionPruner()
			session, err := s.store.GetApplicationSession(refreshDigest(credential))
			if err != nil {
				t.Fatal(err)
			}
			anchor, err := s.store.GetApplicationAnchor(session.AnchorID)
			if err != nil {
				t.Fatal(err)
			}
			source := &model.Session{ID: uuid.NewString(), UserID: session.UserID, Kind: model.SessionKindWeb, CreatedAt: anchor.CompletedMFAAt.Truncate(time.Second), LastSeenAt: s.now()}
			if scenario.name == "CLI_source" {
				source.Kind = model.SessionKindCLI
			}
			if scenario.name == "maximum_elapsed" {
				source.CreatedAt = s.now().Add(-13 * time.Hour)
			}
			if err := s.store.CreateSession(source); err != nil {
				t.Fatal(err)
			}
			if err := s.store.EnsureApplicationAnchor(model.ApplicationAnchor{ID: source.ID, UserID: source.UserID, CompletedMFAAt: source.CreatedAt.Truncate(time.Second)}); err != nil {
				t.Fatal(err)
			}
			id, body := app.ID, `{"path":"/native"}`
			switch scenario.name {
			case "missing_application":
				id = "missing"
			case "disabled_application":
				app.Enabled = false
				if err = s.store.UpdateApplication(app, app.ConfigVersion, s.now()); err != nil {
					t.Fatal(err)
				}
			case "lost_grant":
				if err = s.store.ReplaceApplicationGrants(app.ID, nil, app.ConfigVersion, s.now()); err != nil {
					t.Fatal(err)
				}
			case "malformed_body":
				body = "{"
			case "invalid_destination":
				body = `{"path":"//untrusted.example"}`
			case "revoked_anchor":
				if err = s.store.RevokeApplicationFamily(session.UserID, source.ID, "logout", s.now()); err != nil {
					t.Fatal(err)
				}
			case "ticket_storage_failure":
				_, err = s.store.DB().Exec(`CREATE TRIGGER fail_launch_ticket BEFORE INSERT ON application_launch_tickets BEGIN SELECT RAISE(ABORT,'synthetic ticket storage unavailable'); END`)
				if err != nil {
					t.Fatal(err)
				}
			}
			response := httptest.NewRecorder()
			s.handleApplicationLaunch(response, applicationManagementRequest(s, id, session.UserID, source.ID, body))
			if response.Code != scenario.want || len(response.Result().Cookies()) != 0 || strings.Contains(response.Body.String(), `"ticket":`) {
				t.Fatalf("failed launch issued authority: %d %s", response.Code, response.Body.String())
			}
			var pending int
			if err = s.store.DB().QueryRow(`SELECT count(*) FROM application_launch_tickets`).Scan(&pending); err != nil || pending != 0 {
				t.Fatal("failed launch retained ticket", pending, err)
			}
		})
	}
}

func TestApplicationDeletionWaitsForDurableAuditAndRetries(t *testing.T) {
	for _, scenario := range []string{"audit_failure", "audit_backlog", "delete_failure"} {
		t.Run(scenario, func(t *testing.T) {
			s, app, credential := applicationFixture(t, "http://127.0.0.1:9999")
			s.stopSessionPruner()
			session, err := s.store.GetApplicationSession(refreshDigest(credential))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "audit_backlog" {
				for i := 0; i < 105; i++ {
					digest := uuid.NewString()
					ticket := model.ApplicationLaunchTicket{Digest: digest, ApplicationID: app.ID, UserID: session.UserID, AnchorID: session.AnchorID, Hostname: app.PublicHostname, ConfigVersion: app.ConfigVersion, AccessRevision: session.AccessRevision, Path: "/", ExpiresAt: s.now().Add(time.Minute)}
					if err = s.store.CreateApplicationTicket(ticket); err != nil {
						t.Fatal(err)
					}
					if _, err = s.store.ConsumeApplicationTicket(digest, app.PublicHostname, model.ApplicationSession{ID: uuid.NewString(), CredentialDigest: uuid.NewString(), ExpiresAt: session.ExpiresAt}, s.now()); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				trigger := `CREATE TRIGGER fail_delete_operation BEFORE INSERT ON audit_logs WHEN NEW.action='application.session_ended' BEGIN SELECT RAISE(ABORT,'synthetic audit unavailable'); END`
				if scenario == "delete_failure" {
					trigger = `CREATE TRIGGER fail_delete_operation BEFORE DELETE ON applications BEGIN SELECT RAISE(ABORT,'synthetic deletion unavailable'); END`
				}
				if _, err = s.store.DB().Exec(trigger); err != nil {
					t.Fatal(err)
				}
			}
			r := applicationManagementRequest(s, app.ID, session.UserID, session.AnchorID, "")
			response := httptest.NewRecorder()
			s.handleApplicationDelete(response, r)
			want := 503
			if scenario == "delete_failure" {
				want = 500
			}
			if response.Code != want {
				t.Fatalf("unsafe deletion completion: %d %s", response.Code, response.Body.String())
			}
			retained, err := s.store.GetApplication(app.ID)
			if err != nil || retained.Enabled {
				t.Fatal("failed deletion left app admissible", err)
			}
			if scenario != "audit_backlog" {
				if _, err = s.store.DB().Exec(`DROP TRIGGER fail_delete_operation`); err != nil {
					t.Fatal(err)
				}
			}
			response = httptest.NewRecorder()
			s.handleApplicationDelete(response, r)
			if response.Code != 200 {
				t.Fatalf("durable deletion retry failed: %d %s", response.Code, response.Body.String())
			}
			audited, err := s.store.ApplicationAuditExists("application-session-end:" + session.ID)
			if err != nil || !audited {
				t.Fatal("cascade lost durable end audit", err)
			}
		})
	}
}

type applicationStatusDialer struct{ supported, online bool }

func (d applicationStatusDialer) DialApplication(context.Context, applicationtransport.Target) (net.Conn, error) {
	return nil, errors.New("fixture must not dial")
}
func (d applicationStatusDialer) ApplicationAvailability(string) (bool, bool) {
	return d.supported, d.online
}

func TestApplicationDirectoryListUsesFreshRoleAndGroupsAndNodeAvailability(t *testing.T) {
	s, app, session := directorySessionFixture(t, "role")
	s.stopSessionPruner()
	if _, err := s.store.DB().Exec(`UPDATE applications SET config_json=json_set(config_json,'$.route','node','$.node_id','node') WHERE id=?`, app.ID); err != nil {
		t.Fatal(err)
	}
	r := applicationManagementRequest(s, app.ID, session.UserID, session.AnchorID, "")
	for _, status := range []struct {
		supported, online bool
		reason            string
	}{{false, false, "agent upgrade required"}, {true, false, "node offline"}, {true, true, ""}} {
		s.SetApplicationDialer(applicationStatusDialer{status.supported, status.online})
		response := httptest.NewRecorder()
		s.handleApplications(response, r)
		var listed struct {
			Applications []struct {
				Available         bool   `json:"available"`
				UnavailableReason string `json:"availability_reason"`
				BackendURL        string `json:"backend_url"`
			} `json:"applications"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
			t.Fatal(err)
		}
		if response.Code != 200 || len(listed.Applications) != 1 || listed.Total != 1 || listed.Applications[0].Available != (status.supported && status.online) || listed.Applications[0].UnavailableReason != status.reason || listed.Applications[0].BackendURL != "" {
			t.Fatalf("incorrect private availability DTO: %s", response.Body.String())
		}
	}
	now := s.now()
	s.SetClock(func() time.Time { return now.Add(3 * time.Second) })
	s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
		return ApplicationMembership{}, errors.New("synthetic directory unavailable")
	})
	response := httptest.NewRecorder()
	s.handleApplications(response, r)
	if response.Code != 503 || strings.Contains(response.Body.String(), app.Name) {
		t.Fatal("stale directory identity leaked app metadata", response.Code)
	}
}

func TestApplicationGrantAndPolicyLimitsRejectAmbiguousInputs(t *testing.T) {
	s, app, credential := applicationFixture(t, "http://127.0.0.1:9999")
	s.stopSessionPruner()
	session, _ := s.store.GetApplicationSession(refreshDigest(credential))
	for _, grants := range [][]model.ApplicationGrant{make([]model.ApplicationGrant, 501), {{Kind: "directory_group", SubjectID: ""}}, {{Kind: "directory_group", SubjectID: strings.Repeat("x", 1025)}}} {
		if s.validApplicationGrants(grants) {
			t.Fatal("unbounded/empty grant accepted")
		}
	}
	for _, value := range []string{"{", `{"idle_seconds":1,"max_seconds":43200,"version":8}`} {
		if err := s.store.SetConfig("application.policy", value); err != nil {
			t.Fatal(err)
		}
		policy := s.applicationPolicy()
		if policy.IdleSeconds != 60 || policy.MaxSeconds != 300 || policy.Version != 1 {
			t.Fatal("corrupt policy did not fail conservatively", policy)
		}
	}
	if err := s.store.SetConfig("application.policy", `{"idle_seconds":60,"max_seconds":300,"version":1}`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.DB().Exec(`CREATE TRIGGER fail_policy_write BEFORE UPDATE ON _config WHEN NEW.key='application.policy' BEGIN SELECT RAISE(ABORT,'synthetic policy storage unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.handleApplicationSettingsUpdate(response, applicationManagementRequest(s, app.ID, session.UserID, session.AnchorID, `{"idle_seconds":60,"max_seconds":300,"expected_version":1}`))
	if response.Code != 409 {
		t.Fatal("failed policy write reported success", response.Code, response.Body.String())
	}
}

func TestApplicationAdminValidationAndSubjectPaginationNeverReturnWholeUserList(t *testing.T) {
	s, app, cookie := applicationFixture(t, "http://127.0.0.1:9999")
	s.stopSessionPruner()
	session, err := s.store.GetApplicationSession(refreshDigest(cookie))
	if err != nil {
		t.Fatal(err)
	}
	invalid := `{"slug":"bad","name":"Bad","route":"hub","backend_url":"file:///private","allowed_cidrs":["127.0.0.0/8"],"enabled":true}`
	response := httptest.NewRecorder()
	s.handleApplicationCreate(response, applicationManagementRequest(s, app.ID, session.UserID, session.AnchorID, invalid))
	if response.Code != 400 {
		t.Fatal("invalid administrator target accepted", response.Code)
	}
	if err = s.store.CreateUser(&model.User{ID: "sibling", Username: "sibling", Email: "sibling@example.test", Role: model.RoleViewer}); err != nil {
		t.Fatal(err)
	}
	request := applicationManagementRequest(s, app.ID, session.UserID, session.AnchorID, "")
	request.URL.RawQuery = "limit=1&offset=1"
	response = httptest.NewRecorder()
	s.handleApplicationUserSubjects(response, request)
	var page struct {
		Users []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"users"`
		Total int `json:"total"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || page.Total != 2 || len(page.Users) != 1 || page.Users[0].ID != "sibling" {
		t.Fatal("subject pagination returned unbounded/wrong page", response.Code, page)
	}
	request.URL.RawQuery = "q=%27%20OR%201%3D1--"
	response = httptest.NewRecorder()
	s.handleApplicationUserSubjects(response, request)
	if err = json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || page.Total != 0 || len(page.Users) != 0 {
		t.Fatal("subject search interpreted query as SQL", response.Code, page)
	}
}

func TestApplicationTargetsNormalizeDefaultPortsAndRejectBrokenPersistedConfiguration(t *testing.T) {
	for _, test := range []struct {
		backend string
		port    uint16
	}{{"http://127.0.0.1/base", 80}, {"https://127.0.0.1/base", 443}} {
		app := &model.Application{ID: "target", ConfigVersion: 1, BackendURL: test.backend, AllowedCIDRs: []string{"127.0.0.0/8"}}
		target, err := applicationTarget(app)
		if err != nil || target.Port != test.port {
			t.Fatal("backend default port was lost", target, err)
		}
	}
	for _, backend := range []string{"http://host/%zz", "http://host:99999"} {
		if _, err := applicationTarget(&model.Application{BackendURL: backend}); err == nil {
			t.Fatal("invalid target port/path accepted")
		}
	}
	s, app, _ := applicationFixture(t, "http://127.0.0.1:9999")
	s.stopSessionPruner()
	target, err := applicationTarget(app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.store.DB().Exec(`UPDATE applications SET config_json=json_set(config_json,'$.backend_url','http://host:99999') WHERE id=?`, app.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.ValidateApplicationTarget(context.Background(), target); err == nil {
		t.Fatal("broken persisted target accepted stale authority")
	}
}
