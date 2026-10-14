package store

import (
	"fmt"
	"github.com/wyiu/veyport/hub/internal/model"
	"testing"
	"time"
)

func appStore(t *testing.T) *Store {
	t.Helper()
	s, e := New(":memory:")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	if e = s.CreateUser(&model.User{ID: "u", Username: "alice", Email: "alice@example.test", Role: model.RoleViewer}); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestApplicationAuthoritySurvivesDashboardExpiryButFamilyRevokeWins(t *testing.T) {
	s := appStore(t)
	now := time.Now().UTC()
	a := &model.Application{ID: "a", Name: "Demo", Slug: "demo", PublicHostname: "demo.apps.example.test", Route: "hub", BackendURL: "http://127.0.0.1:9999", AllowedCIDRs: []string{"127.0.0.0/8"}, Enabled: true}
	if e := s.CreateApplication(a, now); e != nil {
		t.Fatal(e)
	}
	anchor := model.ApplicationAnchor{ID: "parent", UserID: "u", CompletedMFAAt: now}
	if e := s.EnsureApplicationAnchor(anchor); e != nil {
		t.Fatal(e)
	}
	ticket := model.ApplicationLaunchTicket{Digest: "ticket", ApplicationID: "a", UserID: "u", AnchorID: "parent", Hostname: a.PublicHostname, Path: "/", ConfigVersion: 1, ExpiresAt: now.Add(30 * time.Second)}
	ticket.AccessRevision, _ = s.ApplicationAccessRevision("u")
	if e := s.CreateApplicationTicket(ticket); e != nil {
		t.Fatal(e)
	}
	ss := model.ApplicationSession{ID: "s", CredentialDigest: "cookie", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(12 * time.Hour)}
	if _, e := s.ConsumeApplicationTicket("ticket", a.PublicHostname, ss, now); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ConsumeApplicationTicket("ticket", a.PublicHostname, ss, now); e == nil {
		t.Fatal("ticket replay")
	}
	if _, e := s.GetApplicationSession("cookie"); e != nil {
		t.Fatal(e)
	}
	if e := s.RevokeApplicationFamily("u", "parent", "logout", now); e != nil {
		t.Fatal(e)
	}
	got, e := s.GetApplicationSession("cookie")
	if e != nil {
		t.Fatal(e)
	}
	if got.EndedAt == nil {
		t.Fatal("app survives explicit family revoke")
	}
	if e := s.EnsureApplicationAnchor(anchor); e == nil {
		t.Fatal("revoked anchor restored")
	}
}
func TestApplicationConfigurationInvalidatesPendingTickets(t *testing.T) {
	s := appStore(t)
	now := time.Now().UTC()
	a := &model.Application{ID: "a", Name: "Demo", Slug: "demo", PublicHostname: "demo.apps.example.test", Route: "hub", BackendURL: "http://127.0.0.1:9999", AllowedCIDRs: []string{"127.0.0.0/8"}, Enabled: true}
	if e := s.CreateApplication(a, now); e != nil {
		t.Fatal(e)
	}
	if e := s.EnsureApplicationAnchor(model.ApplicationAnchor{ID: "parent", UserID: "u", CompletedMFAAt: now}); e != nil {
		t.Fatal(e)
	}
	if e := s.CreateApplicationTicket(model.ApplicationLaunchTicket{Digest: "ticket", ApplicationID: "a", UserID: "u", AnchorID: "parent", Hostname: a.PublicHostname, Path: "/", ConfigVersion: 1, ExpiresAt: now.Add(time.Minute)}); e != nil {
		t.Fatal(e)
	}
	a.Enabled = false
	if e := s.UpdateApplication(a, 1, now); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ConsumeApplicationTicket("ticket", a.PublicHostname, model.ApplicationSession{ID: "s", CredentialDigest: "c", ExpiresAt: now.Add(time.Hour)}, now); e == nil {
		t.Fatal("disabled app accepted")
	}
}
func TestApplicationUserCascadeDoesNotBreakMembershipTriggers(t *testing.T) {
	s := appStore(t)
	g := &model.ApplicationGroup{ID: "g", Name: "Group", UserIDs: []string{"u"}}
	if e := s.PutApplicationGroup(g, 0); e != nil {
		t.Fatal(e)
	}
	if e := s.DeleteUser("u"); e != nil {
		t.Fatal("user cascade blocked", e)
	}
}
func TestApplicationConcurrentTicketConsumptionHasOneWinner(t *testing.T) {
	s := appStore(t)
	now := time.Now().UTC()
	a := &model.Application{ID: "a", Name: "Demo", Slug: "demo", PublicHostname: "demo.apps.example.test", Route: "hub", BackendURL: "http://127.0.0.1:9999", AllowedCIDRs: []string{"127.0.0.0/8"}, Enabled: true}
	if e := s.CreateApplication(a, now); e != nil {
		t.Fatal(e)
	}
	if e := s.EnsureApplicationAnchor(model.ApplicationAnchor{ID: "anchor", UserID: "u", CompletedMFAAt: now}); e != nil {
		t.Fatal(e)
	}
	rev, _ := s.ApplicationAccessRevision("u")
	if e := s.CreateApplicationTicket(model.ApplicationLaunchTicket{Digest: "ticket", ApplicationID: "a", UserID: "u", AnchorID: "anchor", Hostname: a.PublicHostname, Path: "/", ConfigVersion: 1, AccessRevision: rev, ExpiresAt: now.Add(time.Minute)}); e != nil {
		t.Fatal(e)
	}
	results := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			_, e := s.ConsumeApplicationTicket("ticket", a.PublicHostname, model.ApplicationSession{ID: fmt.Sprint(i), CredentialDigest: fmt.Sprint(i), ExpiresAt: now.Add(time.Hour)}, now)
			results <- e == nil
		}(i)
	}
	wins := 0
	for i := 0; i < 8; i++ {
		if <-results {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("ticket winners=%d", wins)
	}
}
func TestApplicationStoreLifecycleAndBoundedQueries(t *testing.T) {
	s := appStore(t)
	now := time.Now().UTC()
	a := &model.Application{ID: "a", Name: "Demo", Slug: "demo", PublicHostname: "demo.apps.example.test", Route: "hub", BackendURL: "http://127.0.0.1:9999", AllowedCIDRs: []string{"127.0.0.0/8"}, Enabled: true}
	if e := s.CreateApplication(a, now); e != nil {
		t.Fatal(e)
	}
	if _, e := s.GetApplicationByHost(a.PublicHostname); e != nil {
		t.Fatal(e)
	}
	if rows, total, e := s.ListApplications(1, 0); e != nil || total != 1 || len(rows) != 1 {
		t.Fatal("app pagination", e)
	}
	if e := s.ReplaceApplicationGrants(a.ID, []model.ApplicationGrant{{Kind: "user", SubjectID: "u"}}, 1, now); e != nil {
		t.Fatal(e)
	}
	a, _ = s.GetApplication(a.ID)
	grants, e := s.ApplicationGrants(a.ID)
	if e != nil || len(grants) != 1 {
		t.Fatal(e)
	}
	if rows, total, e := s.ListAuthorizedApplications(grants, 1, 0); e != nil || total != 1 || len(rows) != 1 {
		t.Fatal("authorized list", e)
	}
	if rows, total, e := s.ListAuthorizedApplications([]model.ApplicationGrant{{Kind: "user", SubjectID: "other"}}, 1, 0); e != nil || total != 0 || len(rows) != 0 {
		t.Fatal("ungranted metadata", e)
	}
	g := &model.ApplicationGroup{ID: "g", Name: "Operators", UserIDs: []string{"u"}}
	if e = s.PutApplicationGroup(g, 0); e != nil {
		t.Fatal(e)
	}
	if _, total, e := s.ListApplicationGroups(1, 0); e != nil || total != 1 {
		t.Fatal(e)
	}
	if got, e := s.GetApplicationGroup("g"); e != nil || len(got.UserIDs) != 1 {
		t.Fatal(e)
	}
	g.Name = "Changed"
	if e = s.PutApplicationGroup(g, 1); e != nil {
		t.Fatal(e)
	}
	if e = s.PutApplicationGroup(g, 1); e == nil {
		t.Fatal("group stale version accepted")
	}
	if m, e := s.ApplicationLocalMemberships("u"); e != nil || !m["g"] {
		t.Fatal(e)
	}
	if users, total, e := s.ApplicationUserSubjects("alice", 1, 0); e != nil || len(users) != 1 || total != 1 {
		t.Fatal(e)
	}
	revision, _ := s.ApplicationAccessRevision("u")
	if e = s.EnsureApplicationAnchor(model.ApplicationAnchor{ID: "parent", UserID: "u", CompletedMFAAt: now}); e != nil {
		t.Fatal(e)
	}
	ticket := model.ApplicationLaunchTicket{Digest: "ticket", ApplicationID: "a", UserID: "u", AnchorID: "parent", Hostname: a.PublicHostname, Path: "/", ConfigVersion: a.ConfigVersion, AccessRevision: revision, ExpiresAt: now.Add(time.Minute)}
	if e = s.CreateApplicationTicket(ticket); e != nil {
		t.Fatal(e)
	}
	if _, e = s.GetApplicationTicket("ticket", a.PublicHostname, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ConsumeApplicationTicket("ticket", a.PublicHostname, model.ApplicationSession{ID: "s", CredentialDigest: "credential", ExpiresAt: now.Add(time.Hour)}, now); e != nil {
		t.Fatal(e)
	}
	if e = s.TouchApplicationSession("s", now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if rows, e := s.ListApplicationSessions("u", 1, 0); e != nil || len(rows) != 1 || rows[0].ApplicationName != "Demo" {
		t.Fatal("session join", e)
	}
	if _, e = s.ApplicationSessionByID("s"); e != nil {
		t.Fatal(e)
	}
	if e = s.EndApplicationSession("s", "revoked", now); e != nil {
		t.Fatal(e)
	}
	if e = s.RevokeUserApplications("u", "", "revoked", now); e != nil {
		t.Fatal(e)
	}
	if e = s.MarkApplicationEndAudited("s"); e != nil {
		t.Fatal(e)
	}
	if e = s.PruneApplicationRecords(now.Add(48*time.Hour), 24*time.Hour); e != nil {
		t.Fatal(e)
	}
	if _, e = s.GetApplicationAnchor("parent"); e == nil {
		t.Fatal("unreferenced old anchor retained")
	}
	if e = s.CompareApplicationPolicy(1, `{"idle_seconds":2700,"max_seconds":43200,"version":2}`); e != nil {
		t.Fatal(e)
	}
	if e = s.CompareApplicationPolicy(1, `{"version":3}`); e == nil {
		t.Fatal("stale policy accepted")
	}
	if e = s.CompareApplicationPolicy(2, `{"idle_seconds":2700,"max_seconds":43200,"version":3}`); e != nil {
		t.Fatal(e)
	}
	if e = s.DeleteApplicationGroup("g"); e != nil {
		t.Fatal(e)
	}
	if e = s.DeleteApplication("a"); e != nil {
		t.Fatal(e)
	}
}
func TestApplicationStoreFailsClosedDuringPersistenceOutage(t *testing.T) {
	s := appStore(t)
	_ = s.Close()
	now := time.Now()
	a := &model.Application{ID: "a"}
	checks := []func() error{func() error { return s.CreateApplication(a, now) }, func() error { _, e := s.GetApplication("a"); return e }, func() error { _, e := s.GetApplicationByHost("a"); return e }, func() error { _, _, e := s.ListApplications(1, 0); return e }, func() error { return s.UpdateApplication(a, 1, now) }, func() error { return s.DeleteApplication("a") }, func() error { _, e := s.ApplicationGrants("a"); return e }, func() error { return s.ReplaceApplicationGrants("a", nil, 1, now) }, func() error { _, e := s.ApplicationAccessRevision("u"); return e }, func() error { _, e := s.ApplicationLocalMemberships("u"); return e }, func() error { return s.EnsureApplicationAnchor(model.ApplicationAnchor{ID: "a"}) }, func() error { return s.CreateApplicationTicket(model.ApplicationLaunchTicket{}) }, func() error { _, e := s.ConsumeApplicationTicket("t", "h", model.ApplicationSession{}, now); return e }, func() error { _, e := s.GetApplicationSession("c"); return e }, func() error { return s.TouchApplicationSession("s", now) }, func() error { return s.EndApplicationSession("s", "revoke", now) }, func() error { return s.RevokeApplicationFamily("u", "a", "r", now) }, func() error { return s.RevokeUserApplications("u", "", "r", now) }, func() error { _, e := s.ListApplicationSessions("u", 1, 0); return e }, func() error { _, _, e := s.ListApplicationGroups(1, 0); return e }, func() error { _, e := s.GetApplicationGroup("g"); return e }, func() error { return s.PutApplicationGroup(&model.ApplicationGroup{}, 0) }, func() error { return s.DeleteApplicationGroup("g") }, func() error { return s.CompareApplicationPolicy(1, `{"version":2}`) }, func() error { _, _, e := s.ListAuthorizedApplications(nil, 1, 0); return e }, func() error { _, _, e := s.ApplicationUserSubjects("", 1, 0); return e }, func() error { return s.PruneApplicationRecords(now, time.Hour) }}
	for i, check := range checks {
		if e := check(); e == nil {
			t.Errorf("operation%d allowed during outage", i)
		}
	}
}
