package store

import (
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

func startupApplicationStore(t *testing.T) (*Store, time.Time) {
	t.Helper()
	s := appStore(t)
	now := time.Now().UTC()
	for _, session := range []*model.Session{
		{ID: "dashboard", UserID: "u", Kind: model.SessionKindWeb, CreatedAt: now, LastSeenAt: now},
		{ID: "cli", UserID: "u", Kind: model.SessionKindCLI, CreatedAt: now, LastSeenAt: now},
	} {
		if err := s.CreateSession(session); err != nil {
			t.Fatal(err)
		}
	}
	app := &model.Application{ID: "app", Slug: "app", Name: "App", PublicHostname: "app.apps.example.test", Route: "hub", BackendURL: "http://127.0.0.1:9999", Enabled: true}
	if err := s.CreateApplication(app, now); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureApplicationAnchor(model.ApplicationAnchor{ID: "dashboard", UserID: "u", CompletedMFAAt: now}); err != nil {
		t.Fatal(err)
	}
	revision, err := s.ApplicationAccessRevision("u")
	if err != nil {
		t.Fatal(err)
	}
	ticket := model.ApplicationLaunchTicket{Digest: "consumed", ApplicationID: app.ID, UserID: "u", AnchorID: "dashboard", Hostname: app.PublicHostname, Path: "/", ConfigVersion: 1, AccessRevision: revision, ExpiresAt: now.Add(time.Minute)}
	if err := s.CreateApplicationTicket(ticket); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeApplicationTicket(ticket.Digest, app.PublicHostname, model.ApplicationSession{ID: "app-session", CredentialDigest: "cookie", ExpiresAt: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	ticket.Digest = "pending"
	if err := s.CreateApplicationTicket(ticket); err != nil {
		t.Fatal(err)
	}
	return s, now
}

func TestApplicationStartupBulkEndIsAtomicAndPreservesSourceAuthority(t *testing.T) {
	for _, failure := range []struct{ name, trigger string }{
		{"session_end", `CREATE TRIGGER fail_startup BEFORE UPDATE OF ended_at ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic end unavailable'); END`},
		{"ticket_removal", `CREATE TRIGGER fail_startup BEFORE DELETE ON application_launch_tickets BEGIN SELECT RAISE(ABORT,'synthetic ticket cleanup unavailable'); END`},
	} {
		t.Run(failure.name, func(t *testing.T) {
			s, now := startupApplicationStore(t)
			if _, err := s.DB().Exec(failure.trigger); err != nil {
				t.Fatal(err)
			}
			if err := s.EndAllApplicationSessions("hub_restart", now); err == nil {
				t.Fatal("failed bulk cleanup appeared successful")
			}
			current, err := s.ApplicationSessionByID("app-session")
			if err != nil || current.EndedAt != nil {
				t.Fatal("failed transaction left a partial session end", err)
			}
			var count int
			if err := s.DB().QueryRow(`SELECT count(*) FROM application_launch_tickets WHERE digest='pending'`).Scan(&count); err != nil || count != 1 {
				t.Fatal("failed transaction removed pending ticket", count, err)
			}
			if _, err := s.DB().Exec(`DROP TRIGGER fail_startup`); err != nil {
				t.Fatal(err)
			}
			if err := s.EndAllApplicationSessions("hub_restart", now); err != nil {
				t.Fatal(err)
			}
			current, err = s.ApplicationSessionByID("app-session")
			if err != nil || current.EndedAt == nil || current.EndReason != "hub_restart" {
				t.Fatal("recovered transaction did not end app session", err)
			}
			if err := s.DB().QueryRow(`SELECT count(*) FROM application_launch_tickets`).Scan(&count); err != nil || count != 0 {
				t.Fatal("recovered transaction retained old launch tickets", count, err)
			}
			for _, id := range []string{"dashboard", "cli"} {
				parent, err := s.GetSession(id)
				if err != nil || parent.EndedAt != nil {
					t.Fatal("bulk app cleanup changed portal/CLI authority", id, err)
				}
			}
			anchor, err := s.GetApplicationAnchor("dashboard")
			if err != nil || anchor.RevokedAt != nil || anchor.CompletedMFAAt.UnixMilli() != now.UnixMilli() {
				t.Fatal("bulk app cleanup changed original MFA anchor", err)
			}
		})
	}
}

func TestApplicationStartupBulkEndRejectsClosedStorage(t *testing.T) {
	s := appStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.EndAllApplicationSessions("hub_restart", time.Now()); err == nil {
		t.Fatal("closed storage admitted startup cleanup")
	}
}
