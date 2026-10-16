package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

func directorySessionFixture(t *testing.T, kind string) (*Server, *model.Application, *model.ApplicationSession) {
	t.Helper()
	s, app, credential := applicationFixture(t, "http://127.0.0.1:9999")
	previous, err := s.store.GetApplicationSession(refreshDigest(credential))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.store.DB().Exec(`UPDATE users SET auth_provider='ldap',ldap_username='synthetic' WHERE id=?`, previous.UserID); err != nil {
		t.Fatal(err)
	}
	subject := previous.UserID
	if kind == "directory_group" {
		subject = "ldap:synthetic-group"
	} else if kind == "role" {
		subject = string(model.RoleAuditor)
	}
	if err = s.store.ReplaceApplicationGrants(app.ID, []model.ApplicationGrant{{Kind: kind, SubjectID: subject}}, app.ConfigVersion, s.now()); err != nil {
		t.Fatal(err)
	}
	app, err = s.store.GetApplication(app.ID)
	if err != nil {
		t.Fatal(err)
	}
	s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
		return ApplicationMembership{Groups: []string{"ldap:synthetic-group"}, Role: model.RoleAuditor}, nil
	})
	user, err := s.store.GetUserByID(previous.UserID)
	if err != nil {
		t.Fatal(err)
	}
	revision, fingerprint, err := s.applicationAuthorization(context.Background(), user, app)
	if err != nil {
		t.Fatal(err)
	}
	digest := uuid.NewString()
	ticket := model.ApplicationLaunchTicket{Digest: digest, ApplicationID: app.ID, UserID: user.ID, AnchorID: previous.AnchorID, Hostname: app.PublicHostname, Path: "/", ConfigVersion: app.ConfigVersion, AccessRevision: revision, DirectoryFingerprint: fingerprint, ExpiresAt: s.now().Add(time.Minute)}
	if err = s.store.CreateApplicationTicket(ticket); err != nil {
		t.Fatal(err)
	}
	session := model.ApplicationSession{ID: uuid.NewString(), CredentialDigest: uuid.NewString(), ExpiresAt: previous.ExpiresAt}
	if _, err = s.store.ConsumeApplicationTicket(digest, app.PublicHostname, session, s.now()); err != nil {
		t.Fatal(err)
	}
	stored, err := s.store.ApplicationSessionByID(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s, app, stored
}

func TestApplicationObservedDirectoryLossPermanentlyEndsSession(t *testing.T) {
	for _, scenario := range []struct{ name, kind string }{
		{"last_group_grant_removed", "directory_group"},
		{"mapped_role_removed", "role"},
		{"account_disabled_with_direct_grant", "user"},
		{"directory_outage_with_direct_grant", "user"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s, app, session := directorySessionFixture(t, scenario.kind)
			now := s.now()
			if err := s.checkApplicationSession(context.Background(), app, session, false); err != nil {
				t.Fatal("initial authority refused", err)
			}
			s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
				if scenario.kind == "user" {
					return ApplicationMembership{}, errors.New("synthetic directory identity unavailable")
				}
				return ApplicationMembership{Role: model.RoleViewer}, nil
			})
			s.SetClock(func() time.Time { return now.Add(3 * time.Second) })
			stream, cancel := context.WithCancel(context.Background())
			defer cancel()
			unrelated, cancelUnrelated := context.WithCancel(context.Background())
			defer cancelUnrelated()
			s.applicationStreams.register(uuid.NewString(), session.ID, app.ID, cancel)
			s.applicationStreams.register(uuid.NewString(), "unrelated-session", app.ID, cancelUnrelated)
			if err := s.checkApplicationSession(context.Background(), app, session, false); err == nil {
				t.Fatal("observed directory authority loss allowed access")
			}
			ended, err := s.store.ApplicationSessionByID(session.ID)
			if err != nil || ended.EndedAt == nil || ended.EndReason != "access_changed" {
				t.Fatal("directory authority loss did not durably revoke the session", err)
			}
			if stream.Err() == nil || unrelated.Err() != nil {
				t.Fatal("revocation must close only the affected session streams")
			}
			audited, err := s.store.ApplicationAuditExists("application-session-end:" + session.ID)
			if err != nil || !audited {
				t.Fatal("directory end audit missing", err)
			}
			s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
				return ApplicationMembership{Groups: []string{"ldap:synthetic-group"}, Role: model.RoleAuditor}, nil
			})
			s.SetClock(func() time.Time { return now.Add(6 * time.Second) })
			if err = s.checkApplicationSession(context.Background(), app, ended, true); err == nil {
				t.Fatal("restoring directory authority resurrected the gate cookie")
			}
		})
	}
}

func TestApplicationCallerCancellationDoesNotRevokeDirectorySession(t *testing.T) {
	s, app, session := directorySessionFixture(t, "user")
	now := s.now()
	s.SetClock(func() time.Time { return now.Add(3 * time.Second) })
	s.applicationMembershipReader = applicationMemberReaderFunc(func(ctx context.Context, _ *model.User) (ApplicationMembership, error) {
		return ApplicationMembership{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.checkApplicationSession(ctx, app, session, false); err == nil {
		t.Fatal("aborted directory lookup allowed request")
	}
	current, err := s.store.ApplicationSessionByID(session.ID)
	if err != nil || current.EndedAt != nil {
		t.Fatal("caller cancellation revoked valid authority", err)
	}
}

func TestApplicationDirectoryRevocationAuditFailureRemainsEndedAndRetries(t *testing.T) {
	s, app, session := directorySessionFixture(t, "user")
	now := s.now()
	s.SetClock(func() time.Time { return now.Add(3 * time.Second) })
	s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
		return ApplicationMembership{}, errApplicationDenied
	})
	_, err := s.store.DB().Exec(`CREATE TRIGGER fail_app_end_audit BEFORE INSERT ON audit_logs WHEN NEW.action='application.session_ended' BEGIN SELECT RAISE(ABORT,'synthetic audit unavailable'); END`)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.checkApplicationSession(context.Background(), app, session, false); err == nil {
		t.Fatal("audit failure authorized request")
	}
	current, err := s.store.ApplicationSessionByID(session.ID)
	if err != nil || current.EndedAt == nil {
		t.Fatal("audit failure undid durable revocation", err)
	}
	s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
		return ApplicationMembership{Groups: []string{"ldap:synthetic-group"}, Role: model.RoleAuditor}, nil
	})
	s.SetClock(func() time.Time { return now.Add(6 * time.Second) })
	if err = s.checkApplicationSession(context.Background(), app, current, true); err == nil {
		t.Fatal("membership restoration resurrected unaudited ended session")
	}
	if _, err = s.store.DB().Exec(`DROP TRIGGER fail_app_end_audit`); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err = s.auditApplicationSessionEnds(); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = s.store.DB().QueryRow(`SELECT count(*) FROM audit_logs WHERE id=?`, "application-session-end:"+session.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("retry did not create exactly one durable end audit", count, err)
	}
}

func TestApplicationDirectoryRevocationPropagatesPersistenceFailure(t *testing.T) {
	s, app, session := directorySessionFixture(t, "user")
	now := s.now()
	s.SetClock(func() time.Time { return now.Add(3 * time.Second) })
	s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
		return ApplicationMembership{}, errApplicationDenied
	})
	_, err := s.store.DB().Exec(`CREATE TRIGGER fail_app_end BEFORE UPDATE OF ended_at ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic end unavailable'); END`)
	if err != nil {
		t.Fatal(err)
	}
	stream, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.applicationStreams.register(uuid.NewString(), session.ID, app.ID, cancel)
	err = s.checkApplicationSession(context.Background(), app, session, false)
	if err == nil || !strings.Contains(err.Error(), "synthetic end unavailable") || stream.Err() == nil {
		t.Fatal("persistence failure was hidden or allowed stream access", err)
	}
	if _, err = s.store.DB().Exec(`DROP TRIGGER fail_app_end`); err != nil {
		t.Fatal(err)
	}
	if err = s.checkApplicationSession(context.Background(), app, session, false); err == nil {
		t.Fatal("authority loss allowed access after persistence recovered")
	}
	current, err := s.store.ApplicationSessionByID(session.ID)
	if err != nil || current.EndedAt == nil {
		t.Fatal("revocation retry did not persist", err)
	}
}

func TestApplicationDirectoryRestorationBeforeRevocationRetryNeverResumesCookie(t *testing.T) {
	s, app, session := directorySessionFixture(t, "user")
	now := s.now()
	s.SetClock(func() time.Time { return now.Add(3 * time.Second) })
	s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
		return ApplicationMembership{}, errApplicationDenied
	})
	if _, err := s.store.DB().Exec(`CREATE TRIGGER fail_app_restore_end BEFORE UPDATE OF ended_at ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic end unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.checkApplicationSession(context.Background(), app, session, false); err == nil {
		t.Fatal("observed loss with failed persistence authorized access")
	}
	if _, err := s.store.DB().Exec(`DROP TRIGGER fail_app_restore_end`); err != nil {
		t.Fatal(err)
	}
	s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
		return ApplicationMembership{Groups: []string{"ldap:synthetic-group"}, Role: model.RoleAuditor}, nil
	})
	s.SetClock(func() time.Time { return now.Add(6 * time.Second) })
	if err := s.checkApplicationSession(context.Background(), app, session, true); err == nil {
		t.Fatal("old cookie resumed when directory restored before persistence retry")
	}
	current, err := s.store.ApplicationSessionByID(session.ID)
	if err != nil || current.EndedAt == nil || current.EndReason != "access_changed" {
		t.Fatal("pending revocation was not durably retried", err)
	}
	if err := s.checkApplicationSession(context.Background(), app, session, true); err == nil {
		t.Fatal("stale snapshot bypassed durable end after pending marker cleanup")
	}
}
