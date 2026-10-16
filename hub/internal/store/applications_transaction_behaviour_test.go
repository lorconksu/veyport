package store

import (
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestApplicationGrantReplacementRollsBackEveryFailedWrite(t *testing.T) {
	for _, stage := range []struct{ name, trigger string }{
		{"configuration", `CREATE TRIGGER fail_grants BEFORE UPDATE OF config_version ON applications BEGIN SELECT RAISE(ABORT,'synthetic configuration unavailable'); END`},
		{"old_grants", `CREATE TRIGGER fail_grants BEFORE DELETE ON application_grants BEGIN SELECT RAISE(ABORT,'synthetic grant delete unavailable'); END`},
		{"new_grants", `CREATE TRIGGER fail_grants BEFORE INSERT ON application_grants BEGIN SELECT RAISE(ABORT,'synthetic grant insert unavailable'); END`},
		{"session_end", `CREATE TRIGGER fail_grants BEFORE UPDATE OF ended_at ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic session end unavailable'); END`},
	} {
		t.Run(stage.name, func(t *testing.T) {
			s, now := startupApplicationStore(t)
			if _, err := s.DB().Exec(`INSERT INTO application_grants(application_id,kind,subject_id)VALUES('app','role','viewer')`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec(stage.trigger); err != nil {
				t.Fatal(err)
			}
			if err := s.ReplaceApplicationGrants("app", []model.ApplicationGrant{{Kind: "user", SubjectID: "u"}}, 1, now); err == nil {
				t.Fatal("failed grant replacement reported success")
			}
			app, err := s.GetApplication("app")
			if err != nil || app.ConfigVersion != 1 {
				t.Fatal("failed grant transaction changed configuration", err)
			}
			grants, err := s.ApplicationGrants("app")
			if err != nil || len(grants) != 1 || grants[0].Kind != "role" {
				t.Fatal("failed grant transaction changed authority", grants, err)
			}
			session, err := s.ApplicationSessionByID("app-session")
			if err != nil || session.EndedAt != nil {
				t.Fatal("failed grant transaction partially ended session", err)
			}
		})
	}
}

func TestApplicationGroupReplacementRollsBackMembershipAndAccessRevision(t *testing.T) {
	for _, stage := range []struct{ name, trigger string }{
		{"group_update", `CREATE TRIGGER fail_group BEFORE UPDATE ON application_groups BEGIN SELECT RAISE(ABORT,'synthetic group update unavailable'); END`},
		{"membership_delete", `CREATE TRIGGER fail_group BEFORE DELETE ON application_group_members BEGIN SELECT RAISE(ABORT,'synthetic membership delete unavailable'); END`},
		{"membership_insert", `CREATE TRIGGER fail_group BEFORE INSERT ON application_group_members BEGIN SELECT RAISE(ABORT,'synthetic membership insert unavailable'); END`},
	} {
		t.Run(stage.name, func(t *testing.T) {
			s := appStore(t)
			original := &model.ApplicationGroup{ID: "group", Name: "Original", UserIDs: []string{"u"}}
			if err := s.PutApplicationGroup(original, 0); err != nil {
				t.Fatal(err)
			}
			revision, err := s.ApplicationAccessRevision("u")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec(stage.trigger); err != nil {
				t.Fatal(err)
			}
			if err := s.PutApplicationGroup(&model.ApplicationGroup{ID: "group", Name: "Changed", UserIDs: []string{"u"}}, 1); err == nil {
				t.Fatal("failed membership replacement reported success")
			}
			group, err := s.GetApplicationGroup("group")
			if err != nil || group.Name != "Original" || group.Version != 1 || len(group.UserIDs) != 1 || group.UserIDs[0] != "u" {
				t.Fatal("failed group transaction changed members/version", group, err)
			}
			after, err := s.ApplicationAccessRevision("u")
			if err != nil || after != revision {
				t.Fatal("rollback retained a partial access-version trigger", after, revision, err)
			}
		})
	}
}

func TestApplicationFamilyRevocationIsAtomicAcrossAnchorAndSession(t *testing.T) {
	for _, kind := range []string{"one_family", "other_families"} {
		for _, stage := range []struct{ name, trigger string }{
			{"anchor", `CREATE TRIGGER fail_family BEFORE UPDATE OF revoked_at ON application_login_anchors BEGIN SELECT RAISE(ABORT,'synthetic anchor unavailable'); END`},
			{"session", `CREATE TRIGGER fail_family BEFORE UPDATE OF ended_at ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic session unavailable'); END`},
		} {
			t.Run(kind+"/"+stage.name, func(t *testing.T) {
				s, now := startupApplicationStore(t)
				if _, err := s.DB().Exec(stage.trigger); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "one_family" {
					err = s.RevokeApplicationFamily("u", "dashboard", "logout", now)
				} else {
					err = s.RevokeUserApplications("u", "kept-other", "logout", now)
				}
				if err == nil {
					t.Fatal("failed family revocation reported success")
				}
				anchor, err := s.GetApplicationAnchor("dashboard")
				if err != nil || anchor.RevokedAt != nil {
					t.Fatal("partial anchor revoke survived rollback", err)
				}
				session, err := s.ApplicationSessionByID("app-session")
				if err != nil || session.EndedAt != nil {
					t.Fatal("partial session revoke survived rollback", err)
				}
			})
		}
	}
}

func TestApplicationDeletionAdmissionRollsBackTicketsAndConfigurationOnFailure(t *testing.T) {
	for _, stage := range []struct{ name, trigger string }{
		{"configuration", `CREATE TRIGGER fail_deletion BEFORE UPDATE ON applications BEGIN SELECT RAISE(ABORT,'synthetic configuration unavailable'); END`},
		{"tickets", `CREATE TRIGGER fail_deletion BEFORE DELETE ON application_launch_tickets BEGIN SELECT RAISE(ABORT,'synthetic ticket delete unavailable'); END`},
		{"sessions", `CREATE TRIGGER fail_deletion BEFORE UPDATE OF ended_at ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic session end unavailable'); END`},
	} {
		t.Run(stage.name, func(t *testing.T) {
			s, now := startupApplicationStore(t)
			if _, err := s.DB().Exec(stage.trigger); err != nil {
				t.Fatal(err)
			}
			if err := s.BeginApplicationDeletion("app", now); err == nil {
				t.Fatal("failed delete admission reported success")
			}
			app, err := s.GetApplication("app")
			if err != nil || !app.Enabled || app.ConfigVersion != 1 {
				t.Fatal("failed deletion partially changed configuration", err)
			}
			var count int
			if err = s.DB().QueryRow(`SELECT count(*) FROM application_launch_tickets WHERE digest='pending'`).Scan(&count); err != nil || count != 1 {
				t.Fatal("failed deletion partially removed ticket", count, err)
			}
			session, err := s.ApplicationSessionByID("app-session")
			if err != nil || session.EndedAt != nil {
				t.Fatal("failed deletion partially ended session", err)
			}
		})
	}
	if err := appStore(t).BeginApplicationDeletion("missing", time.Now()); err == nil {
		t.Fatal("missing application accepted deletion admission")
	}
}

func TestApplicationRetentionTransactionDoesNotPartiallyDiscardAuditHistory(t *testing.T) {
	for _, stage := range []struct{ name, trigger string }{
		{"tickets", `CREATE TRIGGER fail_retention BEFORE DELETE ON application_launch_tickets BEGIN SELECT RAISE(ABORT,'synthetic ticket delete unavailable'); END`},
		{"sessions", `CREATE TRIGGER fail_retention BEFORE DELETE ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic session delete unavailable'); END`},
		{"anchors", `CREATE TRIGGER fail_retention BEFORE DELETE ON application_login_anchors BEGIN SELECT RAISE(ABORT,'synthetic anchor delete unavailable'); END`},
	} {
		t.Run(stage.name, func(t *testing.T) {
			s, now := startupApplicationStore(t)
			if err := s.EndApplicationSession("app-session", "expired_idle", now); err != nil {
				t.Fatal(err)
			}
			if err := s.MarkApplicationEndAudited("app-session"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec(stage.trigger); err != nil {
				t.Fatal(err)
			}
			if err := s.PruneApplicationRecords(now.Add(31*24*time.Hour), 30*24*time.Hour); err == nil {
				t.Fatal("failed retention transaction reported success")
			}
			if _, err := s.ApplicationSessionByID("app-session"); err != nil {
				t.Fatal("failed retention discarded audited session history", err)
			}
			if _, err := s.GetApplicationAnchor("dashboard"); err != nil {
				t.Fatal("failed retention discarded source history", err)
			}
			var count int
			if err := s.DB().QueryRow(`SELECT count(*) FROM application_launch_tickets WHERE digest='pending'`).Scan(&count); err != nil || count != 1 {
				t.Fatal("failed retention partially pruned ticket", count, err)
			}
		})
	}
}
