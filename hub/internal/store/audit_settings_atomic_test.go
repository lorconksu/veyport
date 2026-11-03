package store_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

type auditSettingsChange struct {
	Before model.AuditSettings `json:"before"`
	After  model.AuditSettings `json:"after"`
}

func settingsAuditCount(t *testing.T, s *store.Store) int {
	t.Helper()
	var count int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action=?", model.AuditAuditRetentionUpdated).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestAuditSettingsSystemUpdateRequiresAudit(t *testing.T) {
	s := testStore(t)
	before := s.GetAuditSettings()
	after := before
	after.RetentionDays++
	if _, err := s.DB().Exec(`CREATE TRIGGER reject_settings_audit BEFORE INSERT ON audit_logs WHEN NEW.action='audit.retention_updated' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAuditSettings(after); err == nil {
		t.Fatal("settings update succeeded without its audit record")
	}
	if got := s.GetAuditSettings(); got != before {
		t.Fatalf("audit failure changed settings: got %+v want %+v", got, before)
	}
	if got := settingsAuditCount(t, s); got != 0 {
		t.Fatalf("rolled back write left %d success audits", got)
	}
	health, err := s.GetAuditHealth()
	if err != nil || !health.Degraded || health.FailureCount != 1 {
		t.Fatalf("audit persistence failure not reported: %+v %v", health, err)
	}
	if _, err := s.DB().Exec("DROP TRIGGER reject_settings_audit"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAuditSettings(after); err != nil {
		t.Fatal(err)
	}
	health, err = s.GetAuditHealth()
	if err != nil || health.Degraded || health.LastRecoveredAt == nil {
		t.Fatalf("committed audit did not recover health: %+v %v", health, err)
	}
}

func TestAuditSettingsConfigurationFailureNeverAuditsSuccess(t *testing.T) {
	for _, failure := range []string{"write", "read", "parse", "validation"} {
		t.Run(failure, func(t *testing.T) {
			s := testStore(t)
			before := s.GetAuditSettings()
			after := before
			after.RetentionDays++
			switch failure {
			case "write":
				if _, err := s.DB().Exec(`CREATE TRIGGER reject_settings_write BEFORE INSERT ON _config WHEN NEW.key='audit.review_reminder_days' BEGIN SELECT RAISE(ABORT,'synthetic config failure'); END`); err != nil {
					t.Fatal(err)
				}
			case "parse":
				if err := s.SetConfig("audit.retention_days", "corrupt"); err != nil {
					t.Fatal(err)
				}
			case "read":
				if _, err := s.DB().Exec("ALTER TABLE _config RENAME TO settings_config_saved"); err != nil {
					t.Fatal(err)
				}
			case "validation":
				after.RetentionDays = 0
			}
			if err := s.UpdateAuditSettings(after); err == nil {
				t.Fatal("failed configuration update was accepted")
			}
			if failure == "read" {
				if _, err := s.DB().Exec("ALTER TABLE settings_config_saved RENAME TO _config"); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "parse" {
				if raw, err := s.GetConfig("audit.retention_days"); err != nil || raw != "corrupt" {
					t.Fatalf("failed before snapshot overwrote corrupt value: %q %v", raw, err)
				}
			}
			if got := s.GetAuditSettings(); got != before {
				t.Fatalf("failed update changed effective settings: %+v", got)
			}
			if got := settingsAuditCount(t, s); got != 0 {
				t.Fatalf("failed update left %d success audits", got)
			}
			health, err := s.GetAuditHealth()
			if err != nil || health.Degraded || health.FailureCount != 0 {
				t.Fatalf("configuration rejection claimed audit failure: %+v %v", health, err)
			}
		})
	}
}

func TestAuditSettingsCommitFailureRollsBackAndDegradesHealth(t *testing.T) {
	s := testStore(t)
	before := s.GetAuditSettings()
	after := before
	after.RetentionDays++
	if _, err := s.DB().Exec(`CREATE TRIGGER fail_settings_commit AFTER INSERT ON audit_logs WHEN NEW.action='audit.retention_updated' BEGIN UPDATE audit_logs SET user_id='missing-user' WHERE id=NEW.id; END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec("PRAGMA defer_foreign_keys=ON"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAuditSettings(after); err == nil {
		t.Fatal("settings mutation accepted an uncommittable audit record")
	}
	if s.GetAuditSettings() != before || settingsAuditCount(t, s) != 0 {
		t.Fatal("failed commit left settings or an audit record")
	}
	health, err := s.GetAuditHealth()
	if err != nil || !health.Degraded || health.FailureCount != 1 {
		t.Fatalf("audit commit failure not reported: %+v %v", health, err)
	}
}

func TestAuditSettingsConcurrentChangesHaveContinuousBeforeAfterHistory(t *testing.T) {
	s := testStore(t)
	initial := s.GetAuditSettings()
	const writers = 12
	results := make(chan error, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			settings := initial
			settings.RetentionDays = 100 + i
			results <- s.UpdateAuditSettings(settings)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.DB().Query("SELECT detail,actor_type FROM audit_logs WHERE action=? ORDER BY rowid", model.AuditAuditRetentionUpdated)
	if err != nil {
		t.Fatal(err)
	}
	previous, count := initial, 0
	for rows.Next() {
		var detail, actor string
		if err := rows.Scan(&detail, &actor); err != nil {
			t.Fatal(err)
		}
		var change auditSettingsChange
		if err := json.Unmarshal([]byte(detail), &change); err != nil {
			t.Fatal(err)
		}
		if change.Before != previous || actor != model.AuditActorTypeSystem {
			t.Fatalf("discontinuous or unattributed settings history at %d: %+v actor=%s", count, change, actor)
		}
		previous = change.After
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if count != writers || s.GetAuditSettings() != previous {
		t.Fatalf("committed settings and audit history differ: records=%d", count)
	}
}

func TestAuditSettingsAuditedBindsActorAndRequestMetadata(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	actor := liveManagementActor(t, s, "actor")
	before := s.GetAuditSettings()
	after := before
	after.RetentionDays++
	spoof, correlation, ip := "untrusted-user", "request-123", "192.0.2.10"
	entry := model.AuditEntry{UserID: &spoof, ActorType: model.AuditActorTypeSystem, CorrelationID: &correlation, IPAddress: &ip}
	if err := s.UpdateAuditSettingsAudited(after, time.Now().UTC(), entry, actor); err != nil {
		t.Fatal(err)
	}
	action := model.AuditAuditRetentionUpdated
	entries, total, err := s.ListAuditLogs(model.AuditFilter{Action: &action})
	if err != nil || total != 1 {
		t.Fatalf("settings audit count=%d err=%v", total, err)
	}
	got := entries[0]
	if got.UserID == nil || *got.UserID != actor.UserID || got.ActorType != model.AuditActorTypeUser || got.CorrelationID == nil || *got.CorrelationID != correlation || got.IPAddress == nil || *got.IPAddress != ip || got.Outcome != model.AuditOutcomeSuccess {
		t.Fatalf("settings audit lost actor or request attribution: %+v", got)
	}
	var change auditSettingsChange
	if got.Detail == nil || json.Unmarshal([]byte(*got.Detail), &change) != nil || change.Before != before || change.After != after {
		t.Fatalf("settings audit lost before/after values: %+v", got)
	}
}

func TestAuditSettingsAuditedRejectsChangedAuthorityWithoutRecoveringHealth(t *testing.T) {
	for _, mutation := range []string{"token_generation=token_generation+1", "disabled_at=datetime('now')"} {
		t.Run(mutation, func(t *testing.T) {
			s := testStore(t)
			newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
			actor := liveManagementActor(t, s, "actor")
			before := s.GetAuditSettings()
			after := before
			after.RetentionDays++
			// Preserve an existing degraded state through a rejected mutation.
			if err := s.LogAudit(model.AuditEntry{UserID: stringPointer("missing-user"), Action: "test.invalid_actor"}); err == nil {
				t.Fatal("expected missing audit actor FK failure")
			}
			if _, err := s.DB().Exec(fmt.Sprintf("UPDATE users SET %s WHERE id='actor'", mutation)); err != nil {
				t.Fatal(err)
			}
			err := s.UpdateAuditSettingsAudited(after, time.Now().UTC(), model.AuditEntry{}, actor)
			if !errors.Is(err, store.ErrAccountManagementActor) || s.GetAuditSettings() != before || settingsAuditCount(t, s) != 0 {
				t.Fatalf("changed actor updated settings or audit: %v", err)
			}
			health, err := s.GetAuditHealth()
			if err != nil || !health.Degraded || health.FailureCount != 1 || health.LastRecoveredAt != nil {
				t.Fatalf("rejected mutation changed health: %+v %v", health, err)
			}
		})
	}
}

func TestAuditSettingsRetainsAPITokenAuthorityWithoutWeakeningManagementMFA(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	actor := liveManagementActor(t, s, "actor")
	newLifecycleToken(t, s, "admin-api", actor.UserID, "admin-api-hash")
	actor.SessionID, actor.APITokenHash = "", "admin-api-hash"
	if _, err := s.DB().Exec("UPDATE users SET totp_enabled=0 WHERE id=?", actor.UserID); err != nil {
		t.Fatal(err)
	}
	// API authentication snapshots the user's current generation and revision.
	live := mustGetUser(t, s, actor.UserID)
	actor.Generation, actor.SecurityRevision = live.TokenGeneration, live.SecurityRevision
	settings := s.GetAuditSettings()
	settings.RetentionDays++
	if err := s.UpdateAuditSettingsAudited(settings, time.Now().UTC(), model.AuditEntry{}, actor); err != nil {
		t.Fatalf("settings added an MFA restriction to valid admin API authority: %v", err)
	}
	_, _, err := s.UpdateUserRoleAudited("target", model.RoleAdmin, time.Now().UTC(), model.AuditEntry{}, model.AuditEntry{}, actor)
	if !errors.Is(err, store.ErrAccountManagementActor) {
		t.Fatalf("account management lost its MFA requirement: %v", err)
	}
}

func TestAuditSettingsRechecksActorBeforeCommit(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	actor := liveManagementActor(t, s, "actor")
	before := s.GetAuditSettings()
	after := before
	after.RetentionDays++
	if _, err := s.DB().Exec(`CREATE TRIGGER revoke_settings_actor AFTER INSERT ON _config WHEN NEW.key='audit.retention_days' BEGIN UPDATE users SET token_generation=token_generation+1 WHERE id='actor'; END`); err != nil {
		t.Fatal(err)
	}
	err := s.UpdateAuditSettingsAudited(after, time.Now().UTC(), model.AuditEntry{}, actor)
	if !errors.Is(err, store.ErrAccountManagementActor) || s.GetAuditSettings() != before || settingsAuditCount(t, s) != 0 {
		t.Fatalf("authority revoked during mutation committed settings or audit: %v", err)
	}
	health, err := s.GetAuditHealth()
	if err != nil || health.Degraded || health.FailureCount != 0 {
		t.Fatalf("post-append authority rejection claimed audit failure: %+v %v", health, err)
	}
}

func stringPointer(s string) *string { return &s }
