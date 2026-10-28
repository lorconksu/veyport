package store_test

import (
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestAuditRetentionComparesInstantsAtExactCutoff(t *testing.T) {
	for _, cutoff := range []string{"2026-10-26T18:00:00Z", "2026-10-26 18:00:00", "2026-10-26T20:00:00+02:00"} {
		t.Run(cutoff, func(t *testing.T) {
			s := testStore(t)
			entries := []struct {
				id, timestamp string
				retained      bool
			}{
				{"older-day", "2026-10-25 22:00:00", false},
				{"older-same-day", "2026-10-26 10:00:00", false},
				{"one-second-before", "2026-10-26 17:59:59", false},
				{"exact-cutoff", "2026-10-26 18:00:00", true},
				{"one-second-after", "2026-10-26 18:00:01", true},
				{"newer-same-day", "2026-10-26 22:00:00", true},
				{"newer-day", "2026-10-27 10:00:00", true},
			}
			for _, e := range entries {
				managementExec(t, s, "INSERT INTO audit_logs(id,action,created_at) VALUES(?,'user.login',?)", e.id, e.timestamp)
			}
			if n, err := s.DeleteAuditLogsBefore(cutoff); err != nil || n != 3 {
				t.Fatalf("deleted=%d: %v", n, err)
			}
			for _, e := range entries {
				var exists bool
				if err := s.DB().QueryRow("SELECT EXISTS(SELECT 1 FROM audit_logs WHERE id=?)", e.id).Scan(&exists); err != nil || exists != e.retained {
					t.Fatalf("%s retained=%t, want %t: %v", e.id, exists, e.retained, err)
				}
			}
		})
	}
}

func TestAuditRetentionPreservesUnexpiredRecoveryProvenance(t *testing.T) {
	f := newManagementMutationFixture(t, "reset")
	settings := f.s.GetAuditSettings()
	settings.RetentionDays, settings.TemporaryPasswordTTLHours = 1, 30*24
	if err := f.s.UpdateAuditSettings(settings); err != nil {
		t.Fatal(err)
	}
	managementExec(t, f.s, "INSERT INTO user_roles(user_id,role) VALUES('target','original-reader')")
	u := mustGetUser(t, f.s, f.user.ID)
	now := time.Now().UTC().Truncate(time.Second)
	resetAt := now.Add(-48 * time.Hour)
	if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration}, "temporary", resetAt); err != nil {
		t.Fatal(err)
	}
	var audit string
	if err := f.s.DB().QueryRow("SELECT audit_id FROM local_break_glass_recoveries WHERE user_id=?", u.ID).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	managementExec(t, f.s, "UPDATE audit_logs SET created_at=? WHERE id=?", resetAt.Format("2006-01-02 15:04:05"), audit)
	cutoff := now.Add(-time.Duration(settings.RetentionDays) * 24 * time.Hour).Format(time.RFC3339)
	if n, err := f.s.DeleteAuditLogsBefore(cutoff); err != nil || n != 0 {
		t.Fatalf("retention removed live provenance: deleted=%d %v", n, err)
	}
	u = mustGetUser(t, f.s, u.ID)
	secret := "staged"
	if err := f.s.UpdateUserTOTP(u.ID, &secret, false, u.TokenGeneration); err != nil {
		t.Fatalf("retention broke protected MFA setup: %v", err)
	}
	u = mustGetUser(t, f.s, u.ID)
	if err := f.s.CompleteTOTPSetup(u, "validated", "permanent", now, 1, f.entry, managementAudit(u.ID, u.ID, model.AuditUserTOTPEnabled)); err != nil {
		t.Fatalf("retention broke protected recovery completion: %v", err)
	}
	// Completion consumes the grant. Its old audit is eligible on the next run.
	if n, err := f.s.DeleteAuditLogsBefore(cutoff); err != nil || n != 1 {
		t.Fatalf("consumed recovery pinned audit: deleted=%d %v", n, err)
	}
}
