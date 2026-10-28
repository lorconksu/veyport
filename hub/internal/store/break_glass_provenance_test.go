package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestBreakGlassAuditProvenanceRequiredThroughoutRecovery(t *testing.T) {
	for _, loss := range []string{"direct deletion", "expired grant retention", "wrong action", "wrong outcome", "wrong actor", "wrong user", "wrong target"} {
		t.Run(loss, func(t *testing.T) {
			f := newManagementMutationFixture(t, "reset")
			settings := f.s.GetAuditSettings()
			settings.TemporaryPasswordTTLHours = 30 * 24
			if err := f.s.UpdateAuditSettings(settings); err != nil {
				t.Fatal(err)
			}
			managementExec(t, f.s, "INSERT INTO user_roles(user_id,role) VALUES('target','original-reader')")
			f.user = mustGetUser(t, f.s, f.user.ID)
			// The reset is two days old, with 28 days left on its grant.
			now := time.Now().UTC().Truncate(time.Second)
			if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: f.user.ID, ExpectedGeneration: f.user.TokenGeneration}, "temporary", now.Add(-48*time.Hour)); err != nil {
				t.Fatal(err)
			}
			u := mustGetUser(t, f.s, f.user.ID)
			secret := "staged"
			if err := f.s.UpdateUserTOTP(u.ID, &secret, false, u.TokenGeneration); err != nil {
				t.Fatal(err)
			}
			u = mustGetUser(t, f.s, u.ID)
			var audit string
			if err := f.s.DB().QueryRow("SELECT audit_id FROM local_break_glass_recoveries WHERE user_id=?", u.ID).Scan(&audit); err != nil {
				t.Fatal(err)
			}
			switch loss {
			case "direct deletion":
				managementExec(t, f.s, "DELETE FROM audit_logs WHERE id=?", audit)
			case "expired grant retention":
				managementExec(t, f.s, "UPDATE local_break_glass_recoveries SET expires_at=? WHERE user_id=?", now.Add(-time.Second).Format(time.RFC3339), u.ID)
				managementExec(t, f.s, "UPDATE audit_logs SET created_at=? WHERE id=?", now.Add(-48*time.Hour).Format("2006-01-02 15:04:05"), audit)
				if n, err := f.s.DeleteAuditLogsBefore(now.Add(-24 * time.Hour).Format("2006-01-02 15:04:05")); err != nil || n != 1 {
					t.Fatalf("retention failed: %d %v", n, err)
				}
			default:
				changes := map[string]string{"wrong action": "action='user.password_reset'", "wrong outcome": "outcome='failure'", "wrong actor": "actor_type='user'", "wrong user": "user_id='actor'", "wrong target": "target='actor'"}
				managementExec(t, f.s, "UPDATE audit_logs SET "+changes[loss]+" WHERE id=?", audit)
			}
			before := breakGlassState(t, f.s)
			if err := f.s.UpdateUserTOTP(u.ID, &secret, false, u.TokenGeneration); !errors.Is(err, store.ErrProtectedChange) {
				t.Fatalf("MFA setup accepted invalid audit: %v", err)
			}
			if _, err := f.s.CompleteApprovedPasswordRecoveryAudited(store.PasswordRecoverySnapshot{UserID: u.ID, PasswordHash: u.PasswordHash, SecurityRevision: u.SecurityRevision, TokenGeneration: u.TokenGeneration}, "permanent", now, 1, f.entry); !errors.Is(err, store.ErrProtectedChange) {
				t.Fatalf("password completion accepted invalid audit: %v", err)
			}
			if err := f.s.CompleteTOTPSetup(u, "validated", "permanent", now, 1, f.entry, managementAudit(u.ID, u.ID, model.AuditUserTOTPEnabled)); !errors.Is(err, store.ErrProtectedChange) {
				t.Fatalf("combined completion accepted invalid audit: %v", err)
			}
			if before != breakGlassState(t, f.s) {
				t.Fatal("refused orphan changed durable state")
			}
			if loss == "direct deletion" || loss == "expired grant retention" {
				var n int
				if err := f.s.DB().QueryRow("SELECT COUNT(*) FROM local_break_glass_recoveries").Scan(&n); err != nil || n != 0 {
					t.Fatal("audit deletion left an orphan grant")
				}
			}
		})
	}
}
