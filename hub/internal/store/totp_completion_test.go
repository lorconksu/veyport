package store_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestCompleteTOTPSetupRollsBackEveryBoundary(t *testing.T) {
	for _, protected := range []bool{false, true} {
		for _, boundary := range []string{
			"BEFORE UPDATE OF totp_enabled ON users WHEN NEW.totp_enabled=1",
			"BEFORE DELETE ON local_break_glass_recoveries",
			"BEFORE UPDATE OF password_hash ON users",
			"BEFORE DELETE ON password_history",
			"BEFORE UPDATE OF revoked_at ON api_tokens",
			"BEFORE INSERT ON audit_logs WHEN NEW.action='user.password_changed'",
			"BEFORE INSERT ON audit_logs WHEN NEW.action='user.totp_enabled'",
			"BEFORE INSERT ON _config WHEN NEW.key='initial_setup_completed'",
		} {
			t.Run(fmt.Sprintf("protected=%t/%s", protected, boundary), func(t *testing.T) {
				f := newManagementMutationFixture(t, "change")
				if protected {
					managementExec(t, f.s, "INSERT INTO user_roles(user_id,role) VALUES('target','original-reader')")
				}
				f.user = mustGetUser(t, f.s, f.user.ID)
				if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: f.user.ID, ExpectedGeneration: f.user.TokenGeneration}, "temporary", f.now); err != nil {
					t.Fatal(err)
				}
				u := mustGetUser(t, f.s, f.user.ID)
				secret := "enc:staged-synthetic"
				if err := f.s.UpdateUserTOTP(u.ID, &secret, false, u.TokenGeneration); err != nil {
					t.Fatal(err)
				}
				u = mustGetUser(t, f.s, u.ID)
				// Seed a legacy temporary history row so its cleanup is exercised.
				if err := f.s.AddPasswordHistory(u.ID, u.PasswordHash); err != nil {
					t.Fatal(err)
				}
				managementExec(t, f.s, "UPDATE api_tokens SET revoked_at=NULL WHERE user_id=?", u.ID)
				before := readManagementMutationState(t, f.s, u.ID)
				managementExec(t, f.s, "CREATE TRIGGER totp_fault "+boundary+" BEGIN SELECT RAISE(ABORT,'synthetic setup persistence failure'); END")
				err := f.s.CompleteTOTPSetup(u, "enc:validated", "replacement", f.now, 1, f.entry, managementAudit(u.ID, u.ID, model.AuditUserTOTPEnabled))
				if err == nil {
					t.Fatal("fault committed setup")
				}
				after := readManagementMutationState(t, f.s, u.ID)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("failed setup changed durable state")
				}
				var grants int
				if err := f.s.DB().QueryRow("SELECT COUNT(*) FROM local_break_glass_recoveries WHERE user_id=? AND password_hash=? AND token_generation=? AND password_pending=1", u.ID, u.PasswordHash, u.TokenGeneration).Scan(&grants); err != nil || grants != 1 {
					t.Fatal("failed setup consumed authority")
				}
				managementExec(t, f.s, "DROP TRIGGER totp_fault")
				if err := f.s.CompleteTOTPSetup(u, "enc:validated", "replacement", f.now, 1, f.entry, managementAudit(u.ID, u.ID, model.AuditUserTOTPEnabled)); err != nil {
					t.Fatalf("original snapshot not retryable: %v", err)
				}
			})
		}
	}
}

func TestCompleteTOTPSetupRejectsStaleSnapshot(t *testing.T) {
	for _, mutation := range []string{"generation", "staged secret", "security revision", "provider"} {
		t.Run(mutation, func(t *testing.T) {
			f := newManagementMutationFixture(t, "change")
			managementExec(t, f.s, "INSERT INTO user_roles(user_id,role) VALUES('target','original-reader')")
			f.user = mustGetUser(t, f.s, f.user.ID)
			if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: f.user.ID, ExpectedGeneration: f.user.TokenGeneration}, "temporary", f.now); err != nil {
				t.Fatal(err)
			}
			u := mustGetUser(t, f.s, f.user.ID)
			secret := "enc:staged"
			if err := f.s.UpdateUserTOTP(u.ID, &secret, false, u.TokenGeneration); err != nil {
				t.Fatal(err)
			}
			u = mustGetUser(t, f.s, u.ID)
			switch mutation {
			case "generation":
				managementExec(t, f.s, "UPDATE users SET token_generation=token_generation+1 WHERE id='target'")
			case "staged secret":
				managementExec(t, f.s, "UPDATE users SET totp_secret='enc:replacement' WHERE id='target'")
			case "security revision":
				managementExec(t, f.s, "UPDATE users SET security_revision=security_revision+1 WHERE id='target'")
			case "provider":
				managementExec(t, f.s, "UPDATE users SET auth_provider='ldap' WHERE id='target'")
			}
			before := readManagementMutationState(t, f.s, u.ID)
			err := f.s.CompleteTOTPSetup(u, "enc:validated", "replacement", f.now, 1, f.entry, managementAudit(u.ID, u.ID, model.AuditUserTOTPEnabled))
			if err == nil || (mutation == "generation" && !errors.Is(err, store.ErrSecurityConflict)) {
				t.Fatalf("stale snapshot accepted: %v", err)
			}
			if !reflect.DeepEqual(before, readManagementMutationState(t, f.s, u.ID)) {
				t.Fatal("stale snapshot changed state")
			}
		})
	}
}
