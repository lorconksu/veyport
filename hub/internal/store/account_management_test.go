package store_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func managementAudit(actor, target, action string) model.AuditEntry {
	return model.AuditEntry{UserID: &actor, Target: &target, Action: action}
}
func TestReactivateUserPreservesLockAndNoopAnchor(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	now := time.Now().UTC().Truncate(time.Second)
	created := now.Add(-60 * 24 * time.Hour)
	locked := now.Add(time.Hour)
	if _, err := s.DB().Exec("UPDATE users SET created_at=?,locked_until=?,failed_login_count=7 WHERE id=?", created.Format("2006-01-02 15:04:05"), locked.Format("2006-01-02 15:04:05"), u.ID); err != nil {
		t.Fatal(err)
	}
	got, changed, err := s.ReactivateUser(u.ID, now, 35, managementAudit("actor", u.ID, model.AuditUserReactivated))
	if err != nil || !changed {
		t.Fatalf("reactivate changed=%v err=%v", changed, err)
	}
	if got.ReactivatedAt == nil || !got.ReactivatedAt.Equal(now) || got.LockedUntil == nil || !got.LockedUntil.Equal(locked) || got.FailedLoginCount != 7 {
		t.Fatal("reactivation lost independent lock state")
	}
	_, changed, err = s.ReactivateUser(u.ID, now.Add(time.Hour), 35, managementAudit("actor", u.ID, model.AuditUserReactivated))
	if err != nil || changed {
		t.Fatalf("noop changed=%v err=%v", changed, err)
	}
	got = mustGetUser(t, s, u.ID)
	if !got.ReactivatedAt.Equal(now) {
		t.Fatal("noop moved activity clock")
	}
	if _, err := s.DisableUser(u.ID, "actor", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReactivateUser(u.ID, now, 35, managementAudit("actor", u.ID, model.AuditUserReactivated)); !errors.Is(err, store.ErrAccountDisabled) {
		t.Fatalf("disabled refusal %v", err)
	}
}

func TestResetLocalPasswordAtomicRevocationAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "audit failure rolls everything back"}[fail], func(t *testing.T) {
			s := testStore(t)
			newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
			u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
			now := time.Now().UTC().Truncate(time.Second)
			expires := now.Add(time.Hour)
			secret := "preserved-mfa"
			if err := s.UpdateUserTOTP(u.ID, &secret, true); err != nil {
				t.Fatal(err)
			}
			newLifecycleToken(t, s, "token", u.ID, "tokenhash")
			if _, err := s.DB().Exec(`INSERT INTO sessions(id,user_id,kind,created_at,last_seen_at) VALUES('session',?,'web',?,?)`, u.ID, now.Format("2006-01-02 15:04:05"), now.Format("2006-01-02 15:04:05")); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec(`INSERT INTO application_login_anchors(id,user_id,completed_mfa_at,token_generation) VALUES('anchor',?,1,0)`, u.ID); err != nil {
				t.Fatal(err)
			}
			if fail {
				if _, err := s.DB().Exec(`CREATE TRIGGER reject_reset_audit BEFORE INSERT ON audit_logs WHEN NEW.action='user.password_reset' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.ResetLocalPassword(u.ID, 0, "replacement-hash", expires, now, 5, managementAudit("actor", u.ID, model.AuditUserPasswordReset))
			live := mustGetUser(t, s, u.ID)
			var sessions, anchors, history, audits int
			for _, check := range []struct {
				q string
				v *int
			}{
				{"SELECT COUNT(*) FROM sessions WHERE user_id='target' AND ended_at IS NULL", &sessions},
				{"SELECT COUNT(*) FROM application_login_anchors WHERE user_id='target' AND revoked_at IS NULL", &anchors},
				{"SELECT COUNT(*) FROM password_history WHERE user_id='target'", &history},
				{"SELECT COUNT(*) FROM audit_logs WHERE action='user.password_reset'", &audits},
			} {
				if e := s.DB().QueryRow(check.q).Scan(check.v); e != nil {
					t.Fatal(e)
				}
			}
			if fail {
				if err == nil {
					t.Fatal("transaction unexpectedly committed")
				}
				if live.PasswordHash != u.PasswordHash || live.TokenGeneration != 0 || live.MustChangePassword || sessions != 1 || anchors != 1 || history != 0 || audits != 0 {
					t.Fatal("failure partially changed authority")
				}
				assertTokenActive(t, s, "tokenhash", true)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.PasswordHash != "replacement-hash" || live.TokenGeneration != 1 || !live.MustChangePassword || !live.TempPasswordExpiresAt.Equal(expires) || live.TOTPSecret == nil || *live.TOTPSecret != secret || !live.TOTPEnabled || sessions != 0 || anchors != 0 || history != 2 || audits != 1 {
				t.Fatal("reset did not preserve MFA or revoke durable authority atomically")
			}
			assertTokenActive(t, s, "tokenhash", false)
		})
	}
}

func TestResetPasswordConflictsAndSourceGuard(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	now := time.Now().UTC()
	entry := managementAudit("actor", u.ID, model.AuditUserPasswordReset)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.ResetLocalPassword(u.ID, 0, "new-hash", now.Add(time.Hour), now, 5, entry)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	succeeded, conflicted := 0, 0
	for err := range errs {
		if err == nil {
			succeeded++
		} else if errors.Is(err, store.ErrSecurityConflict) {
			conflicted++
		} else {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("successes=%d conflicts=%d", succeeded, conflicted)
	}
	for _, provider := range []string{"ldap", "unexpected"} {
		if _, err := s.DB().Exec("UPDATE users SET auth_provider=? WHERE id=?", provider, u.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ResetLocalPassword(u.ID, 1, "forbidden", now.Add(time.Hour), now, 5, entry); !errors.Is(err, store.ErrLocalPasswordOnly) {
			t.Fatalf("provider %s accepted: %v", provider, err)
		}
	}
}

func TestPasswordChangeCannotOverwriteResetOrDisabledState(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	now := time.Now().UTC()
	entry := managementAudit("actor", u.ID, model.AuditUserPasswordReset)
	if _, err := s.ResetLocalPassword(u.ID, 0, "new-hash", now.Add(time.Hour), now, 5, entry); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeLocalPassword(u, "stale", now, 5, false, entry); !errors.Is(err, store.ErrSecurityConflict) {
		t.Fatalf("stale change accepted %v", err)
	}
	live := mustGetUser(t, s, u.ID)
	if _, err := s.DisableUser(u.ID, "actor", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeLocalPassword(live, "stale", now, 5, true, entry); !errors.Is(err, store.ErrSecurityConflict) {
		t.Fatalf("disabled change accepted %v", err)
	}
}

func TestPrivilegedResetRechecksActorAuthority(t *testing.T) {
	for _, mutation := range []string{"UPDATE users SET token_generation=token_generation+1 WHERE id='actor'", "UPDATE users SET role='viewer' WHERE id='actor'", "UPDATE sessions SET ended_at=datetime('now') WHERE id='actor-session'"} {
		t.Run(mutation, func(t *testing.T) {
			s := testStore(t)
			newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
			u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
			now := time.Now().UTC()
			if _, err := s.DB().Exec(`INSERT INTO sessions(id,user_id,kind,created_at,last_seen_at) VALUES('actor-session','actor','web',datetime('now'),datetime('now'))`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec(mutation); err != nil {
				t.Fatal(err)
			}
			actor := store.AccountManagementActor{UserID: "actor", SessionID: "actor-session"}
			if _, err := s.ResetLocalPassword(u.ID, 0, "forbidden", now.Add(time.Hour), now, 5, managementAudit("actor", u.ID, model.AuditUserPasswordReset), actor); !errors.Is(err, store.ErrAccountManagementActor) {
				t.Fatalf("stale actor accepted: %v", err)
			}
			if got := mustGetUser(t, s, u.ID); got.PasswordHash != u.PasswordHash || got.TokenGeneration != 0 {
				t.Fatal("stale actor changed credentials")
			}
		})
	}
}

func TestPasswordRecoveryCompletionExpiresAndConsumesGeneration(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	now := time.Now().UTC().Truncate(time.Second)
	entry := managementAudit("actor", u.ID, model.AuditUserPasswordReset)
	live, err := s.ResetLocalPassword(u.ID, 0, "temporary", now.Add(time.Hour), now, 5, entry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeLocalPassword(live, "permanent", now.Add(time.Hour), 5, true, entry); !errors.Is(err, store.ErrTemporaryPasswordExpired) {
		t.Fatalf("expiry not enforced: %v", err)
	}
	if _, err := s.ChangeLocalPassword(live, "permanent", now.Add(time.Minute), 5, true, entry); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeLocalPassword(live, "replay", now.Add(time.Minute), 5, true, entry); !errors.Is(err, store.ErrSecurityConflict) {
		t.Fatalf("replay accepted: %v", err)
	}
	got := mustGetUser(t, s, u.ID)
	if got.MustChangePassword || got.TempPasswordExpiresAt != nil || got.TokenGeneration != 2 {
		t.Fatal("recovery state not consumed")
	}
}

// Keep bcrypt verification explicit: outgoing local credentials remain in policy
// history even when created before password-history collection existed.
func TestResetPreservesOutgoingPasswordHistory(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	hash, err := auth.HashPassword("Previous!Password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUserPassword(u.ID, hash); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := s.ResetLocalPassword(u.ID, 0, "new", now.Add(time.Hour), now, 5, managementAudit("actor", u.ID, model.AuditUserPasswordReset)); err != nil {
		t.Fatal(err)
	}
	matches, err := s.PasswordMatchesRecent(u.ID, "Previous!Password123", 5)
	if err != nil || !matches {
		t.Fatalf("outgoing password lost: %v", err)
	}
}

func TestPasswordResetPreservesEveryLifecycleRestriction(t *testing.T) {
	for _, state := range []string{"locked", "disabled", "dormant"} {
		t.Run(state, func(t *testing.T) {
			s := testStore(t)
			newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
			u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
			now := time.Now().UTC().Truncate(time.Second)
			switch state {
			case "locked":
				if _, err := s.DB().Exec("UPDATE users SET locked_until=?,failed_login_count=7 WHERE id=?", now.Add(time.Hour).Format("2006-01-02 15:04:05"), u.ID); err != nil {
					t.Fatal(err)
				}
			case "disabled":
				if _, err := s.DisableUser(u.ID, "actor", now); err != nil {
					t.Fatal(err)
				}
			case "dormant":
				if _, err := s.DB().Exec("UPDATE users SET created_at=? WHERE id=?", now.Add(-60*24*time.Hour).Format("2006-01-02 15:04:05"), u.ID); err != nil {
					t.Fatal(err)
				}
			}
			before := mustGetUser(t, s, u.ID)
			after, err := s.ResetLocalPassword(u.ID, before.TokenGeneration, "new-hash", now.Add(time.Hour), now, 5, managementAudit("actor", u.ID, model.AuditUserPasswordReset))
			if err != nil {
				t.Fatal(err)
			}
			sameTime := func(a, b *time.Time) bool { return a == nil && b == nil || a != nil && b != nil && a.Equal(*b) }
			if !sameTime(before.LockedUntil, after.LockedUntil) || !sameTime(before.DisabledAt, after.DisabledAt) || !sameTime(before.ReactivatedAt, after.ReactivatedAt) || before.FailedLoginCount != after.FailedLoginCount || !before.CreatedAt.Equal(after.CreatedAt) {
				t.Fatal("password reset changed lifecycle state")
			}
		})
	}
}

func TestResetAndReactivateSerializeWithConcurrentDisable(t *testing.T) {
	for _, action := range []string{"password-reset", "reactivate"} {
		t.Run(action, func(t *testing.T) {
			s := testStore(t)
			newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
			u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
			now := time.Now().UTC().Truncate(time.Second)
			if _, err := s.DB().Exec("UPDATE users SET created_at=? WHERE id=?", now.Add(-60*24*time.Hour).Format("2006-01-02 15:04:05"), u.ID); err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			go func() { <-start; _, err := s.DisableUser(u.ID, "actor", now); results <- err }()
			go func() {
				<-start
				entry := managementAudit("actor", u.ID, model.AuditUserReactivated)
				if action == "reactivate" {
					_, _, err := s.ReactivateUser(u.ID, now, 35, entry)
					results <- err
				} else {
					_, err := s.ResetLocalPassword(u.ID, 0, "reset-hash", now.Add(time.Hour), now, 5, entry)
					results <- err
				}
			}()
			close(start)
			for range 2 {
				err := <-results
				if err != nil && !errors.Is(err, store.ErrSecurityConflict) && !errors.Is(err, store.ErrAccountDisabled) {
					t.Fatal(err)
				}
			}
			live := mustGetUser(t, s, u.ID)
			if live.DisabledAt == nil {
				t.Fatal("concurrent administrative action restored disabled access")
			}
			if live.PasswordHash != u.PasswordHash && live.PasswordHash != "reset-hash" {
				t.Fatal("concurrency produced unexpected password")
			}
		})
	}
}

func TestAccountManagementProtectionIsReevaluatedInsideStore(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	now := time.Now().UTC()
	// A promotion after the UI snapshot must defeat both ordinary endpoints.
	if _, err := s.DB().Exec("INSERT INTO user_roles(user_id,role) VALUES(?,'original-reader')", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetLocalPassword(u.ID, 0, "forbidden", now.Add(time.Hour), now, 5, managementAudit("actor", u.ID, model.AuditUserPasswordReset)); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("protected reset accepted: %v", err)
	}
	if _, _, err := s.ReactivateUser(u.ID, now, 35, managementAudit("actor", u.ID, model.AuditUserReactivated)); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("protected reactivate accepted: %v", err)
	}
	flags, err := s.ProtectedUsers()
	if err != nil || !flags[u.ID] || flags["actor"] {
		t.Fatalf("batched protected metadata wrong: %v", err)
	}
}
