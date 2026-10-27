package store_test

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

const managementReplacementHash = "replacement-hash"

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
			installManagementLiveAuthority(t, s, u.ID, secret, now)
			if fail {
				if _, err := s.DB().Exec(`CREATE TRIGGER reject_reset_audit BEFORE INSERT ON audit_logs WHEN NEW.action='user.password_reset' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: 0}, store.TemporaryPasswordCredential{Hash: managementReplacementHash, ExpiresAt: expires}, now, 5, managementAudit("actor", u.ID, model.AuditUserPasswordReset))
			live := mustGetUser(t, s, u.ID)
			counts := readManagementResetCounts(t, s)
			if fail {
				assertManagementFailedReset(t, s, u, live, counts, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.PasswordHash != managementReplacementHash || live.TokenGeneration != 1 || !live.MustChangePassword || !live.TempPasswordExpiresAt.Equal(expires) || live.TOTPSecret == nil || *live.TOTPSecret != secret || !live.TOTPEnabled || counts.sessions != 0 || counts.anchors != 0 || counts.history != 2 || counts.audits != 1 {
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
			_, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: 0}, store.TemporaryPasswordCredential{Hash: "new-hash", ExpiresAt: now.Add(time.Hour)}, now, 5, entry)
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
		if _, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: 1}, store.TemporaryPasswordCredential{Hash: "forbidden", ExpiresAt: now.Add(time.Hour)}, now, 5, entry); !errors.Is(err, store.ErrLocalPasswordOnly) {
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
	if _, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: 0}, store.TemporaryPasswordCredential{Hash: "new-hash", ExpiresAt: now.Add(time.Hour)}, now, 5, entry); err != nil {
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
	for _, mutation := range []struct {
		name, sql          string
		generationDelta    int
		admin, liveSession bool
	}{
		{"credential generation", "UPDATE users SET token_generation=token_generation+1 WHERE id='actor'", 1, true, true},
		{"canonical administrator role", "DELETE FROM user_roles WHERE user_id='actor' AND role='admin'", 0, false, true},
		{"interactive session", "UPDATE sessions SET ended_at=datetime('now') WHERE id='actor-session'", 0, true, false},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			s := testStore(t)
			newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
			u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
			now := time.Now().UTC()
			actor := liveManagementActor(t, s, "actor")
			if _, err := s.DB().Exec(mutation.sql); err != nil {
				t.Fatal(err)
			}
			assertManagementActorState(t, s, actor, mutation.generationDelta, mutation.admin, mutation.liveSession)
			if _, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: 0}, store.TemporaryPasswordCredential{Hash: "forbidden", ExpiresAt: now.Add(time.Hour)}, now, 5, managementAudit("actor", u.ID, model.AuditUserPasswordReset), actor); !errors.Is(err, store.ErrAccountManagementActor) {
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
	live, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: 0}, store.TemporaryPasswordCredential{Hash: "temporary", ExpiresAt: now.Add(time.Hour)}, now, 5, entry)
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
	if _, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: 0}, store.TemporaryPasswordCredential{Hash: "new", ExpiresAt: now.Add(time.Hour)}, now, 5, managementAudit("actor", u.ID, model.AuditUserPasswordReset)); err != nil {
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
			after, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: before.TokenGeneration}, store.TemporaryPasswordCredential{Hash: "new-hash", ExpiresAt: now.Add(time.Hour)}, now, 5, managementAudit("actor", u.ID, model.AuditUserPasswordReset))
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
			raceManagementDisableAction(t, s, u, action, now)
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
	if _, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: 0}, store.TemporaryPasswordCredential{Hash: "forbidden", ExpiresAt: now.Add(time.Hour)}, now, 5, managementAudit("actor", u.ID, model.AuditUserPasswordReset)); !errors.Is(err, store.ErrProtectedChange) {
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

func installManagementLiveAuthority(t *testing.T, s *store.Store, userID, secret string, now time.Time) {
	t.Helper()
	if err := s.UpdateUserTOTP(userID, &secret, true); err != nil {
		t.Fatal(err)
	}
	newLifecycleToken(t, s, "token", userID, "tokenhash")
	if _, err := s.DB().Exec(`INSERT INTO sessions(id,user_id,kind,created_at,last_seen_at) VALUES('session',?,'web',?,?)`, userID, now.Format("2006-01-02 15:04:05"), now.Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO application_login_anchors(id,user_id,completed_mfa_at,token_generation) VALUES('anchor',?,1,0)`, userID); err != nil {
		t.Fatal(err)
	}
}

func raceManagementDisableAction(t *testing.T, s *store.Store, u *model.User, action string, now time.Time) {
	t.Helper()
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
			_, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: 0}, store.TemporaryPasswordCredential{Hash: "reset-hash", ExpiresAt: now.Add(time.Hour)}, now, 5, entry)
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
}

// liveManagementActor establishes every independent authorization prerequisite
// before a test mutates exactly one of them.
func liveManagementActor(t *testing.T, s *store.Store, id string) store.AccountManagementActor {
	t.Helper()
	secret := "JBSWY3DPEHPK3PXP"
	if err := s.UpdateUserTOTP(id, &secret, true); err != nil {
		t.Fatal(err)
	}
	sessionID := id + "-session"
	if _, err := s.DB().Exec(`INSERT INTO sessions(id,user_id,kind,created_at,last_seen_at) VALUES(?,?,'web',datetime('now'),datetime('now'))`, sessionID, id); err != nil {
		t.Fatal(err)
	}
	user := mustGetUser(t, s, id)
	return store.AccountManagementActor{UserID: id, SessionID: sessionID, Generation: user.TokenGeneration, SecurityRevision: user.SecurityRevision}
}

func TestPrivilegedResetAcceptsLiveActorSnapshot(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	target := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	actor := liveManagementActor(t, s, "actor")
	now := time.Now().UTC()
	updated, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: target.ID, ExpectedGeneration: target.TokenGeneration}, store.TemporaryPasswordCredential{Hash: managementReplacementHash, ExpiresAt: now.Add(time.Hour)}, now, 5, managementAudit("actor", target.ID, model.AuditUserPasswordReset), actor)
	if err != nil {
		t.Fatalf("live actor was refused: %v", err)
	}
	if updated.PasswordHash != managementReplacementHash || updated.TokenGeneration != target.TokenGeneration+1 || !updated.MustChangePassword {
		t.Fatal("live actor did not commit the requested reset")
	}
}

func assertManagementActorState(t *testing.T, s *store.Store, actor store.AccountManagementActor, generationDelta int, admin, liveSession bool) {
	t.Helper()
	user := mustGetUser(t, s, actor.UserID)
	if !user.TOTPEnabled || user.DisabledAt != nil || user.MustChangePassword || user.SecurityRevision != actor.SecurityRevision {
		t.Fatal("actor mutation changed unrelated MFA/lifecycle/security predicates")
	}
	if user.TokenGeneration != actor.Generation+generationDelta {
		t.Fatal("actor mutation changed unexpected credential generation")
	}
	roles, err := s.UserRoles(actor.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(roles, model.RoleAdmin) != admin {
		t.Fatal("actor mutation did not isolate canonical administrator authority")
	}
	session, err := s.GetSession(actor.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if (session.EndedAt == nil) != liveSession {
		t.Fatal("actor mutation did not isolate session liveness")
	}
}

type managementResetCounts struct{ sessions, anchors, history, audits int }

func readManagementResetCounts(t *testing.T, s *store.Store) managementResetCounts {
	t.Helper()
	var counts managementResetCounts
	for _, check := range []struct {
		q string
		v *int
	}{
		{"SELECT COUNT(*) FROM sessions WHERE user_id='target' AND ended_at IS NULL", &counts.sessions},
		{"SELECT COUNT(*) FROM application_login_anchors WHERE user_id='target' AND revoked_at IS NULL", &counts.anchors},
		{"SELECT COUNT(*) FROM password_history WHERE user_id='target'", &counts.history},
		{"SELECT COUNT(*) FROM audit_logs WHERE action='user.password_reset'", &counts.audits},
	} {
		if e := s.DB().QueryRow(check.q).Scan(check.v); e != nil {
			t.Fatal(e)
		}
	}
	return counts
}

func assertManagementFailedReset(t *testing.T, s *store.Store, u, live *model.User, counts managementResetCounts, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("transaction unexpectedly committed")
	}
	if live.PasswordHash != u.PasswordHash || live.TokenGeneration != 0 || live.MustChangePassword || counts.sessions != 1 || counts.anchors != 1 || counts.history != 0 || counts.audits != 0 {
		t.Fatal("failure partially changed authority")
	}
	assertTokenActive(t, s, "tokenhash", true)
}
