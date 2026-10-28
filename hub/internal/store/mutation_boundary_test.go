package store_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"modernc.org/sqlite"
)

func TestAccountMutationResamplesClockAfterFinalSessionRead(t *testing.T) {
	var reads atomic.Int32
	var expires time.Time
	name := "account_session_delay_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := sqlite.RegisterScalarFunction(name, 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		if reads.Add(1) == 2 {
			time.Sleep(time.Until(expires) + 100*time.Millisecond)
		}
		return args[0], nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err := store.New(filepath.Join(t.TempDir(), "session-boundary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	actor := liveManagementActor(t, s, "actor")
	managementExec(t, s, "UPDATE users SET created_at='2000-01-01 00:00:00',last_activity_at=NULL,reactivated_at=NULL WHERE id='target'")
	expires = time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	managementExec(t, s, "UPDATE sessions SET expires_at=? WHERE id=?", expires.Format(sqliteBoundaryLayout), actor.SessionID)
	managementExec(t, s, "ALTER TABLE sessions RENAME TO account_boundary_sessions")
	managementExec(t, s, "CREATE VIEW sessions AS SELECT id,user_id,kind,created_at,"+name+"(last_seen_at) AS last_seen_at,expires_at,ended_at FROM account_boundary_sessions")

	_, changed, err := s.ReactivateUser("target", time.Now().UTC(), managementAudit("actor", "target", model.AuditUserReactivated), actor)
	if reads.Load() != 2 {
		t.Fatalf("expected both session guards, got %d", reads.Load())
	}
	if err == nil || changed {
		t.Fatalf("expired actor authority committed: changed=%t err=%v", changed, err)
	}
}

func TestAccountManagementPolicyReadFailureFailsClosed(t *testing.T) {
	for _, operation := range []string{"reactivate", "password reset", "password change", "MFA removal"} {
		t.Run(operation, func(t *testing.T) {
			s := testStore(t)
			now := time.Now().UTC().Truncate(time.Second)
			newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
			target := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
			var actor store.AccountManagementActor
			if operation == "password change" {
				installManagementLiveAuthority(t, s, target.ID, "target-mfa", now)
				target = mustGetUser(t, s, target.ID)
			} else {
				actor = liveManagementActor(t, s, "actor")
				if operation == "MFA removal" {
					secret := "target-mfa"
					if err := s.UpdateUserTOTP(target.ID, &secret, true); err != nil {
						t.Fatal(err)
					}
				}
			}
			managementExec(t, s, "UPDATE users SET created_at='2000-01-01 00:00:00',last_activity_at=NULL,reactivated_at=NULL WHERE id='target'")
			before := mustGetUser(t, s, target.ID)
			for _, query := range []string{
				"ALTER TABLE _config RENAME TO unavailable_account_management_config",
				"CREATE VIEW _config AS SELECT key,value FROM missing_account_management_config",
			} {
				managementExec(t, s, query)
			}
			var err error
			switch operation {
			case "reactivate":
				_, _, err = s.ReactivateUser(target.ID, now, managementAudit("actor", target.ID, model.AuditUserReactivated), actor)
			case "password reset":
				_, err = s.ResetLocalPassword(store.PasswordResetTarget{UserID: target.ID, ExpectedGeneration: before.TokenGeneration}, store.TemporaryPasswordCredential{Hash: "forbidden", ExpiresAt: now.Add(time.Hour)}, now, 5, managementAudit("actor", target.ID, model.AuditUserPasswordReset), actor)
			case "password change":
				authority := store.PasswordChangeAuthority{Snapshot: before, SessionID: "session", Generation: before.TokenGeneration, ExpiresAt: now.Add(time.Hour)}
				_, err = s.ChangeLocalPassword(before, "forbidden", now, 5, false, managementAudit(target.ID, target.ID, model.AuditUserPasswordChanged), authority)
			case "MFA removal":
				err = s.DisableUserTOTP(target.ID, now, managementAudit("actor", target.ID, model.AuditUserTOTPDisabled), actor)
			}
			if err == nil {
				t.Fatal("unavailable policy store authorized account mutation")
			}
			after := mustGetUser(t, s, target.ID)
			if after.PasswordHash != before.PasswordHash || after.TokenGeneration != before.TokenGeneration || after.SSHCredentialGeneration != before.SSHCredentialGeneration || after.TOTPEnabled != before.TOTPEnabled || after.ReactivatedAt != nil {
				t.Fatal("policy-read refusal left account mutation side effects")
			}
		})
	}
}

func TestPasswordChangeResamplesAuthorityImmediatelyBeforeCommit(t *testing.T) {
	var calls atomic.Int32
	var expires time.Time
	name := "password_commit_delay_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := sqlite.RegisterScalarFunction(name, 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		if calls.Add(1) == 1 {
			time.Sleep(time.Until(expires) + 100*time.Millisecond)
		}
		return args[0], nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err := store.New(filepath.Join(t.TempDir(), "password-commit-boundary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	installManagementLiveAuthority(t, s, "target", "enrolled", time.Now().UTC())
	u := mustGetUser(t, s, "target")
	expires = time.Now().UTC().Add(500 * time.Millisecond)
	a := store.PasswordChangeAuthority{Snapshot: u, SessionID: "session", Generation: u.TokenGeneration, ExpiresAt: expires}
	managementExec(t, s, "CREATE TRIGGER delay_password_audit BEFORE INSERT ON audit_logs WHEN NEW.action='user.password_changed' BEGIN SELECT "+name+"(NEW.action); END")

	_, err = s.ChangeLocalPassword(u, "must-not-commit", time.Now().UTC(), 5, false, managementAudit(u.ID, u.ID, model.AuditUserPasswordChanged), a)
	if !errors.Is(err, store.ErrSecurityConflict) {
		t.Fatalf("authority that expired during the transaction committed: %v", err)
	}
	live := mustGetUser(t, s, u.ID)
	state := readManagementMutationState(t, s, u.ID)
	if live.PasswordHash != u.PasswordHash || state.history != 0 || state.audits != 0 || state.tokens != 1 || state.anchors != 1 {
		t.Fatal("late authority refusal failed to roll back password side effects")
	}
}

func TestCredentialCompletionRechecksRecoveryDeadlinesBeforeCommit(t *testing.T) {
	for _, operation := range []string{"temporary password", "combined setup", "protected password grant", "protected combined grant", "protected MFA grant"} {
		t.Run(operation, func(t *testing.T) {
			var expiry time.Time
			var calls atomic.Int32
			name := "recovery_expiry_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			if err := sqlite.RegisterScalarFunction(name, 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
				if calls.Add(1) == 1 {
					time.Sleep(time.Until(expiry) + 75*time.Millisecond)
				}
				return args[0], nil
			}); err != nil {
				t.Fatal(err)
			}
			f := newManagementMutationFixture(t, "change")
			protected := strings.HasPrefix(operation, "protected")
			if protected {
				managementExec(t, f.s, "INSERT INTO user_roles(user_id,role) VALUES('target','original-reader')")
			}
			u := mustGetUser(t, f.s, "target")
			if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration}, "temporary", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			u = mustGetUser(t, f.s, u.ID)
			if operation == "protected MFA grant" {
				if _, err := f.s.CompleteApprovedPasswordRecoveryAudited(store.PasswordRecoverySnapshot{UserID: u.ID, PasswordHash: u.PasswordHash, SecurityRevision: u.SecurityRevision, TokenGeneration: u.TokenGeneration}, "permanent", time.Now().UTC(), 5, managementAudit(u.ID, u.ID, model.AuditUserPasswordChanged)); err != nil {
					t.Fatal(err)
				}
				u = mustGetUser(t, f.s, u.ID)
			}
			setup := strings.Contains(operation, "setup") || operation == "protected MFA grant"
			if setup {
				secret := "enc:staged"
				if err := f.s.UpdateUserTOTP(u.ID, &secret, false, u.TokenGeneration); err != nil {
					t.Fatal(err)
				}
			}
			expiry = time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
			if protected {
				managementExec(t, f.s, "UPDATE local_break_glass_recoveries SET expires_at=? WHERE user_id=?", expiry.Format(sqliteBoundaryLayout), u.ID)
			} else {
				managementExec(t, f.s, "UPDATE users SET temp_password_expires_at=? WHERE id=?", expiry.Format(sqliteBoundaryLayout), u.ID)
			}
			u = mustGetUser(t, f.s, u.ID)
			action := model.AuditUserPasswordChanged
			if operation == "protected MFA grant" {
				action = model.AuditUserTOTPEnabled
			}
			managementExec(t, f.s, "CREATE TRIGGER delay_recovery_audit BEFORE INSERT ON audit_logs WHEN NEW.action='"+action+"' BEGIN SELECT "+name+"(NEW.action); END")
			authority := store.PasswordChangeAuthority{Snapshot: u, Generation: u.TokenGeneration, ExpiresAt: time.Now().Add(time.Hour)}
			before := breakGlassState(t, f.s)
			var err error
			if setup {
				hash := "replacement"
				if operation == "protected MFA grant" {
					hash = ""
				}
				err = f.s.CompleteTOTPSetup(u, "enc:validated", hash, time.Now().UTC(), 5, managementAudit(u.ID, u.ID, model.AuditUserPasswordChanged), managementAudit(u.ID, u.ID, model.AuditUserTOTPEnabled), authority)
			} else if protected {
				_, err = f.s.CompleteApprovedPasswordRecoveryAudited(store.PasswordRecoverySnapshot{UserID: u.ID, PasswordHash: u.PasswordHash, SecurityRevision: u.SecurityRevision, TokenGeneration: u.TokenGeneration}, "replacement", time.Now().UTC(), 5, managementAudit(u.ID, u.ID, model.AuditUserPasswordChanged), authority)
			} else {
				_, err = f.s.ChangeLocalPassword(u, "replacement", time.Now().UTC(), 5, true, managementAudit(u.ID, u.ID, model.AuditUserPasswordChanged), authority)
			}
			if err == nil || calls.Load() != 1 {
				t.Fatalf("expired recovery authority committed or missed delayed boundary: calls=%d err=%v", calls.Load(), err)
			}
			if after := breakGlassState(t, f.s); after != before {
				t.Fatal("expired recovery authority changed durable state")
			}
		})
	}
}

func TestMutationAuthorityExpiresWhileWaitingForSQLiteWriter(t *testing.T) {
	for _, operation := range []string{"reset", "reactivate", "mfa removal", "temporary password", "combined setup", "protected password", "protected combined setup", "recovery grant", "access token"} {
		for _, timer := range []string{"absolute", "idle", "token"} {
			if timer != "absolute" && operation != "reset" && operation != "reactivate" && operation != "mfa removal" {
				continue
			}
			t.Run(operation+"/"+timer, func(t *testing.T) {
				t.Parallel()
				s, locker := boundaryStores(t)
				newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
				newLifecycleUser(t, s, "target", "target", model.RoleViewer)
				installManagementLiveAuthority(t, s, "target", "enrolled", time.Now().UTC())
				installBreakGlassApplicationAuthority(t, s)
				actor := liveManagementActor(t, s, "actor")
				if operation == "reactivate" {
					managementExec(t, s, "UPDATE users SET created_at=?,last_activity_at=NULL,reactivated_at=NULL WHERE id='target'", time.Now().Add(-60*24*time.Hour).Format(sqliteBoundaryLayout))
				}
				protected := operation == "protected password" || operation == "protected combined setup" || operation == "recovery grant"
				combined := operation == "combined setup" || operation == "protected combined setup"
				if protected {
					managementExec(t, s, "INSERT INTO user_roles(user_id,role) VALUES('target','original-reader')")
				}
				if protected || combined {
					u := mustGetUser(t, s, "target")
					if err := s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration}, "temporary", time.Now().UTC()); err != nil {
						t.Fatal(err)
					}
					if combined {
						u = mustGetUser(t, s, "target")
						secret := "enc:staged"
						if err := s.UpdateUserTOTP(u.ID, &secret, false, u.TokenGeneration); err != nil {
							t.Fatal(err)
						}
					}
				}
				// SQLite persists whole seconds. Leave enough real time to prove
				// authority is initially live before waiting across the boundary.
				expires := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
				var apply func(time.Time) error
				switch operation {
				case "reset", "reactivate", "mfa removal":
					if timer == "absolute" {
						managementExec(t, s, "UPDATE sessions SET expires_at=? WHERE id=?", expires.Format(sqliteBoundaryLayout), actor.SessionID)
					} else if timer == "idle" {
						if err := s.SetConfig(lockout.KeySessionIdleMinutes, "1"); err != nil {
							t.Fatal(err)
						}
						managementExec(t, s, "UPDATE sessions SET last_seen_at=? WHERE id=?", expires.Add(-time.Minute).Format(sqliteBoundaryLayout), actor.SessionID)
					} else {
						actor.ExpiresAt = expires
					}
					apply = func(now time.Time) error {
						switch operation {
						case "reset":
							_, err := s.ResetLocalPassword(store.PasswordResetTarget{UserID: "target"}, store.TemporaryPasswordCredential{Hash: "forbidden", ExpiresAt: now.Add(time.Hour)}, now, 5, managementAudit("actor", "target", model.AuditUserPasswordReset), actor)
							return err
						case "reactivate":
							_, _, err := s.ReactivateUser("target", now, managementAudit("actor", "target", model.AuditUserReactivated), actor)
							return err
						default:
							return s.DisableUserTOTP("target", now, managementAudit("actor", "target", model.AuditUserTOTPDisabled), actor)
						}
					}
				case "access token":
					u := mustGetUser(t, s, "target")
					a := store.PasswordChangeAuthority{Snapshot: u, SessionID: "session", Generation: u.TokenGeneration, ExpiresAt: expires}
					apply = func(now time.Time) error {
						_, err := s.ChangeLocalPassword(u, "forbidden", now, 5, false, managementAudit(u.ID, u.ID, model.AuditUserPasswordChanged), a)
						return err
					}
				default:
					temporaryExpiry := expires
					if operation == "recovery grant" {
						temporaryExpiry = expires.Add(time.Hour)
						managementExec(t, s, "UPDATE local_break_glass_recoveries SET expires_at=? WHERE user_id='target'", expires.Format(sqliteBoundaryLayout))
					}
					managementExec(t, s, "UPDATE users SET must_change_password=1,temp_password_expires_at=? WHERE id='target'", temporaryExpiry.Format(sqliteBoundaryLayout))
					u := mustGetUser(t, s, "target")
					apply = func(now time.Time) error {
						entry := managementAudit(u.ID, u.ID, model.AuditUserPasswordChanged)
						if combined {
							return s.CompleteTOTPSetup(u, "enc:validated", "forbidden", now, 5, entry, managementAudit(u.ID, u.ID, model.AuditUserTOTPEnabled))
						}
						if protected {
							_, err := s.CompleteApprovedPasswordRecoveryAudited(store.PasswordRecoverySnapshot{UserID: u.ID, PasswordHash: u.PasswordHash, SecurityRevision: u.SecurityRevision, TokenGeneration: u.TokenGeneration}, "forbidden", now, 5, entry)
							return err
						}
						_, err := s.ChangeLocalPassword(u, "forbidden", now, 5, true, entry)
						return err
					}
				}
				before := breakGlassState(t, s)
				conn := boundaryWriter(t, locker)
				now := time.Now().UTC()
				if !now.Before(expires) {
					t.Fatal("fixture authority expired before writer wait")
				}
				result := make(chan error, 1)
				go func() { result <- apply(now) }()
				waitForBoundaryWriter(t, s, result)
				<-time.After(time.Until(expires) + 100*time.Millisecond)
				if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("expired authority committed after writer wait")
					}
					if operation == "reset" || operation == "reactivate" || operation == "mfa removal" {
						if !errors.Is(err, store.ErrAccountManagementActor) {
							t.Fatalf("actor refusal: %v", err)
						}
					}
				case <-time.After(5 * time.Second):
					t.Fatal("mutation did not leave writer wait")
				}
				if after := breakGlassState(t, s); after != before {
					t.Fatal("expiry refusal changed credentials, history, grants, sessions, applications or success audits")
				}
			})
		}
	}
}

const sqliteBoundaryLayout = "2006-01-02 15:04:05"

func boundaryStores(t *testing.T) (*store.Store, *store.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "boundary.db")
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	locker, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { locker.Close() })
	return s, locker
}

func boundaryWriter(t *testing.T, locker *store.Store) *sql.Conn {
	t.Helper()
	conn, err := locker.DB().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.ExecContext(context.Background(), "ROLLBACK"); conn.Close() })
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	return conn
}

func waitForBoundaryWriter(t *testing.T, s *store.Store, result <-chan error) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if s.DB().Stats().InUse > 0 {
			select {
			case err := <-result:
				t.Fatalf("operation did not wait for SQLite writer: %v", err)
			default:
				return
			}
		}
		select {
		case err := <-result:
			t.Fatalf("operation did not wait for SQLite writer: %v", err)
		case <-deadline.C:
			t.Fatal("operation never acquired its writer connection")
		case <-tick.C:
		}
	}
}

func TestPasswordChangeRechecksAuthorityAfterWriterWait(t *testing.T) {
	for _, mutation := range []string{"ended session", "generation revoked", "MFA removed"} {
		t.Run(mutation, func(t *testing.T) {
			s, locker := boundaryStores(t)
			newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
			newLifecycleUser(t, s, "target", "target", model.RoleViewer)
			installManagementLiveAuthority(t, s, "target", "enrolled", time.Now().UTC())
			u := mustGetUser(t, s, "target")
			a := store.PasswordChangeAuthority{Snapshot: u, SessionID: "session", Generation: u.TokenGeneration, ExpiresAt: time.Now().Add(time.Hour)}
			conn := boundaryWriter(t, locker)
			result := make(chan error, 1)
			go func() {
				_, err := s.ChangeLocalPassword(u, "forbidden", time.Now(), 5, false, managementAudit(u.ID, u.ID, model.AuditUserPasswordChanged), a)
				result <- err
			}()
			waitForBoundaryWriter(t, s, result)
			query := "UPDATE sessions SET ended_at=datetime('now') WHERE id='session'"
			if mutation == "generation revoked" {
				query = "UPDATE users SET token_generation=token_generation+1 WHERE id='target'"
			} else if mutation == "MFA removed" {
				query = "UPDATE users SET totp_enabled=0,totp_secret=NULL WHERE id='target'"
			}
			if _, err := conn.ExecContext(context.Background(), query); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, store.ErrSecurityConflict) {
				t.Fatalf("revoked writer-wait authority accepted: %v", err)
			}
			live := mustGetUser(t, s, u.ID)
			state := readManagementMutationState(t, s, u.ID)
			if live.PasswordHash != u.PasswordHash || state.history != 0 || state.audits != 0 || state.tokens != 1 || state.anchors != 1 {
				t.Fatal("refused writer-wait request changed password authority")
			}
		})
	}
}
