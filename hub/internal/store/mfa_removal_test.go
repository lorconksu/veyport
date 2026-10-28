package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestMFARemovalAtomicAtEveryBoundary(t *testing.T) {
	for _, boundary := range []string{
		"BEFORE UPDATE OF totp_secret ON users", "BEFORE UPDATE OF token_generation ON users",
		"BEFORE UPDATE OF ssh_credential_generation ON users", "BEFORE UPDATE ON api_tokens",
		"BEFORE UPDATE ON sessions", "BEFORE UPDATE ON application_login_anchors",
		"BEFORE UPDATE ON application_sessions", "BEFORE DELETE ON application_launch_tickets",
		"BEFORE UPDATE ON stepup_proofs", "BEFORE INSERT ON audit_logs", "commit",
	} {
		t.Run(boundary, func(t *testing.T) {
			f := newManagementMutationFixture(t, "reset")
			actor := liveManagementActor(t, f.s, "actor")
			installBreakGlassApplicationAuthority(t, f.s)
			if _, err := f.s.IssueStepup(f.user.ID, "target-session", "test", strings.Repeat("0", 64), f.now); err != nil {
				t.Fatal(err)
			}
			entry := managementAudit("actor", "target", model.AuditUserTOTPDisabled)
			before := breakGlassState(t, f.s)
			if boundary == "commit" {
				managementExec(t, f.s, `CREATE TABLE mfa_deferred_fault(user_id TEXT REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED)`)
				managementExec(t, f.s, `CREATE TRIGGER mfa_fault AFTER INSERT ON audit_logs BEGIN INSERT INTO mfa_deferred_fault VALUES('missing'); END`)
			} else {
				managementExec(t, f.s, "CREATE TRIGGER mfa_fault "+boundary+" BEGIN SELECT RAISE(ABORT,'synthetic MFA storage failure'); END")
			}
			if err := f.s.DisableUserTOTP(f.user.ID, f.now, entry, actor); err == nil {
				t.Fatal("fault reported success")
			}
			if after := breakGlassState(t, f.s); after != before {
				t.Fatal("factor removal partially committed")
			}
			managementExec(t, f.s, "DROP TRIGGER mfa_fault")
			if err := f.s.DisableUserTOTP(f.user.ID, f.now, entry, actor); err != nil {
				t.Fatal(err)
			}
			u := mustGetUser(t, f.s, f.user.ID)
			if u.TOTPEnabled || u.TOTPSecret != nil || u.TokenGeneration != f.user.TokenGeneration+1 || u.SSHCredentialGeneration != f.user.SSHCredentialGeneration+1 {
				t.Fatal("incomplete factor revocation")
			}
			for _, q := range []string{
				"SELECT COUNT(*) FROM sessions WHERE user_id='target' AND ended_at IS NULL",
				"SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL",
				"SELECT COUNT(*) FROM application_login_anchors WHERE revoked_at IS NULL",
				"SELECT COUNT(*) FROM application_sessions WHERE ended_at IS NULL",
				"SELECT COUNT(*) FROM application_launch_tickets",
				"SELECT COUNT(*) FROM stepup_proofs WHERE consumed_at IS NULL",
			} {
				var n int
				if err := f.s.DB().QueryRow(q).Scan(&n); err != nil || n != 0 {
					t.Fatalf("authority survived: %s: %d %v", q, n, err)
				}
			}
			var audits int
			if err := f.s.DB().QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action=? AND target=? AND outcome='success'", model.AuditUserTOTPDisabled, u.ID).Scan(&audits); err != nil || audits != 1 {
				t.Fatal("missing atomic success audit")
			}
		})
	}
}

func TestMFARemovalWritersCannotBypassRevocationOrProtection(t *testing.T) {
	for _, operation := range []string{"disable", "clear", "stage-over-enrolled", "replace"} {
		t.Run(operation, func(t *testing.T) {
			f := newManagementMutationFixture(t, "reset")
			actor := liveManagementActor(t, f.s, "actor")
			apply := func() error {
				secret := "replacement"
				switch operation {
				case "disable":
					return f.s.DisableUserTOTP(f.user.ID, f.now, managementAudit("actor", "target", model.AuditUserTOTPDisabled), actor)
				case "clear":
					return f.s.UpdateUserTOTP(f.user.ID, nil, false)
				case "stage-over-enrolled":
					return f.s.UpdateUserTOTP(f.user.ID, &secret, false)
				default:
					return f.s.UpdateUserTOTP(f.user.ID, &secret, true)
				}
			}
			managementExec(t, f.s, "INSERT INTO user_roles(user_id,role) VALUES('target','original-reader')")
			before := breakGlassState(t, f.s)
			if err := apply(); !errors.Is(err, store.ErrProtectedChange) || before != breakGlassState(t, f.s) {
				t.Fatalf("protected factor changed: %v", err)
			}
			managementExec(t, f.s, "DELETE FROM user_roles WHERE user_id='target'")
			if err := apply(); err != nil {
				t.Fatal(err)
			}
			for _, ssh := range []bool{false, true} {
				if f.s.TerminalCredentialLive(context.Background(), f.user.ID, 0, ssh) {
					t.Fatal("old credential authority survived factor change")
				}
			}
		})
	}
}

func TestSSHCredentialRequiresLiveMFAEvenAtCurrentEpoch(t *testing.T) {
	f := newManagementMutationFixture(t, "reset")
	for _, change := range []string{"totp_enabled=0", "totp_secret=NULL"} {
		managementExec(t, f.s, "UPDATE users SET totp_enabled=1,totp_secret='enrolled' WHERE id='target'")
		if !f.s.TerminalCredentialLive(context.Background(), f.user.ID, 0, true) {
			t.Fatal("enrolled credential refused")
		}
		managementExec(t, f.s, "UPDATE users SET "+change+" WHERE id='target'")
		if f.s.TerminalCredentialLive(context.Background(), f.user.ID, 0, true) {
			t.Fatal("SSH authority survived missing MFA")
		}
	}
}

func TestMFARemovalRejectsStaleActorSnapshot(t *testing.T) {
	for _, mutation := range []struct{ name, sql string }{
		{"admin role", "DELETE FROM user_roles WHERE user_id='actor' AND role='admin'"},
		{"disabled", "UPDATE users SET disabled_at=datetime('now') WHERE id='actor'"},
		{"MFA disabled", "UPDATE users SET totp_enabled=0 WHERE id='actor'"},
		{"MFA secret removed", "UPDATE users SET totp_secret=NULL WHERE id='actor'"},
		{"MFA replaced", "UPDATE users SET totp_secret='replacement' WHERE id='actor'"},
		{"credential epoch", "UPDATE users SET token_generation=token_generation+1 WHERE id='actor'"},
		{"security revision", "UPDATE users SET security_revision=security_revision+1 WHERE id='actor'"},
		{"password change required", "UPDATE users SET must_change_password=1 WHERE id='actor'"},
		{"ended session", "UPDATE sessions SET ended_at=datetime('now') WHERE id='actor-session'"},
		{"expired session", "UPDATE sessions SET expires_at=strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 second') WHERE id='actor-session'"},
		{"idle session", "UPDATE sessions SET last_seen_at=datetime('now','-1 year') WHERE id='actor-session'"},
		{"missing session", "DELETE FROM sessions WHERE id='actor-session'"},
		{"other user's session", "UPDATE sessions SET user_id='target' WHERE id='actor-session'"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			f := newManagementMutationFixture(t, "reset")
			actor := liveManagementActor(t, f.s, "actor")
			managementExec(t, f.s, mutation.sql)
			before := breakGlassState(t, f.s)
			if err := f.s.DisableUserTOTP(f.user.ID, f.now, managementAudit(actor.UserID, f.user.ID, model.AuditUserTOTPDisabled), actor); !errors.Is(err, store.ErrAccountManagementActor) {
				t.Fatalf("stale actor accepted: %v", err)
			}
			if before != breakGlassState(t, f.s) {
				t.Fatal("stale actor changed target, revoked credentials or wrote success audit")
			}
		})
	}
}

func TestMFARemovalRequiresBoundActorAndAudit(t *testing.T) {
	for _, mismatch := range []string{"missing actor", "missing session", "wrong audit actor", "wrong audit target", "wrong audit action", "self removal"} {
		t.Run(mismatch, func(t *testing.T) {
			f := newManagementMutationFixture(t, "reset")
			actor := liveManagementActor(t, f.s, "actor")
			entry := managementAudit(actor.UserID, f.user.ID, model.AuditUserTOTPDisabled)
			target := f.user.ID
			switch mismatch {
			case "missing actor":
				actor = store.AccountManagementActor{}
			case "missing session":
				actor.SessionID = ""
			case "wrong audit actor":
				entry.UserID = &target
			case "wrong audit target":
				entry.Target = &actor.UserID
			case "wrong audit action":
				entry.Action = model.AuditUserTOTPReset
			case "self removal":
				target = actor.UserID
				entry.Target = &target
			}
			before := breakGlassState(t, f.s)
			if err := f.s.DisableUserTOTP(target, f.now, entry, actor); !errors.Is(err, store.ErrAccountManagementActor) {
				t.Fatalf("unbound removal accepted: %v", err)
			}
			if before != breakGlassState(t, f.s) {
				t.Fatal("unbound removal changed durable state")
			}
		})
	}
}

func TestMFARemovalRechecksActorAfterWaitingForWriter(t *testing.T) {
	f := newManagementMutationFixture(t, "reset")
	actor := liveManagementActor(t, f.s, "actor")
	f.s.DB().SetMaxOpenConns(1)
	conn, err := f.s.DB().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	waits := f.s.DB().Stats().WaitCount
	done := make(chan error, 1)
	go func() {
		done <- f.s.DisableUserTOTP(f.user.ID, f.now, managementAudit(actor.UserID, f.user.ID, model.AuditUserTOTPDisabled), actor)
	}()
	// Wait for the operation to queue behind the writer's connection lease.
	deadline := time.Now().Add(time.Second)
	for f.s.DB().Stats().WaitCount == waits {
		if time.Now().After(deadline) {
			t.Fatal("factor removal did not reach write boundary")
		}
		time.Sleep(time.Millisecond)
	}
	// Unlike legacy users.role, canonical role revocation need not advance the
	// actor's credential generation. The transaction must check the role itself.
	if _, err := conn.ExecContext(context.Background(), "DELETE FROM user_roles WHERE user_id='actor' AND role='admin'"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-done; !errors.Is(err, store.ErrAccountManagementActor) {
		t.Fatalf("queued former administrator removed factor: %v", err)
	}
	u := mustGetUser(t, f.s, f.user.ID)
	if !u.TOTPEnabled || u.TOTPSecret == nil || u.TokenGeneration != f.user.TokenGeneration {
		t.Fatal("queued removal changed target")
	}
	var n int
	if err := f.s.DB().QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action=?", model.AuditUserTOTPDisabled).Scan(&n); err != nil || n != 0 {
		t.Fatal("refused removal wrote success audit")
	}
}

func TestMFARemovalRacingSetupAcrossConnectionsCannotRestoreRevokedFactor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	first, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	newLifecycleUser(t, first, "actor", "actor", model.RoleAdmin)
	actor := liveManagementActor(t, first, "actor")
	secret := "staged"
	if err := first.CreateUser(&model.User{ID: "target", Username: "target", Email: "target@test", PasswordHash: "permanent", Role: model.RoleViewer, TOTPSecret: &secret}); err != nil {
		t.Fatal(err)
	}
	u := mustGetUser(t, first, "target")
	start := make(chan struct{})
	completed := make(chan error, 1)
	removed := make(chan error, 1)
	go func() {
		<-start
		completed <- first.CompleteTOTPSetup(u, "enrolled", "", time.Now(), 1, model.AuditEntry{}, managementAudit(u.ID, u.ID, model.AuditUserTOTPEnabled))
	}()
	go func() {
		<-start
		removed <- second.DisableUserTOTP(u.ID, time.Now(), managementAudit(actor.UserID, u.ID, model.AuditUserTOTPDisabled), actor)
	}()
	close(start)
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil && !errors.Is(err, store.ErrSecurityConflict) {
		t.Fatal(err)
	}
	live := mustGetUser(t, first, u.ID)
	if live.TOTPEnabled || live.TOTPSecret != nil || live.TokenGeneration != u.TokenGeneration+1 || live.SSHCredentialGeneration != u.SSHCredentialGeneration+1 {
		t.Fatal("racing setup revived revoked MFA authority")
	}
}
