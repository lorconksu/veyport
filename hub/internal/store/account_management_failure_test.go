package store_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

type managementMutationFixture struct {
	s     *store.Store
	user  *model.User
	now   time.Time
	entry model.AuditEntry
}

type managementStorageBoundary struct {
	name, trigger string
	history       int
}

func TestAccountManagementMutationStorageFailuresRollBackAuthority(t *testing.T) {
	boundaries := []managementStorageBoundary{
		{"outgoing history", "BEFORE INSERT ON password_history WHEN NEW.password_hash='h'", 5},
		{"legacy history cleanup", "BEFORE DELETE ON password_history WHEN OLD.password_hash='h'", 5},
		{"history retention", "BEFORE DELETE ON password_history", 0},
		{"credential update", "BEFORE UPDATE OF password_hash ON users WHEN OLD.id='target'", 5},
		{"API revocation", "BEFORE UPDATE OF revoked_at ON api_tokens WHEN OLD.user_id='target'", 5},
		{"session revocation", "BEFORE UPDATE OF ended_at ON sessions WHEN OLD.user_id='target'", 5},
		{"application anchor revocation", "BEFORE UPDATE OF revoked_at ON application_login_anchors WHEN OLD.user_id='target'", 5},
		{"success audit", "BEFORE INSERT ON audit_logs WHEN NEW.action IN ('user.password_reset','user.password_changed')", 5},
	}
	for _, operation := range []string{"reset", "change"} {
		for _, boundary := range boundaries {
			t.Run(operation+"/"+boundary.name, func(t *testing.T) { verifyManagementMutationRollback(t, operation, boundary) })
		}
	}
}

func newManagementMutationFixture(t *testing.T, operation string) managementMutationFixture {
	t.Helper()
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	now := time.Now().UTC().Truncate(time.Second)
	installManagementLiveAuthority(t, s, "target", "preserved-mfa", now)
	action := model.AuditUserPasswordReset
	if operation == "change" {
		action = model.AuditUserPasswordChanged
	}
	return managementMutationFixture{s: s, user: mustGetUser(t, s, "target"), now: now, entry: managementAudit("actor", "target", action)}
}

func (f managementMutationFixture) apply(operation string, history int) (*model.User, error) {
	if operation == "reset" {
		return f.s.ResetLocalPassword(store.PasswordResetTarget{UserID: f.user.ID, ExpectedGeneration: f.user.TokenGeneration}, store.TemporaryPasswordCredential{Hash: managementReplacementHash, ExpiresAt: f.now.Add(time.Hour)}, f.now, history, f.entry)
	}
	if _, err := f.s.ChangeLocalPassword(f.user, managementReplacementHash, f.now, history, false, f.entry); err != nil {
		return nil, err
	}
	return f.s.GetUserByID(f.user.ID)
}

func managementExec(t *testing.T, s *store.Store, query string, args ...any) {
	t.Helper()
	if _, err := s.DB().Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

type managementMutationState struct {
	user                                       model.User
	history, tokens, sessions, anchors, audits int
}

func readManagementMutationState(t *testing.T, s *store.Store, id string) managementMutationState {
	t.Helper()
	result := managementMutationState{user: *mustGetUser(t, s, id)}
	checks := []struct {
		query string
		value *int
	}{
		{"SELECT COUNT(*) FROM password_history WHERE user_id=?", &result.history},
		{"SELECT COUNT(*) FROM api_tokens WHERE user_id=? AND revoked_at IS NULL", &result.tokens},
		{"SELECT COUNT(*) FROM sessions WHERE user_id=? AND ended_at IS NULL", &result.sessions},
		{"SELECT COUNT(*) FROM application_login_anchors WHERE user_id=? AND revoked_at IS NULL", &result.anchors},
		{"SELECT COUNT(*) FROM audit_logs WHERE target=? AND outcome='success'", &result.audits},
	}
	for _, check := range checks {
		if err := s.DB().QueryRow(check.query, id).Scan(check.value); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func verifyManagementMutationRollback(t *testing.T, operation string, boundary managementStorageBoundary) {
	t.Helper()
	f := newManagementMutationFixture(t, operation)
	if boundary.name == "legacy history cleanup" {
		if err := f.s.AddPasswordHistory(f.user.ID, f.user.PasswordHash); err != nil {
			t.Fatal(err)
		}
	}
	before := readManagementMutationState(t, f.s, f.user.ID)
	managementExec(t, f.s, "CREATE TRIGGER account_mutation_fault "+boundary.trigger+" BEGIN SELECT RAISE(ABORT,'synthetic account mutation storage failure'); END")
	if _, err := f.apply(operation, boundary.history); err == nil {
		t.Fatal("failed authoritative storage published a credential mutation")
	}
	after := readManagementMutationState(t, f.s, f.user.ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed mutation changed credentials, MFA, history, durable authority or success audit")
	}
	managementExec(t, f.s, "DROP TRIGGER account_mutation_fault")
	updated, err := f.apply(operation, boundary.history)
	if err != nil {
		t.Fatalf("restored storage did not permit explicit retry: %v", err)
	}
	if updated.PasswordHash != managementReplacementHash || updated.TokenGeneration != before.user.TokenGeneration+1 {
		t.Fatal("explicit retry did not commit the requested mutation")
	}
}

func TestAccountManagementStoreRefusesMissingAndDirectoryTargets(t *testing.T) {
	f := newManagementMutationFixture(t, "reset")
	missing := *f.user
	missing.ID = "missing-target"
	if _, err := f.s.ChangeLocalPassword(&missing, managementReplacementHash, f.now, 5, false, f.entry); err == nil {
		t.Fatal("missing password-change target accepted")
	}
	if _, err := f.s.ResetLocalPassword(store.PasswordResetTarget{UserID: missing.ID}, store.TemporaryPasswordCredential{Hash: managementReplacementHash, ExpiresAt: f.now.Add(time.Hour)}, f.now, 5, f.entry); err == nil {
		t.Fatal("missing password-reset target accepted")
	}
	if _, _, err := f.s.ReactivateUser(missing.ID, f.now, f.entry); err == nil {
		t.Fatal("missing reactivation target accepted")
	}
	managementExec(t, f.s, "UPDATE users SET auth_provider='ldap' WHERE id=?", f.user.ID)
	if _, err := f.s.ChangeLocalPassword(f.user, managementReplacementHash, f.now, 5, false, f.entry); !errors.Is(err, store.ErrLocalPasswordOnly) {
		t.Fatalf("directory credential change refusal: %v", err)
	}
}

func TestAccountManagementReactivationStorageFailurePreservesDormancyAndLock(t *testing.T) {
	f := newManagementMutationFixture(t, "reset")
	managementExec(t, f.s, "UPDATE users SET created_at=?,locked_until=?,failed_login_count=7 WHERE id=?", f.now.Add(-60*24*time.Hour).Format("2006-01-02 15:04:05"), f.now.Add(time.Hour).Format("2006-01-02 15:04:05"), f.user.ID)
	before := readManagementMutationState(t, f.s, f.user.ID)
	managementExec(t, f.s, "CREATE TRIGGER account_reactivation_fault BEFORE UPDATE OF reactivated_at ON users BEGIN SELECT RAISE(ABORT,'synthetic reactivation failure'); END")
	if _, _, err := f.s.ReactivateUser(f.user.ID, f.now, f.entry); err == nil {
		t.Fatal("reactivation storage failure reported success")
	}
	if after := readManagementMutationState(t, f.s, f.user.ID); !reflect.DeepEqual(before, after) {
		t.Fatal("failed reactivation changed independent lifecycle or audit state")
	}
}

func TestAccountManagementRefusesUnavailableAdministratorAndMetadataStore(t *testing.T) {
	f := newManagementMutationFixture(t, "reset")
	actor := store.AccountManagementActor{UserID: "missing-actor"}
	if _, err := f.s.ResetLocalPassword(store.PasswordResetTarget{UserID: f.user.ID}, store.TemporaryPasswordCredential{Hash: managementReplacementHash, ExpiresAt: f.now.Add(time.Hour)}, f.now, 5, f.entry, actor); !errors.Is(err, store.ErrAccountManagementActor) {
		t.Fatal("missing administrator accepted")
	}
	if _, _, err := f.s.ReactivateUser(f.user.ID, f.now, f.entry, actor); !errors.Is(err, store.ErrAccountManagementActor) {
		t.Fatal("missing administrator reactivated target")
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ProtectedUsers(); err == nil {
		t.Fatal("unavailable protection metadata was treated as ordinary users")
	}
}

func TestAccountManagementPasswordChangeCannotBypassProtectedPrincipal(t *testing.T) {
	f := newManagementMutationFixture(t, "change")
	managementExec(t, f.s, "INSERT INTO user_roles(user_id,role) VALUES(?,'original-reader')", f.user.ID)
	before := readManagementMutationState(t, f.s, f.user.ID)
	if _, err := f.s.ChangeLocalPassword(f.user, managementReplacementHash, f.now, 5, false, f.entry); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("ordinary password change bypassed protection: %v", err)
	}
	if after := readManagementMutationState(t, f.s, f.user.ID); !reflect.DeepEqual(before, after) {
		t.Fatal("protected refusal partially changed credential authority")
	}
}
