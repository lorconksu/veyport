package server

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestApprovedPasswordResetHistoryFailureRollsBackAndReconciles(t *testing.T) {
	for _, fault := range []struct{ name, boundary string }{
		{"legacy cleanup", "BEFORE DELETE ON password_history WHEN OLD.password_hash!='older-hash'"},
		{"outgoing insert", "BEFORE INSERT ON password_history"},
		{"history retention", "BEFORE DELETE ON password_history WHEN OLD.password_hash='older-hash'"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			s, before := recoveryServer(t)
			for _, hash := range []string{"older-hash", before.PasswordHash} {
				if err := s.store.AddPasswordHistory(before.ID, hash); err != nil {
					t.Fatal(err)
				}
			}
			ref := recoveryPasswordSecret(t, s, "SyntheticTemporary@1234")
			change := prepareRecoveryPayload(t, s, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: before.ID, Operation: "password-reset", SecretRef: ref}})
			managementServerExec(t, s, "CREATE TRIGGER approved_reset_history_fault "+fault.boundary+" BEGIN SELECT RAISE(ABORT,'synthetic approved reset history failure'); END")
			proof, err := s.store.IssueStepup("recovery-officer", "officer-session", authorization.ActionApply, change.Digest, s.now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.securityService().Apply(context.Background(), change.ID, "recovery-officer", "officer-session", proof, s.securityTransition); err == nil {
				t.Fatal("failed history write published an approved reset")
			}
			after, err := s.store.GetUserByID(before.ID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("failed approved reset changed credentials or MFA: %v", err)
			}
			var history, grants int
			if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM password_history WHERE user_id=? AND password_hash IN (?,?)", before.ID, "older-hash", before.PasswordHash).Scan(&history); err != nil || history != 2 {
				t.Fatalf("failed approved reset changed prior history: count %d, error %v", history, err)
			}
			if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM security_password_recoveries WHERE user_id=?", before.ID).Scan(&grants); err != nil || grants != 0 {
				t.Fatalf("failed approved reset published a recovery grant: %v", err)
			}
			managementServerExec(t, s, "DROP TRIGGER approved_reset_history_fault")
			if _, err := s.securityService().ReconcileChange(context.Background(), change.ID, s.securityTransition); err != nil {
				t.Fatalf("restored history storage did not reconcile approved reset: %v", err)
			}
			var retained string
			if err := s.store.DB().QueryRow("SELECT password_hash FROM password_history WHERE user_id=?", before.ID).Scan(&retained); err != nil || retained != before.PasswordHash {
				t.Fatalf("reconciled approved reset lost the outgoing password: %v", err)
			}
			if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM password_history WHERE user_id=?", before.ID).Scan(&history); err != nil || history != 1 {
				t.Fatalf("reconciled reset exceeded history depth 1: count %d, error %v", history, err)
			}
		})
	}
}

func TestApprovedRecoveryCompletionRollsBackCredentialAndRevocationWritesTogether(t *testing.T) {
	h := newGovernanceHTTP(t)
	bootstrap := h.bootstrapPayload()
	bootstrap.Nominations = append(bootstrap.Nominations, model.SecurityNomination{UserID: "viewer", PersonID: "synthetic-completion-person", Roles: []model.Role{model.RoleOriginalReader}, Verification: "Synthetic independently verified recovery principal"})
	h.apply(t, h.approve(t, h.request(t, bootstrap, 1)), http.StatusOK)
	ref := h.secret(t, "password", "SyntheticTemporary@1234")
	passwordChange := h.apply(t, h.approve(t, h.request(t, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "viewer", Operation: "password-reset", SecretRef: ref}}, 2)), http.StatusOK)
	mfaChange := h.apply(t, h.approve(t, h.request(t, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "viewer", Operation: "mfa-reset"}}, 3)), http.StatusOK)
	before, err := h.s.store.GetUserByID("viewer")
	if err != nil || !before.MustChangePassword || before.TOTPEnabled {
		t.Fatalf("approved recovery fixture did not require authenticated completion: %v", err)
	}
	replacement, err := auth.HashPassword("SyntheticReplacement@1234")
	if err != nil {
		t.Fatal(err)
	}
	// This synthetic row is never issued to a client. Completion must revoke
	// every active token in the same transaction as consuming its recovery grant.
	token := &model.APIToken{ID: "synthetic-completion-token", UserID: before.ID, Name: "Atomic revocation fixture", TokenHash: "synthetic-completion-token-hash", TokenPrefix: "adt_synthetic"}
	if err := h.s.store.CreateAPIToken(token); err != nil {
		t.Fatal(err)
	}
	for _, boundary := range []string{
		"BEFORE UPDATE OF password_hash ON users WHEN NEW.id='viewer'",
		"BEFORE DELETE ON security_password_recoveries WHEN OLD.user_id='viewer'",
		"BEFORE UPDATE ON security_mfa_recoveries WHEN NEW.user_id='viewer'",
		"BEFORE UPDATE OF revoked_at ON api_tokens WHEN NEW.id='synthetic-completion-token'",
	} {
		if _, err := h.s.store.DB().Exec("CREATE TRIGGER recovery_completion_fault " + boundary + " BEGIN SELECT RAISE(ABORT,'injected approved completion storage failure'); END"); err != nil {
			t.Fatal(err)
		}
		if _, err := h.s.store.CompleteApprovedPasswordRecovery(before.ID, before.PasswordHash, before.SecurityRevision, replacement, h.clock.Now()); err == nil {
			t.Fatal("incomplete durable revocation reported successful recovery completion")
		}
		after, err := h.s.store.GetUserByID(before.ID)
		if err != nil || after.PasswordHash != before.PasswordHash || after.SecurityRevision != before.SecurityRevision || after.TokenGeneration != before.TokenGeneration || !after.MustChangePassword || after.TOTPEnabled {
			t.Fatalf("failed completion partially changed credential authority: %v", err)
		}
		var passwordRequest, storedHash, mfaRequest string
		var mfaGeneration int
		if err := h.s.store.DB().QueryRow("SELECT request_id,password_hash FROM security_password_recoveries WHERE user_id=?", before.ID).Scan(&passwordRequest, &storedHash); err != nil || passwordRequest != passwordChange.ID || storedHash != before.PasswordHash {
			t.Fatalf("failed completion consumed or substituted approved password recovery: %v", err)
		}
		if err := h.s.store.DB().QueryRow("SELECT request_id,token_generation FROM security_mfa_recoveries WHERE user_id=?", before.ID).Scan(&mfaRequest, &mfaGeneration); err != nil || mfaRequest != mfaChange.ID || mfaGeneration != before.TokenGeneration {
			t.Fatalf("failed completion partially rebound approved MFA recovery: %v", err)
		}
		if _, err := h.s.store.GetActiveAPITokenByHash(token.TokenHash); err != nil {
			t.Fatalf("rolled-back completion partially revoked the token: %v", err)
		}
		if err := h.s.store.UpdateUserPassword(before.ID, replacement); !errors.Is(err, store.ErrProtectedChange) {
			t.Fatalf("completion failure weakened ordinary protected credential writes: %v", err)
		}
		if _, err := h.s.store.DB().Exec("DROP TRIGGER recovery_completion_fault"); err != nil {
			t.Fatal(err)
		}
	}
	generation, err := h.s.store.CompleteApprovedPasswordRecovery(before.ID, before.PasswordHash, before.SecurityRevision, replacement, h.clock.Now())
	if err != nil || generation != before.TokenGeneration+1 {
		t.Fatalf("restored storage did not finish the exact approved recovery: generation%d error%v", generation, err)
	}
	after, err := h.s.store.GetUserByID(before.ID)
	if err != nil || after.PasswordHash != replacement || after.MustChangePassword || after.SecurityRevision <= before.SecurityRevision || after.TokenGeneration != generation || after.TOTPEnabled {
		t.Fatalf("completion did not atomically rotate the password while retaining unfinished MFA: %v", err)
	}
	var grants int
	if err := h.s.store.DB().QueryRow("SELECT COUNT(*) FROM security_password_recoveries WHERE user_id=?", before.ID).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("completed password recovery retained a reusable grant: %v", err)
	}
	var mfaGeneration int
	if err := h.s.store.DB().QueryRow("SELECT token_generation FROM security_mfa_recoveries WHERE user_id=?", before.ID).Scan(&mfaGeneration); err != nil || mfaGeneration != generation {
		t.Fatalf("completion stranded the separately approved MFA setup: %v", err)
	}
	if _, err := h.s.store.GetActiveAPITokenByHash(token.TokenHash); err == nil {
		t.Fatal("completed recovery left its old API token active")
	}
	if _, err := h.s.store.CompleteApprovedPasswordRecovery(before.ID, before.PasswordHash, before.SecurityRevision, replacement, h.clock.Now()); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("completed recovery accepted the stale credential snapshot: %v", err)
	}
	if len(h.archive.Governance.Envelopes()) != 12 {
		t.Fatal("completion retries rewrote or duplicated the independently approved transitions")
	}
}

func TestApprovedRecoveryCompletionRejectsGenerationOnlyRevocation(t *testing.T) {
	s, target := recoveryServer(t)
	installApprovedTemporaryPassword(t, s, "SyntheticTemporary@1234")
	before, err := s.store.GetUserByID(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.IncrementTokenGeneration(target.ID); err != nil {
		t.Fatal(err)
	}
	current, err := s.store.GetUserByID(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.SecurityRevision != before.SecurityRevision || current.PasswordHash != before.PasswordHash {
		t.Fatal("fixture changed more than credential generation")
	}
	replacement, err := auth.HashPassword("SyntheticReplacement@1234")
	if err != nil {
		t.Fatal(err)
	}
	entry := model.AuditEntry{UserID: &target.ID, Target: &target.ID, Action: model.AuditUserPasswordChanged}
	_, err = s.store.CompleteApprovedPasswordRecoveryAudited(store.PasswordRecoverySnapshot{UserID: before.ID, PasswordHash: before.PasswordHash, SecurityRevision: before.SecurityRevision, TokenGeneration: before.TokenGeneration}, replacement, s.now(), 5, entry)
	if !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("revoked completion challenge accepted: %v", err)
	}
	after, err := s.store.GetUserByID(target.ID)
	if err != nil || after.PasswordHash != before.PasswordHash || !after.MustChangePassword {
		t.Fatal("rejected generation-only revocation changed password authority")
	}
}

func TestApprovedRecoveryAuditedStorageFailureRollsBackHistoryAndAuthority(t *testing.T) {
	s, target := recoveryServer(t)
	_, _, sessionID := sessionTokenPair(t, s, target.ID)
	installApprovedTemporaryPassword(t, s, "SyntheticTemporary@1234")
	before, err := s.store.GetUserByID(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Older versions seeded active temporary hashes. Exercise atomic cleanup
	// while retaining the outgoing permanent hash captured by approved reset.
	if err := s.store.AddPasswordHistory(target.ID, before.PasswordHash); err != nil {
		t.Fatal(err)
	}
	replacement, err := auth.HashPassword("SyntheticReplacement@1234")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.PasswordRecoverySnapshot{UserID: before.ID, PasswordHash: before.PasswordHash, SecurityRevision: before.SecurityRevision, TokenGeneration: before.TokenGeneration}
	entry := model.AuditEntry{UserID: &target.ID, Target: &target.ID, Action: model.AuditUserPasswordChanged}
	for _, fault := range []struct{ name, boundary string }{
		{"password history cleanup", "BEFORE DELETE ON password_history"},
		{"durable session revocation", "BEFORE UPDATE OF ended_at ON sessions WHEN OLD.user_id='recovery-target'"},
		{"atomic success audit", "BEFORE INSERT ON audit_logs WHEN NEW.action='user.password_changed'"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			managementServerExec(t, s, "CREATE TRIGGER approved_completion_fault "+fault.boundary+" BEGIN SELECT RAISE(ABORT,'synthetic audited completion failure'); END")
			if _, err := s.store.CompleteApprovedPasswordRecoveryAudited(snapshot, replacement, s.now(), 5, entry); err == nil {
				t.Fatal("failed storage completed protected recovery")
			}
			assertApprovedCompletionRollback(t, s, before, sessionID)
			managementServerExec(t, s, "DROP TRIGGER approved_completion_fault")
		})
	}
	if _, err := s.store.CompleteApprovedPasswordRecoveryAudited(snapshot, replacement, s.now(), 5, entry); err != nil {
		t.Fatalf("restored storage did not permit approved retry: %v", err)
	}
}

func assertApprovedCompletionRollback(t *testing.T, s *Server, before *model.User, sessionID string) {
	t.Helper()
	after, err := s.store.GetUserByID(before.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.PasswordHash != before.PasswordHash || after.TokenGeneration != before.TokenGeneration || after.SecurityRevision != before.SecurityRevision || !after.MustChangePassword {
		t.Fatal("failed audited completion changed protected credential state")
	}
	var grants, history, audits int
	for _, check := range []struct {
		query string
		value *int
	}{
		{"SELECT COUNT(*) FROM security_password_recoveries WHERE user_id=?", &grants},
		{"SELECT COUNT(*) FROM password_history WHERE user_id=?", &history},
		{"SELECT COUNT(*) FROM audit_logs WHERE user_id=? AND action='user.password_changed'", &audits},
	} {
		if err := s.store.DB().QueryRow(check.query, before.ID).Scan(check.value); err != nil {
			t.Fatal(err)
		}
	}
	if grants != 1 || history != 2 || audits != 0 {
		t.Fatal("failed completion consumed approval or retained history/success audit")
	}
	session, err := s.store.GetSession(sessionID)
	if err != nil || session.EndedAt != nil {
		t.Fatal("failed audited completion partially revoked durable authority")
	}
}
