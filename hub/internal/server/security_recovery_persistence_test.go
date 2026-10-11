package server

import (
	"errors"
	"net/http"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

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
