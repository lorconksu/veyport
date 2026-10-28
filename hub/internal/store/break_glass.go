package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

// ResetLocalTOTPBreakGlass is the shell operator's atomic local-account recovery
// boundary. It deliberately permits protected local principals; HTTP admin
// mutations must continue using ResetLocalPassword and its governance guard.
func (s *Store) ResetLocalTOTPBreakGlass(target PasswordResetTarget, hash string, now time.Time) error {
	return s.withImmediateTxAt(now, func(ctx context.Context, conn *sql.Conn, now time.Time) error {
		current, err := s.scanUser(conn.QueryRowContext(ctx, accountUserByIDQuery, target.UserID))
		if err != nil {
			return err
		}
		if current.AuthProvider != model.AuthProviderLocal {
			return ErrLocalPasswordOnly
		}
		if current.TokenGeneration != target.ExpectedGeneration {
			return ErrSecurityConflict
		}
		var history, ttl int
		if err := conn.QueryRowContext(ctx, `SELECT COALESCE((SELECT value FROM _config WHERE key=?),?),COALESCE((SELECT value FROM _config WHERE key=?),72)`, configAuthPasswordHistoryCount, defaultPasswordHistoryLimit, configAuthTemporaryPasswordTTLHours).Scan(&history, &ttl); err != nil {
			return err
		}
		if history < 1 || history > 24 || ttl < 1 || ttl > 24*30 {
			return ErrSecurityConflict
		}
		if err := appendPasswordHistoryConn(ctx, conn, current.ID, current.PasswordHash, current.MustChangePassword, history, now); err != nil {
			return err
		}
		expires := now.Add(time.Duration(ttl) * time.Hour).UTC().Format(sqliteTimeFormat)
		if _, err := conn.ExecContext(ctx, `UPDATE users SET password_hash=?,must_change_password=1,temp_password_expires_at=?,updated_at=? WHERE id=?`, hash, expires, now.UTC().Format(sqliteTimeFormat), current.ID); err != nil {
			return err
		}
		if err := removeUserTOTPConn(ctx, conn, current.ID, &current.ID, now); err != nil {
			return err
		}
		// Persist the legacy "TOTP user exists" setup state before clearing MFA
		// can reopen registration. This also retains the historical CLI behavior.
		if _, err := conn.ExecContext(ctx, `INSERT INTO _config(key,value) VALUES(?,'true') ON CONFLICT(key) DO UPDATE SET value=excluded.value`, configInitialSetupComplete); err != nil {
			return err
		}
		for _, table := range []string{"security_password_recoveries", "security_mfa_recoveries"} {
			if _, err := conn.ExecContext(ctx, "DELETE FROM "+table+" WHERE user_id=?", current.ID); err != nil {
				return err
			}
		}
		resource := "user"
		entry := model.AuditEntry{ID: uuid.NewString(), UserID: &current.ID, Target: &current.ID, Action: model.AuditUserTOTPReset, Outcome: model.AuditOutcomeSuccess, ActorType: model.AuditActorTypeSystem, ResourceType: &resource}
		if err := logAuditConn(ctx, conn, entry); err != nil {
			return err
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO local_break_glass_recoveries(user_id,audit_id,password_hash,token_generation,password_pending,expires_at) VALUES(?,?,?,?,1,?) ON CONFLICT(user_id) DO UPDATE SET audit_id=excluded.audit_id,password_hash=excluded.password_hash,token_generation=excluded.token_generation,password_pending=1,expires_at=excluded.expires_at`, current.ID, entry.ID, hash, current.TokenGeneration+1, expires)
		return err
	})
}
