package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

// removeUserTOTPConn is the common factor-removal boundary, including shell
// break-glass and governed recovery. Call only inside an immediate transaction.
// Revocation is durable so other Hub processes cannot retain credential authority.
func removeUserTOTPConn(ctx context.Context, conn *sql.Conn, user string, actor *string, now time.Time) error {
	result, err := conn.ExecContext(ctx, `UPDATE users SET totp_secret=NULL,totp_enabled=0,token_generation=token_generation+1,ssh_credential_generation=ssh_credential_generation+1,updated_at=? WHERE id=?`, now.UTC().Format(sqliteTimeFormat), user)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		if err != nil {
			return err
		}
		return ErrSecurityConflict
	}
	if err := revokeCredentialAuthorityConn(ctx, conn, user, actor, now, "mfa_reset"); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "UPDATE stepup_proofs SET consumed_at=COALESCE(consumed_at,?) WHERE user_id=?", now.Unix(), user)
	return err
}

// DisableUserTOTP commits ordinary administrator factor removal and its success
// audit together. Actor authority and target governance are checked under the
// same write lock, using the snapshot whose TOTP the handler verified.
func (s *Store) DisableUserTOTP(user string, now time.Time, entry model.AuditEntry, actor AccountManagementActor) error {
	clock := advancingClock(now)
	return s.securityUserWrite(user, false, func(ctx context.Context, conn *sql.Conn) error {
		if actor.SessionID == "" || actor.UserID == user || entry.UserID == nil || *entry.UserID != actor.UserID || entry.Target == nil || *entry.Target != user || entry.Action != model.AuditUserTOTPDisabled {
			return ErrAccountManagementActor
		}
		// Include time waiting for BEGIN IMMEDIATE when checking session expiry.
		if err := guardAccountManagementActor(ctx, conn, []AccountManagementActor{actor}, clock); err != nil {
			return err
		}
		now := clock()
		if err := removeUserTOTPConn(ctx, conn, user, entry.UserID, now); err != nil {
			return err
		}
		if err := logAuditConn(ctx, conn, entry); err != nil {
			return err
		}
		return guardAccountManagementActor(ctx, conn, []AccountManagementActor{actor}, clock)
	})
}
