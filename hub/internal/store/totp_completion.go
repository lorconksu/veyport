package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/model"
)

// CompleteTOTPSetup commits the checked setup snapshot, optional temporary
// password replacement, grants, revocations and success audits together.
// Encryption and password policy/history validation must precede this call.
func (s *Store) CompleteTOTPSetup(snapshot *model.User, encryptedSecret, newHash string, now time.Time, history int, passwordAudit, totpAudit model.AuditEntry, authority ...PasswordChangeAuthority) error {
	if snapshot == nil || encryptedSecret == "" {
		return ErrSecurityConflict
	}
	return s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		recheck, err := s.guardPasswordChangeAuthority(ctx, conn, snapshot.ID, authority, clock)
		if err != nil {
			return err
		}
		now := clock()
		live, err := s.scanUser(conn.QueryRowContext(ctx, accountUserByIDQuery, snapshot.ID))
		if err != nil {
			return err
		}
		if live.TokenGeneration != snapshot.TokenGeneration || live.SecurityRevision != snapshot.SecurityRevision || live.PasswordHash != snapshot.PasswordHash || live.AuthProvider != snapshot.AuthProvider || live.TOTPEnabled || live.DisabledAt != nil || live.TOTPSecret == nil || snapshot.TOTPSecret == nil || *live.TOTPSecret != *snapshot.TOTPSecret || live.MustChangePassword != snapshot.MustChangePassword {
			return ErrSecurityConflict
		}
		policy, err := accountManagementPolicyStrict(ctx, conn)
		if err != nil {
			return err
		}
		if account.IsDormant(account.InputFromUser(live), now, policy.DormantDays) {
			return ErrSecurityConflict
		}
		// Check MFA authority before changing any generation or consuming password authority.
		if err := guardMFASetup(ctx, conn, live.ID, true, now); err != nil {
			return err
		}
		mfaDeadline, err := mfaSetupDeadlineRecheck(ctx, conn, live.ID, now)
		if err != nil {
			return err
		}
		passwordDeadline := func(time.Time) error { return nil }
		if live.MustChangePassword {
			if newHash == "" {
				return ErrSecurityConflict
			}
			if err := guardSecurityPrincipal(ctx, conn, live.ID); err != nil {
				if err != ErrProtectedChange {
					return err
				}
				passwordDeadline, err = s.completeApprovedPasswordRecoveryConn(ctx, conn, PasswordRecoverySnapshot{UserID: live.ID, PasswordHash: live.PasswordHash, SecurityRevision: live.SecurityRevision, TokenGeneration: live.TokenGeneration}, newHash, now, history, &passwordAudit)
				if err != nil {
					return err
				}
			} else {
				passwordDeadline = temporaryPasswordDeadlineRecheck(live, true)
				if err := passwordDeadline(now); err != nil {
					return err
				}
				if err := s.changeLocalPasswordConn(ctx, conn, live, newHash, now, history, true, passwordAudit); err != nil {
					return err
				}
			}
		} else if newHash != "" {
			return ErrSecurityConflict
		}
		if err := updateUserTOTPConn(ctx, conn, live.ID, &encryptedSecret, true); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO _config(key,value) VALUES(?, 'true') ON CONFLICT(key) DO UPDATE SET value='true'", configInitialSetupComplete); err != nil {
			return err
		}
		if err := logAuditConn(ctx, conn, totpAudit); err != nil {
			return err
		}
		finalNow := clock()
		if err := passwordDeadline(finalNow); err != nil {
			return err
		}
		if err := mfaDeadline(finalNow); err != nil {
			return err
		}
		return recheck(finalNow)
	})
}
