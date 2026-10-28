package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
)

// ErrSessionRefreshRejected covers spent refresh tokens and a session or
// account whose authority changed before rotation. It never exposes a digest.
var ErrSessionRefreshRejected = errors.New("refresh token is no longer current")

// RotateSessionRefresh durably replaces a session's one-use refresh digest.
// The single guarded UPDATE is also the authorization commit point: account
// revocation, MFA/recovery changes and session expiry cannot race its checks.
// Existing sessions with no digest may adopt their first valid signed refresh
// after migration; the UPDATE serializes that adoption with every other spend.
// An empty previous digest is used only when issuing a new sign-in's tokens.
// Mandatory password replacement uses a purpose-bound recovery challenge and
// may never publish normal access or refresh authority, including initial issue.
func (s *Store) RotateSessionRefresh(ctx context.Context, user *model.User, sessionID, previous, next string, now time.Time, policy lockout.Policy) error {
	if user == nil || user.ID == "" || sessionID == "" || !auditrecord.ValidHash(next) ||
		(previous != "" && (!auditrecord.ValidHash(previous) || previous == next)) {
		return ErrSessionRefreshRejected
	}
	tx, cleanup, err := s.protectedTransaction(ctx)
	if err != nil {
		return fmt.Errorf("start refresh rotation: %w", err)
	}
	defer cleanup()
	stamp := now.UTC().Format(sqliteTimeFormat)
	cliIdle := session.IdleTimeout(model.SessionKindCLI, policy)
	webIdle := session.IdleTimeout(model.SessionKindWeb, policy)
	cliThreshold := now.UTC().Add(-cliIdle).Format(sqliteTimeFormat)
	webThreshold := now.UTC().Add(-webIdle).Format(sqliteTimeFormat)
	result, err := tx.ExecContext(ctx, `UPDATE sessions
		SET refresh_token_sha256=?, last_seen_at=CASE WHEN last_seen_at<? THEN ? ELSE last_seen_at END
		WHERE id=? AND user_id=? AND ended_at IS NULL
		AND (expires_at IS NULL OR expires_at>?)
		AND (CASE WHEN kind=? THEN ? ELSE ? END<=0
		    OR last_seen_at>=CASE WHEN kind=? THEN ? ELSE ? END)
		AND (refresh_token_sha256=? OR refresh_token_sha256='')
		AND EXISTS (SELECT 1 FROM users WHERE id=? AND token_generation=? AND security_revision=?
		    AND disabled_at IS NULL AND totp_enabled=1 AND must_change_password=?
		    AND must_change_password=0)`,
		next, stamp, stamp, sessionID, user.ID, stamp,
		model.SessionKindCLI, cliIdle.Nanoseconds(), webIdle.Nanoseconds(), model.SessionKindCLI, cliThreshold, webThreshold,
		previous, user.ID, user.TokenGeneration, user.SecurityRevision, user.MustChangePassword)
	if err != nil {
		return fmt.Errorf("rotate session refresh: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read refresh rotation result: %w", err)
	}
	if changed != 1 {
		return ErrSessionRefreshRejected
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit refresh rotation: %w", err)
	}
	return nil
}
