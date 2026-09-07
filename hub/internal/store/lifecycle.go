package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

// Sentinel errors for the account-lifecycle operations. Callers compare with
// errors.Is and map them to HTTP responses.
var (
	// ErrAlreadyDisabled reports that the target account was already disabled,
	// so nothing was written. Handlers treat this as an idempotent success.
	ErrAlreadyDisabled = errors.New("account is already disabled")
	// ErrLastAdmin reports that disabling the target would leave the hub with
	// no enabled administrator.
	ErrLastAdmin = errors.New("cannot disable the last enabled administrator")
	// ErrNotAdmin reports that the target account is not an administrator, and
	// so cannot carry the dormancy exemption.
	ErrNotAdmin = errors.New("account is not an administrator")
)

// activityThrottle is the minimum gap between two writes of last_activity_at
// for the same user. See research R3: token authentication touches the clock
// on every request, and this bounds that to one write per user per minute.
const activityThrottle = 60 * time.Second

// withImmediateTx runs fn inside a BEGIN IMMEDIATE transaction on a dedicated
// connection, committing when fn returns nil and rolling back otherwise.
//
// BEGIN IMMEDIATE takes SQLite's single write lock up front, so a read
// performed inside fn cannot be invalidated by another writer before fn's own
// write lands. That is what makes the guards below race-safe: the decision and
// the write it authorises are one atomic step.
func (s *Store) withImmediateTx(fn func(ctx context.Context, conn *sql.Conn) error) (err error) {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}

	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return fmt.Errorf("begin immediate: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
		_ = conn.Close()
	}()

	if err = fn(ctx, conn); err != nil {
		return err
	}

	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}

// DisableUser disables an account as one atomic step and returns the number of
// API tokens the disable revoked.
//
// Everything that removes access happens in a single BEGIN IMMEDIATE
// transaction: the disabled marker and actor are stamped, token_generation is
// advanced (which invalidates the account's access and refresh tokens), and
// every active API token the account holds is revoked. There is no
// half-disabled state to observe, and re-enabling does not resurrect the old
// tokens (FR-002, FR-003).
//
// The last-admin guard is evaluated inside that same transaction, so two
// administrators disabling each other at the same instant serialize: the
// second sees the first's write and is refused with ErrLastAdmin, and the hub
// can never reach zero enabled administrators (SC-003).
//
// Returns an unknown-user error, ErrAlreadyDisabled or ErrLastAdmin without
// writing anything.
func (s *Store) DisableUser(userID, byID string, now time.Time) (revokedTokens int, err error) {
	stamp := now.UTC().Format(sqliteTimeFormat)

	err = s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		var role model.Role
		var disabledAt sql.NullString
		scanErr := conn.QueryRowContext(
			ctx, "SELECT role, disabled_at FROM users WHERE id = ?", userID,
		).Scan(&role, &disabledAt)
		if scanErr == sql.ErrNoRows {
			return fmt.Errorf(errUserNotFound)
		}
		if scanErr != nil {
			return fmt.Errorf("read account state: %w", scanErr)
		}
		if disabledAt.Valid {
			return ErrAlreadyDisabled
		}

		if role == model.RoleAdmin {
			var others int
			if countErr := conn.QueryRowContext(
				ctx,
				`SELECT COUNT(*) FROM users
				 WHERE role = ? AND disabled_at IS NULL AND id != ?`,
				model.RoleAdmin, userID,
			).Scan(&others); countErr != nil {
				return fmt.Errorf("count enabled admins: %w", countErr)
			}
			if others == 0 {
				return ErrLastAdmin
			}
		}

		result, execErr := conn.ExecContext(
			ctx,
			`UPDATE users
			 SET disabled_at = ?, disabled_by = ?,
			     token_generation = token_generation + 1, updated_at = ?
			 WHERE id = ? AND disabled_at IS NULL`,
			stamp, byID, stamp, userID,
		)
		if execErr != nil {
			return fmt.Errorf("disable user: %w", execErr)
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return fmt.Errorf("disable user rows: %w", rowsErr)
		}
		if rows != 1 {
			// The row was read inside this write transaction, so this cannot
			// happen; treat it as a lost race rather than writing on.
			return fmt.Errorf("disable user: expected 1 row updated, got %d", rows)
		}

		tokenResult, tokenErr := conn.ExecContext(
			ctx,
			`UPDATE api_tokens
			 SET revoked_at = ?, updated_at = ?
			 WHERE user_id = ? AND revoked_at IS NULL`,
			stamp, stamp, userID,
		)
		if tokenErr != nil {
			return fmt.Errorf("revoke api tokens on disable: %w", tokenErr)
		}
		tokenRows, tokenRowsErr := tokenResult.RowsAffected()
		if tokenRowsErr != nil {
			return fmt.Errorf("revoke api tokens rows: %w", tokenRowsErr)
		}
		revokedTokens = int(tokenRows)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return revokedTokens, nil
}

// EnableUser re-enables an account, clearing the disabled marker and actor,
// any lock, and the consecutive-failure count (FR-004).
//
// wasDisabled reports whether the account was actually disabled, which is what
// the caller audits and what decides the activity clock: reactivated_at is
// stamped only on a real disabled → enabled transition, so enabling an already
// enabled account is idempotent and does not push out the dormancy deadline.
// The read that decides it runs inside the same BEGIN IMMEDIATE transaction as
// the write, so a concurrent disable cannot slip in between them.
func (s *Store) EnableUser(userID string, now time.Time) (wasDisabled bool, err error) {
	stamp := now.UTC().Format(sqliteTimeFormat)

	err = s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		var disabledAt sql.NullString
		scanErr := conn.QueryRowContext(
			ctx, "SELECT disabled_at FROM users WHERE id = ?", userID,
		).Scan(&disabledAt)
		if scanErr == sql.ErrNoRows {
			return fmt.Errorf(errUserNotFound)
		}
		if scanErr != nil {
			return fmt.Errorf("read account state: %w", scanErr)
		}
		wasDisabled = disabledAt.Valid

		_, execErr := conn.ExecContext(
			ctx,
			`UPDATE users
			 SET disabled_at = NULL, disabled_by = NULL,
			     locked_until = NULL, failed_login_count = 0,
			     reactivated_at = CASE WHEN disabled_at IS NOT NULL THEN ? ELSE reactivated_at END,
			     updated_at = ?
			 WHERE id = ?`,
			stamp, stamp, userID,
		)
		if execErr != nil {
			return fmt.Errorf("enable user: %w", execErr)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return wasDisabled, nil
}

// UnlockUser clears a lockout and its failure count (FR-005).
//
// wasLocked reports whether a lock was actually in force at now — a lock that
// has already expired reads as false, since the account was usable again
// anyway. As with EnableUser, reactivated_at moves only on a real transition,
// and the read that decides it shares the write transaction, so the answer
// cannot be stale by the time the write lands.
func (s *Store) UnlockUser(userID string, now time.Time) (wasLocked bool, err error) {
	stamp := now.UTC().Format(sqliteTimeFormat)

	err = s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		var lockedUntil sql.NullString
		scanErr := conn.QueryRowContext(
			ctx, "SELECT locked_until FROM users WHERE id = ?", userID,
		).Scan(&lockedUntil)
		if scanErr == sql.ErrNoRows {
			return fmt.Errorf(errUserNotFound)
		}
		if scanErr != nil {
			return fmt.Errorf("read lock state: %w", scanErr)
		}
		if until := parseSQLiteTime(lockedUntil); until != nil && until.After(now.UTC()) {
			wasLocked = true
		}

		// COALESCE leaves reactivated_at untouched when the bind is NULL,
		// which is exactly the "was not locked" case.
		var reactivated interface{}
		if wasLocked {
			reactivated = stamp
		}
		_, execErr := conn.ExecContext(
			ctx,
			`UPDATE users
			 SET locked_until = NULL, failed_login_count = 0,
			     reactivated_at = COALESCE(?, reactivated_at), updated_at = ?
			 WHERE id = ?`,
			reactivated, stamp, userID,
		)
		if execErr != nil {
			return fmt.Errorf("unlock user: %w", execErr)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return wasLocked, nil
}

// SetDormancyExempt sets or clears the dormancy exemption, which only
// administrator accounts may carry — the exemption exists to guarantee a hub
// always keeps one recovery path, and that path has to be an admin.
//
// The role condition lives in the UPDATE itself, so a concurrent demotion
// cannot leave a non-admin exempt. Returns ErrNotAdmin for a non-admin target
// and an unknown-user error for a missing one.
func (s *Store) SetDormancyExempt(userID string, exempt bool) error {
	result, err := s.db.Exec(
		`UPDATE users
		 SET dormancy_exempt = ?, updated_at = ?
		 WHERE id = ? AND role = ?`,
		exempt, time.Now().UTC().Format(sqliteTimeFormat), userID, model.RoleAdmin,
	)
	if err != nil {
		return fmt.Errorf("set dormancy exemption: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("set dormancy exemption rows: %w", err)
	}
	if rows > 0 {
		return nil
	}

	// Nothing matched: the row is either missing or not an administrator.
	var role model.Role
	switch err := s.db.QueryRow("SELECT role FROM users WHERE id = ?", userID).Scan(&role); {
	case err == sql.ErrNoRows:
		return fmt.Errorf(errUserNotFound)
	case err != nil:
		return fmt.Errorf("read role for dormancy exemption: %w", err)
	default:
		return ErrNotAdmin
	}
}

// TouchUserActivity records that an account was used, for the dormancy clock.
//
// This runs on the API-token authentication path, so it is deliberately cheap:
// one guarded UPDATE that writes at most once per user per activityThrottle
// regardless of request rate (research R3). It leaves updated_at alone — mere
// use is not an administrative change to the row — and an unknown user is not
// an error, because the caller must never fail a request over the clock.
func (s *Store) TouchUserActivity(userID string, now time.Time) error {
	stamp := now.UTC().Format(sqliteTimeFormat)
	threshold := now.UTC().Add(-activityThrottle).Format(sqliteTimeFormat)

	_, err := s.db.Exec(
		`UPDATE users
		 SET last_activity_at = ?
		 WHERE id = ? AND (last_activity_at IS NULL OR last_activity_at < ?)`,
		stamp, userID, threshold,
	)
	if err != nil {
		return fmt.Errorf("touch user activity: %w", err)
	}
	return nil
}

// CountEnabledAdmins returns the number of accounts that are administrators
// and not disabled — the definition the last-admin guard rests on.
func (s *Store) CountEnabledAdmins() (int, error) {
	var count int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM users WHERE role = ? AND disabled_at IS NULL`,
		model.RoleAdmin,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count enabled admins: %w", err)
	}
	return count, nil
}
