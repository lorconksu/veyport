package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
)

// FailureResult reports the account state after one recorded credential
// failure. NewlyLocked is true only for the single call that performed the
// unlocked → locked transition, so callers can emit the lock audit entry and
// notification exactly once even under concurrent attempts.
type FailureResult struct {
	// Count is the consecutive-failure count now stored on the account.
	Count int
	// LockedUntil is the account's lock expiry, or nil if it has never locked.
	LockedUntil *time.Time
	// NewlyLocked reports whether this failure is the one that locked the account.
	NewlyLocked bool
}

// RecordLoginFailure records one failed credential check against a user and
// applies the lockout policy to the result.
//
// The read-decide-write cycle runs inside a single BEGIN IMMEDIATE transaction
// on a dedicated connection (the same pattern as LogAudit's hash chain), so
// SQLite's single writer serializes simultaneous failures: the second caller
// reads the first caller's lock and therefore does not report NewlyLocked.
// The transition itself is delegated to the pure lockout package.
//
// An unknown user is an error and writes nothing.
func (s *Store) RecordLoginFailure(userID string, now time.Time, p lockout.Policy) (result FailureResult, err error) {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return FailureResult{}, fmt.Errorf("acquire connection: %w", err)
	}

	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return FailureResult{}, fmt.Errorf("begin immediate: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
		_ = conn.Close()
	}()

	var count int
	var lastFailedAt, lockedUntil sql.NullString
	err = conn.QueryRowContext(
		ctx,
		"SELECT failed_login_count, last_failed_login_at, locked_until FROM users WHERE id = ?",
		userID,
	).Scan(&count, &lastFailedAt, &lockedUntil)
	if err == sql.ErrNoRows {
		return FailureResult{}, fmt.Errorf(errUserNotFound)
	}
	if err != nil {
		return FailureResult{}, fmt.Errorf("read lockout state: %w", err)
	}

	prev := lockout.State{
		Count:        count,
		LastFailedAt: parseSQLiteTime(lastFailedAt),
		LockedUntil:  parseSQLiteTime(lockedUntil),
	}
	next, newlyLocked := lockout.NextState(prev, now, p)

	_, err = conn.ExecContext(
		ctx,
		`UPDATE users
		 SET failed_login_count = ?, last_failed_login_at = ?, locked_until = ?, updated_at = ?
		 WHERE id = ?`,
		next.Count, sqliteTimePtr(next.LastFailedAt), sqliteTimePtr(next.LockedUntil),
		now.UTC().Format(sqliteTimeFormat), userID,
	)
	if err != nil {
		return FailureResult{}, fmt.Errorf("record login failure: %w", err)
	}

	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return FailureResult{}, fmt.Errorf("commit login failure: %w", err)
	}
	committed = true

	return FailureResult{
		Count:       next.Count,
		LockedUntil: next.LockedUntil,
		NewlyLocked: newlyLocked,
	}, nil
}

// RecordLoginSuccess clears the failure streak and any lock on a successful
// sign-in and stamps the last-login time. last_failed_login_at is deliberately
// left in place: it is failure history for administrators, not counter state.
//
// A single UPDATE is enough here — there is no read-modify-write to protect,
// and clearing is idempotent.
func (s *Store) RecordLoginSuccess(userID string, now time.Time) error {
	stamp := now.UTC().Format(sqliteTimeFormat)
	result, err := s.db.Exec(
		`UPDATE users
		 SET failed_login_count = 0, last_login_at = ?, locked_until = NULL, updated_at = ?
		 WHERE id = ?`,
		stamp, stamp, userID,
	)
	if err != nil {
		return fmt.Errorf("record login success: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("record login success rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf(errUserNotFound)
	}
	return nil
}

// parseSQLiteTime converts a nullable stored timestamp into a *time.Time,
// yielding nil for NULL and for any value that does not parse.
func parseSQLiteTime(v sql.NullString) *time.Time {
	if !v.Valid {
		return nil
	}
	parsed, err := time.Parse(sqliteTimeFormat, v.String)
	if err != nil {
		return nil
	}
	return &parsed
}
