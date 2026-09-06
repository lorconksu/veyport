package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

// ErrSessionNotFound reports that no session row carries the requested id.
// Callers compare with errors.Is: the authentication middleware maps it to
// "session expired" (an unknown session is indistinguishable from one that has
// been pruned), and the session handlers map it to 404. It is deliberately
// distinct from "the session exists but has already ended", which the ending
// operations report through their boolean result instead.
var ErrSessionNotFound = errors.New("session not found")

// sessionColumns is the column list every session read shares, in the order
// scanSession expects.
const sessionColumns = `id, user_id, kind, ip, user_agent, created_at,
	last_seen_at, expires_at, ended_at, end_reason, ended_by`

// scanSession reads one session row from a *sql.Row or *sql.Rows.
func scanSession(row interface{ Scan(...interface{}) error }) (*model.Session, error) {
	var s model.Session
	var createdAt, lastSeenAt string
	var expiresAt, endedAt, endReason, endedBy sql.NullString

	if err := row.Scan(
		&s.ID, &s.UserID, &s.Kind, &s.IP, &s.UserAgent, &createdAt,
		&lastSeenAt, &expiresAt, &endedAt, &endReason, &endedBy,
	); err != nil {
		return nil, err
	}

	s.CreatedAt = parseSQLiteTimeValue(createdAt)
	s.LastSeenAt = parseSQLiteTimeValue(lastSeenAt)
	s.ExpiresAt = parseSQLiteTime(expiresAt)
	s.EndedAt = parseSQLiteTime(endedAt)
	if endReason.Valid {
		s.EndReason = endReason.String
	}
	if endedBy.Valid {
		by := endedBy.String
		s.EndedBy = &by
	}
	return &s, nil
}

// parseSQLiteTimeValue converts a non-nullable stored timestamp, yielding the
// zero time for anything that does not parse.
func parseSQLiteTimeValue(v string) time.Time {
	parsed, err := time.Parse(sqliteTimeFormat, v)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// CreateSession records a new signed-in session (FR-001).
//
// ip and user_agent may be empty (the column defaults cover a request that
// carries neither), and ExpiresAt may be nil, which is how a session created
// while the absolute limit was disabled is stored: NULL means "no absolute
// limit", and a later policy change never rewrites it.
func (s *Store) CreateSession(sess *model.Session) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions (
			id, user_id, kind, ip, user_agent, created_at, last_seen_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.Kind, sess.IP, sess.UserAgent,
		sess.CreatedAt.UTC().Format(sqliteTimeFormat),
		sess.LastSeenAt.UTC().Format(sqliteTimeFormat),
		sqliteTimePtr(sess.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// GetSession reads one session by id, returning ErrSessionNotFound when there
// is no such row.
func (s *Store) GetSession(id string) (*model.Session, error) {
	sess, err := scanSession(s.db.QueryRow(
		"SELECT "+sessionColumns+" FROM sessions WHERE id = ?", id,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return sess, nil
}

// ListUserSessions returns a user's sessions for the listing endpoints.
//
// Live sessions come first, most recently seen at the top, which is the order
// the panel shows. When includeEnded is set, the ended sessions of the
// retention window follow, most recently ended first; since is the window's
// start (30 days back), so pruned-but-not-yet-deleted history cannot leak in.
// The two sections are read as two queries because they are ordered on
// different columns.
func (s *Store) ListUserSessions(userID string, includeEnded bool, since time.Time) ([]model.Session, error) {
	sessions, err := s.querySessions(
		"SELECT "+sessionColumns+` FROM sessions
		 WHERE user_id = ? AND ended_at IS NULL
		 ORDER BY last_seen_at DESC, created_at DESC, id`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	if !includeEnded {
		return sessions, nil
	}

	ended, err := s.querySessions(
		"SELECT "+sessionColumns+` FROM sessions
		 WHERE user_id = ? AND ended_at IS NOT NULL AND ended_at >= ?
		 ORDER BY ended_at DESC, id`,
		userID, since.UTC().Format(sqliteTimeFormat),
	)
	if err != nil {
		return nil, err
	}
	return append(sessions, ended...), nil
}

// querySessions runs a session query and scans every row.
func (s *Store) querySessions(query string, args ...interface{}) ([]model.Session, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	sessions := []model.Session{}
	for rows.Next() {
		sess, scanErr := scanSession(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan session: %w", scanErr)
		}
		sessions = append(sessions, *sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

// TouchSession records that a session was used, for the idle clock (FR-003).
//
// This runs on every authenticated request, so it is deliberately cheap: one
// guarded UPDATE that writes at most once per session per minInterval
// regardless of request rate. The guard also refuses to touch an ended
// session, so a request racing a revoke can never resurrect it. An unknown or
// already-ended session is not an error, because the caller must never fail a
// request over the activity clock.
//
// minInterval is the caller's choice because the throttle is also the error
// bar on the idle clock: last_seen_at can lag real activity by up to
// minInterval, so a session may be judged idle that much early. The caller
// scales it to the configured idle limit rather than fixing it here (see
// touchInterval in the server package). A minInterval of zero or less stamps
// on every request, which is the exact clock at the cost of a write per
// request.
func (s *Store) TouchSession(id string, now time.Time, minInterval time.Duration) error {
	stamp := now.UTC().Format(sqliteTimeFormat)

	var err error
	if minInterval <= 0 {
		_, err = s.db.Exec(
			`UPDATE sessions SET last_seen_at = ?
			 WHERE id = ? AND ended_at IS NULL`,
			stamp, id,
		)
	} else {
		threshold := now.UTC().Add(-minInterval).Format(sqliteTimeFormat)
		_, err = s.db.Exec(
			`UPDATE sessions SET last_seen_at = ?
			 WHERE id = ? AND ended_at IS NULL AND last_seen_at < ?`,
			stamp, id, threshold,
		)
	}
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

// EndSession ends one session, and reports whether it was live at the time.
//
// The write is guarded on ended_at IS NULL, so two administrators revoking the
// same session concurrently serialize: exactly one sees wasLive true and audits
// the revocation, and the loser reports "already ended" without overwriting the
// first actor and reason. by is the acting user, or nil when the system ended
// the session (expiry, or an account disable).
//
// Returns ErrSessionNotFound when no such session exists, which is how a
// handler tells a wrong or unknown id (404) from an already-ended one (200).
func (s *Store) EndSession(id, reason string, by *string, now time.Time) (wasLive bool, err error) {
	return s.endOne(id, reason, by, now)
}

// MarkExpired ends a session that a validation check found expired, and
// reports whether this was the first detection.
//
// It is EndSession with no actor: expiry is the hub's own decision, so
// ended_by stays NULL. first is what keeps the audit trail to exactly one
// session.expired event per session (FR-005) even when several requests of the
// same expired session arrive at once, because the guarded UPDATE lets only
// one of them win.
func (s *Store) MarkExpired(id, reason string, now time.Time) (first bool, err error) {
	return s.endOne(id, reason, nil, now)
}

// endOne is the shared body of EndSession and MarkExpired.
func (s *Store) endOne(id, reason string, by *string, now time.Time) (bool, error) {
	stamp := now.UTC().Format(sqliteTimeFormat)

	result, err := s.db.Exec(
		`UPDATE sessions SET ended_at = ?, end_reason = ?, ended_by = ?
		 WHERE id = ? AND ended_at IS NULL`,
		stamp, reason, by, id,
	)
	if err != nil {
		return false, fmt.Errorf("end session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("end session rows: %w", err)
	}
	if rows == 1 {
		return true, nil
	}

	// Nothing was updated: the session is either already ended or absent.
	var exists int
	switch err := s.db.QueryRow("SELECT 1 FROM sessions WHERE id = ?", id).Scan(&exists); {
	case errors.Is(err, sql.ErrNoRows):
		return false, ErrSessionNotFound
	case err != nil:
		return false, fmt.Errorf("read session after end: %w", err)
	default:
		return false, nil
	}
}

// EndUserSessions ends every live session of a user and returns their ids.
//
// exceptID spares one session, which is what "sign out my other sessions"
// needs; pass nil to end them all (an admin revoke-all, or an account disable).
// The ids come back so the caller can audit one session.revoked per session
// that was actually live, and close the shells that belong to them.
//
// The select and the update share one BEGIN IMMEDIATE transaction, so the ids
// returned are exactly the rows this call ended: a session created or revoked
// by a concurrent request cannot slip between the two statements and be
// reported as ended by this actor.
func (s *Store) EndUserSessions(
	userID string, exceptID *string, reason string, by *string, now time.Time,
) ([]string, error) {
	stamp := now.UTC().Format(sqliteTimeFormat)
	var ids []string

	err := s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		ids = nil

		query := "SELECT id FROM sessions WHERE user_id = ? AND ended_at IS NULL"
		args := []interface{}{userID}
		if exceptID != nil {
			query += " AND id != ?"
			args = append(args, *exceptID)
		}

		rows, queryErr := conn.QueryContext(ctx, query, args...)
		if queryErr != nil {
			return fmt.Errorf("select live sessions: %w", queryErr)
		}
		for rows.Next() {
			var id string
			if scanErr := rows.Scan(&id); scanErr != nil {
				rows.Close()
				return fmt.Errorf("scan live session id: %w", scanErr)
			}
			ids = append(ids, id)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			rows.Close()
			return fmt.Errorf("iterate live sessions: %w", rowsErr)
		}
		rows.Close()

		if len(ids) == 0 {
			return nil
		}

		for _, id := range ids {
			if _, execErr := conn.ExecContext(
				ctx,
				`UPDATE sessions SET ended_at = ?, end_reason = ?, ended_by = ?
				 WHERE id = ? AND ended_at IS NULL`,
				stamp, reason, by, id,
			); execErr != nil {
				return fmt.Errorf("end user sessions: %w", execErr)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// PruneEndedSessions deletes ended sessions that ended before the cutoff, and
// returns how many rows went.
//
// Only ended rows are eligible: a live session is never removed however old it
// is, because removing it would silently sign its owner out (FR-013).
func (s *Store) PruneEndedSessions(before time.Time) (int64, error) {
	result, err := s.db.Exec(
		"DELETE FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?",
		before.UTC().Format(sqliteTimeFormat),
	)
	if err != nil {
		return 0, fmt.Errorf("prune ended sessions: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune ended sessions rows: %w", err)
	}
	return deleted, nil
}
