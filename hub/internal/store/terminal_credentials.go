package store

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"time"

	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/lockout"
)

const TerminalCredentialTimeout = 250 * time.Millisecond

// WithTerminalAuthorizationBoundary holds SQLite's cross-process writer gate
// while fn performs the final durable authorization check and ordered agent
// send. A revocation cannot commit between those two events. The transaction is
// read-only from the application's perspective and is always rolled back.
func (s *Store) WithTerminalAuthorizationBoundary(ctx context.Context, fn func() error) (err error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	return fn()
}

// TerminalAuthorizationLive checks an established shell's current authority in
// one bounded read budget, using indexed user/role/server/permission predicates. It
// observes changes from other processes without in-memory invalidation hooks.
// The execution user must still be the one captured when the agent opened it.
func (s *Store) TerminalAuthorizationLive(ctx context.Context, user, server, executionUser string, generation int, ssh bool, owningSession ...string) bool {
	ctx, cancel := context.WithTimeout(ctx, TerminalCredentialTimeout)
	defer cancel()
	conn, err := s.credentialDB.Conn(ctx)
	if err != nil {
		return false
	}
	defer conn.Close()
	var authorized bool
	var created, dormantDays string
	var activity, reactivated sql.NullString
	var in account.Input
	err = conn.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM servers WHERE id=?) AND
		(EXISTS(SELECT 1 FROM user_roles WHERE user_id=u.id AND role='admin') OR
		 (u.auth_provider='ldap' AND u.terminal_access AND
		  EXISTS(SELECT 1 FROM permissions WHERE user_id=u.id AND server_id=? AND path='/'))) AND
		CASE WHEN u.auth_provider='ldap' THEN COALESCE(NULLIF(u.ldap_username,''),u.username) ELSE '' END = ?,
		u.created_at,u.last_activity_at,u.reactivated_at,u.dormancy_exempt,
		COALESCE((SELECT value FROM _config WHERE key=?),'')
		FROM users u WHERE u.id=?
		AND ((? AND u.ssh_credential_generation=?) OR (NOT ? AND u.token_generation=?))
		AND (NOT ? OR (u.totp_enabled AND u.totp_secret IS NOT NULL))
		AND u.disabled_at IS NULL AND NOT u.must_change_password`,
		server, server, executionUser, lockout.KeyDormantDays, user,
		ssh, generation, ssh, generation, ssh,
	).Scan(&authorized, &created, &activity, &reactivated, &in.DormancyExempt, &dormantDays)
	if err != nil || ctx.Err() != nil || !authorized {
		return false
	}
	in.CreatedAt = parseSQLiteTimeValue(created)
	in.LastActivityAt, in.ReactivatedAt = parseSQLiteTime(activity), parseSQLiteTime(reactivated)
	policy := lockout.Load(func(key string) (string, error) {
		if key == lockout.KeyDormantDays {
			return dormantDays, nil
		}
		return "", nil
	})
	if account.IsDormant(in, time.Now(), policy.DormantDays) || !s.terminalPolicyLive(ctx, conn, user, server) {
		return false
	}
	if !ssh && len(owningSession) > 0 && !terminalSessionLive(ctx, conn, owningSession[0], user, time.Now()) {
		return false
	}

	return ctx.Err() == nil
}

// Credential reads must not inherit the writer pool's five-second busy wait.
// The driver applies DSN pragmas before it can observe context cancellation,
// so disable busy handling even during connection initialization. Lock errors
// fail closed immediately; pool acquisition and query execution share a deadline.
func openCredentialDB(dsn string) (*sql.DB, error) {
	path, query, _ := strings.Cut(dsn, "?")
	params, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}
	params.Set("_pragma", "busy_timeout(0)")
	params.Add("_pragma", "query_only(1)")
	db, err := sql.Open("sqlite", path+"?"+params.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	// Do not retain reader locks/connections between periodic checks.
	db.SetMaxIdleConns(0)
	return db, nil
}

// TerminalSessionLive uses the authentication session policy with strict stored
// timestamps, bounded pool acquisition and fail-closed reads. Admission supplies
// its clock; watchers supply the real clock without touching session activity.

func (s *Store) TerminalSessionLive(ctx context.Context, id, user string, now time.Time) bool {
	clock := advancingClock(now)
	ctx, cancel := context.WithTimeout(ctx, TerminalCredentialTimeout)
	defer cancel()
	conn, err := s.credentialDB.Conn(ctx)
	if err != nil {
		return false
	}
	defer conn.Close()
	return terminalSessionLive(ctx, conn, id, user, clock())
}
func terminalSessionLive(ctx context.Context, conn securityQuerier, id, user string, now time.Time) bool {
	clock := advancingClock(now)
	if id == "" {
		return false
	}
	var readErr error
	policy := lockout.Load(func(key string) (string, error) {
		// Only the saved kind's two idle limits influence the session verdict.
		if key != lockout.KeySessionIdleMinutes && key != lockout.KeyCLISessionIdleMinutes {
			return "", nil
		}
		var raw string
		err := conn.QueryRowContext(ctx, "SELECT value FROM _config WHERE key=?", key).Scan(&raw)
		if err != nil && err != sql.ErrNoRows {
			readErr = err
		}
		return raw, err
	})
	return readErr == nil && guardLiveSession(ctx, conn, id, user, clock(), policy) == nil && ctx.Err() == nil
}
