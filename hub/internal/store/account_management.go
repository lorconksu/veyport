package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
)

var ErrAccountDisabled = errors.New("account disabled; enable it separately")
var ErrLocalPasswordOnly = errors.New("password recovery is available for local accounts only")
var ErrTemporaryPasswordExpired = errors.New("temporary password expired")
var ErrUserExists = errors.New("user already exists")

// PasswordResetTarget binds an administrator's confirmation to the observed credential generation.
type PasswordResetTarget struct {
	UserID             string
	ExpectedGeneration int
}

// TemporaryPasswordCredential contains only the one-way credential and its expiry.
type TemporaryPasswordCredential struct {
	Hash      string
	ExpiresAt time.Time
}

// PasswordRecoverySnapshot is the immutable password-stage authority checked at commit.
type PasswordRecoverySnapshot struct {
	UserID, PasswordHash              string
	SecurityRevision, TokenGeneration int
}

const accountUserByIDQuery = "SELECT " + userSelectColumns + " FROM users WHERE id=?"

// CreateUserAudited binds administrator authority, the new account and its
// success audit to one writer transaction. Revocation that committed before
// this transaction is observed by the actor guard; audit failure rolls the
// account back instead of leaving an unaudited principal behind.
func (s *Store) CreateUserAudited(user *model.User, now time.Time, entry model.AuditEntry, actor AccountManagementActor) error {
	normalizeUserForCreate(user)
	return s.accountManagementWrite(now, actor, func(ctx context.Context, conn *sql.Conn, _ func() time.Time) error {
		var exists bool
		if err := conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username=? OR email=?)", user.Username, user.Email).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrUserExists
		}
		if _, err := conn.ExecContext(ctx, createUserStatement, createUserArgs(user)...); err != nil {
			return err
		}
		if err := logAuditConn(ctx, conn, entry); err != nil {
			return err
		}
		return nil
	})
}

// ProtectedUsers resolves governance protection in one query for the user table.
func (s *Store) ProtectedUsers() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT u.id, (SELECT (SELECT COUNT(*) FROM user_roles r JOIN security_identity_links l ON l.user_id=r.user_id WHERE r.role IN ('security-officer','security-approver','original-reader') AND l.person_id=(SELECT person_id FROM security_identity_links WHERE user_id=u.id))+(SELECT COUNT(*) FROM security_nominations n JOIN security_changes c ON c.id=n.request_id WHERE (n.user_id=u.id OR n.person_id=(SELECT person_id FROM security_identity_links WHERE user_id=u.id)) AND c.state IN ('requested','partially_approved','approved','applying'))+(SELECT COUNT(*) FROM security_changes c WHERE c.state IN ('requested','partially_approved','approved','applying') AND (u.id IN (json_extract(c.payload,'$.change.role.user_id'),json_extract(c.payload,'$.change.person.user_id'),json_extract(c.payload,'$.change.recovery.user_id')) OR c.state='applying' AND u.id IN (c.requester_id,c.applier_id)))) > 0 FROM users u`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		var protected bool
		if err := rows.Scan(&id, &protected); err != nil {
			return nil, err
		}
		out[id] = protected
	}
	return out, rows.Err()
}

// ReactivateUser changes only the dormancy anchor. In particular, a live lock
// and the disabled flag have independent semantics and are never cleared.
func (s *Store) ReactivateUser(id string, now time.Time, entry model.AuditEntry, actors ...AccountManagementActor) (user *model.User, changed bool, err error) {
	err = s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		if err := guardAccountManagementActor(ctx, conn, actors, clock); err != nil {
			return err
		}
		if err := guardSecurityPrincipal(ctx, conn, id); err != nil {
			return err
		}
		var e error
		user, e = s.scanUser(conn.QueryRowContext(ctx, accountUserByIDQuery, id))
		if e != nil {
			return e
		}
		if user.DisabledAt != nil {
			return ErrAccountDisabled
		}
		policy, e := accountManagementPolicyStrict(ctx, conn)
		if e != nil {
			return e
		}
		now := clock()
		changed = account.IsDormant(account.InputFromUser(user), now, policy.DormantDays)
		if changed {
			stamp := now.UTC().Format(sqliteTimeFormat)
			if _, e = conn.ExecContext(ctx, "UPDATE users SET reactivated_at=?,updated_at=? WHERE id=?", stamp, stamp, id); e != nil {
				return e
			}
			anchor := parseSQLiteTimeValue(stamp)
			user.ReactivatedAt = &anchor
		}
		detail := "{\"changed\":false}"
		if changed {
			detail = "{\"changed\":true}"
		}
		entry.Detail = &detail
		if err := logAuditConn(ctx, conn, entry); err != nil {
			return err
		}
		// Session expiry is a clock-only revocation and cannot be blocked by the
		// writer transaction. Recheck it after every potentially blocking read
		// and write; failure rolls back the reactivation and its success audit.
		return guardAccountManagementActor(ctx, conn, actors, clock)
	})
	if err != nil {
		user, changed = nil, false
	}
	return
}

// ResetLocalPassword installs one credential generation and revokes all durable
// authority in the same write transaction as its history and success audit.
func (s *Store) ResetLocalPassword(target PasswordResetTarget, credential TemporaryPasswordCredential, now time.Time, history int, entry model.AuditEntry, actors ...AccountManagementActor) (user *model.User, err error) {
	id, expected := target.UserID, target.ExpectedGeneration
	hash, expires := credential.Hash, credential.ExpiresAt
	err = s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		if err := guardAccountManagementActor(ctx, conn, actors, clock); err != nil {
			return err
		}
		now := clock()
		if err := guardSecurityPrincipal(ctx, conn, id); err != nil {
			return err
		}
		current, e := s.scanUser(conn.QueryRowContext(ctx, accountUserByIDQuery, id))
		if e != nil {
			return e
		}
		if current.AuthProvider != model.AuthProviderLocal {
			return ErrLocalPasswordOnly
		}
		if current.TokenGeneration != expected {
			return ErrSecurityConflict
		}
		if e = appendPasswordHistoryConn(ctx, conn, id, current.PasswordHash, current.MustChangePassword, history, now); e != nil {
			return e
		}
		if _, e = conn.ExecContext(ctx, `UPDATE users SET password_hash=?,must_change_password=1,temp_password_expires_at=?,token_generation=token_generation+1,ssh_credential_generation=ssh_credential_generation+1,updated_at=? WHERE id=?`, hash, expires.UTC().Format(sqliteTimeFormat), now.UTC().Format(sqliteTimeFormat), id); e != nil {
			return e
		}
		if e = revokePasswordAuthorityConn(ctx, conn, id, entry.UserID, now); e != nil {
			return e
		}
		if e = logAuditConn(ctx, conn, entry); e != nil {
			return e
		}
		user, e = s.scanUser(conn.QueryRowContext(ctx, accountUserByIDQuery, id))
		if e != nil {
			return e
		}
		return guardAccountManagementActor(ctx, conn, actors, clock)
	})
	return
}

func appendPasswordHistoryConn(ctx context.Context, conn *sql.Conn, id, oldHash string, temporary bool, limit int, now time.Time) error {
	// History counts prior permanent passwords; the active credential is checked
	// separately. Remove legacy seeded rows and refresh outgoing-password recency.
	if _, err := conn.ExecContext(ctx, `DELETE FROM password_history WHERE user_id=? AND password_hash=?`, id, oldHash); err != nil {
		return err
	}
	if !temporary {
		if _, err := conn.ExecContext(ctx, `INSERT INTO password_history(id,user_id,password_hash,created_at) VALUES(?,?,?,?)`, uuid.NewString(), id, oldHash, now.UTC().Format(sqliteTimeFormat)); err != nil {
			return err
		}
	}
	_, err := conn.ExecContext(ctx, `DELETE FROM password_history WHERE user_id=? AND id NOT IN(SELECT id FROM password_history WHERE user_id=? ORDER BY created_at DESC,rowid DESC LIMIT ?)`, id, id, limit)
	return err
}

func revokePasswordAuthorityConn(ctx context.Context, conn *sql.Conn, id string, actor *string, now time.Time) error {
	return revokeCredentialAuthorityConn(ctx, conn, id, actor, now, "password_changed")
}

func revokeCredentialAuthorityConn(ctx context.Context, conn *sql.Conn, id string, actor *string, now time.Time, reason string) error {
	stamp := now.UTC().Format(sqliteTimeFormat)
	queries := []struct {
		q    string
		args []any
	}{
		{`UPDATE api_tokens SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at IS NULL`, []any{stamp, stamp, id}},
		{`UPDATE sessions SET ended_at=?,end_reason=?,ended_by=?,refresh_token_sha256='' WHERE user_id=? AND ended_at IS NULL`, []any{stamp, reason, actor, id}},
		{`UPDATE application_login_anchors SET revoked_at=?,reason=? WHERE user_id=? AND revoked_at IS NULL`, []any{now.UnixMilli(), reason, id}},
		{`UPDATE application_sessions SET ended_at=?,end_reason=? WHERE user_id=? AND ended_at IS NULL`, []any{now.UnixMilli(), reason, id}},
		{`DELETE FROM application_launch_tickets WHERE user_id=?`, []any{id}},
	}
	for _, q := range queries {
		if _, err := conn.ExecContext(ctx, q.q, q.args...); err != nil {
			return err
		}
	}
	return nil
}

// ChangeLocalPassword prevents an authenticated password change from overwriting
// a concurrent reset, disable or another password change. Generation invalidates
// every outstanding recovery challenge, including replay after completion.
func (s *Store) ChangeLocalPassword(user *model.User, hash string, now time.Time, history int, requireTemporary bool, entry model.AuditEntry, authority ...PasswordChangeAuthority) (int, error) {
	var generation int
	err := s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		recheck, err := s.guardPasswordChangeAuthority(ctx, conn, user.ID, authority, clock)
		if err != nil {
			return err
		}
		now := clock()
		deadline := temporaryPasswordDeadlineRecheck(user, requireTemporary)
		if err := deadline(now); err != nil {
			return err
		}
		if err := s.changeLocalPasswordConn(ctx, conn, user, hash, now, history, requireTemporary, entry); err != nil {
			return err
		}
		if err := conn.QueryRowContext(ctx, "SELECT token_generation FROM users WHERE id=?", user.ID).Scan(&generation); err != nil {
			return err
		}
		finalNow := clock()
		if err := deadline(finalNow); err != nil {
			return err
		}
		return recheck(finalNow)
	})
	return generation, err
}

func temporaryPasswordDeadlineRecheck(user *model.User, required bool) func(time.Time) error {
	if !required {
		return func(time.Time) error { return nil }
	}
	var expires *time.Time
	if user != nil && user.TempPasswordExpiresAt != nil {
		value := *user.TempPasswordExpiresAt
		expires = &value
	}
	return func(now time.Time) error {
		if expires == nil || !now.Before(*expires) {
			return ErrTemporaryPasswordExpired
		}
		return nil
	}
}

func (s *Store) changeLocalPasswordConn(ctx context.Context, conn *sql.Conn, user *model.User, hash string, now time.Time, history int, requireTemporary bool, entry model.AuditEntry) error {
	if err := guardSecurityPrincipal(ctx, conn, user.ID); err != nil {
		return err
	}
	live, err := s.scanUser(conn.QueryRowContext(ctx, accountUserByIDQuery, user.ID))
	if err != nil {
		return err
	}
	if live.AuthProvider != model.AuthProviderLocal {
		return ErrLocalPasswordOnly
	}
	// Bind the exact pre-body/pre-hash authority, including MFA removal or
	// replacement committed before a separate token-generation revocation.
	// Initial enrollment legitimately presents an unchanged MFA=false snapshot.
	policy, err := accountManagementPolicyStrict(ctx, conn)
	if err != nil {
		return err
	}
	if !samePasswordSnapshot(live, user) || live.DisabledAt != nil || account.IsDormant(account.InputFromUser(live), now, policy.DormantDays) {
		return ErrSecurityConflict
	}
	if requireTemporary && (!live.MustChangePassword || live.TempPasswordExpiresAt == nil || !now.Before(*live.TempPasswordExpiresAt)) {
		return ErrTemporaryPasswordExpired
	}
	if err = appendPasswordHistoryConn(ctx, conn, user.ID, live.PasswordHash, live.MustChangePassword, history, now); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE users SET password_hash=?,must_change_password=0,temp_password_expires_at=NULL,token_generation=token_generation+1,ssh_credential_generation=ssh_credential_generation+1,updated_at=? WHERE id=?`, hash, now.UTC().Format(sqliteTimeFormat), user.ID); err != nil {
		return err
	}
	if err = revokePasswordAuthorityConn(ctx, conn, user.ID, entry.UserID, now); err != nil {
		return err
	}
	if err = logAuditConn(ctx, conn, entry); err != nil {
		return err
	}
	return nil
}

// PasswordChangeAuthority is captured before reading a request body. Generation
// and expiry come from the authenticated token, never from a later user read.
// Empty SessionID preserves legacy sessionless tokens and setup/recovery tokens.
type PasswordChangeAuthority struct {
	Snapshot   *model.User
	SessionID  string
	Generation int
	ExpiresAt  time.Time
}

func samePasswordSnapshot(live, original *model.User) bool {
	return original != nil && live.ID == original.ID && live.TokenGeneration == original.TokenGeneration &&
		live.SecurityRevision == original.SecurityRevision && live.PasswordHash == original.PasswordHash &&
		live.AuthProvider == original.AuthProvider && live.TOTPEnabled == original.TOTPEnabled &&
		sameString(live.TOTPSecret, original.TOTPSecret) && live.MustChangePassword == original.MustChangePassword &&
		sameTime(live.TempPasswordExpiresAt, original.TempPasswordExpiresAt)
}

func sameString(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func sameTime(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}

func (s *Store) guardPasswordChangeAuthority(ctx context.Context, conn *sql.Conn, user string, authorities []PasswordChangeAuthority, clock func() time.Time) (func(time.Time) error, error) {
	if len(authorities) == 0 {
		return func(time.Time) error { return nil }, nil
	}
	a := authorities[0]
	live, err := s.scanUser(conn.QueryRowContext(ctx, accountUserByIDQuery, user))
	if err != nil {
		return nil, err
	}
	policy, err := accountManagementPolicyStrict(ctx, conn)
	if err != nil {
		return nil, err
	}
	var sessionState *session.State
	if a.SessionID != "" {
		state, err := readLiveSession(ctx, conn, a.SessionID, user)
		if err != nil {
			return nil, err
		}
		sessionState = &state
	}
	// All durable revocation state was read under BEGIN IMMEDIATE. Re-evaluate
	// the time-dependent parts once after those reads and again immediately
	// before commit; the target's expected generation may legitimately advance
	// during a self-service password change, so the final check uses this
	// captured, writer-serialized authority state.
	recheck := func(now time.Time) error {
		if a.ExpiresAt.IsZero() || !now.Before(a.ExpiresAt) || live.TokenGeneration != a.Generation ||
			!samePasswordSnapshot(live, a.Snapshot) || live.DisabledAt != nil || account.IsDormant(account.InputFromUser(live), now, policy.DormantDays) {
			return ErrSecurityConflict
		}
		if sessionState != nil && session.Evaluate(*sessionState, now, policy) != session.VerdictOK {
			return ErrSecurityConflict
		}
		return nil
	}
	if err := recheck(clock()); err != nil {
		return nil, err
	}
	return recheck, nil
}

func guardLiveSession(ctx context.Context, conn securityQuerier, id, user string, now time.Time, policy lockout.Policy) error {
	clock := advancingClock(now)
	state, err := readLiveSession(ctx, conn, id, user)
	if err != nil {
		return err
	}
	// Session authority can expire while the final database read is blocked.
	// Sample after that read rather than accepting the caller's earlier instant.
	if session.Evaluate(state, clock(), policy) != session.VerdictOK {
		return ErrSecurityConflict
	}
	return nil
}

func readLiveSession(ctx context.Context, conn securityQuerier, id, user string) (session.State, error) {
	var kind, created, lastSeen string
	var expires, ended sql.NullString
	if err := conn.QueryRowContext(ctx, "SELECT kind,created_at,last_seen_at,expires_at,ended_at FROM sessions WHERE id=? AND user_id=?", id, user).Scan(&kind, &created, &lastSeen, &expires, &ended); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return session.State{}, ErrSecurityConflict
		}
		return session.State{}, err
	}
	if ended.Valid || parseSQLiteTimeValue(created).IsZero() || parseSQLiteTimeValue(lastSeen).IsZero() || expires.Valid && parseSQLiteTime(expires) == nil {
		return session.State{}, ErrSecurityConflict
	}
	return session.State{Kind: kind, LastSeenAt: parseSQLiteTimeValue(lastSeen), ExpiresAt: parseSQLiteTime(expires), EndedAt: parseSQLiteTime(ended)}, nil
}

// AccountManagementActor binds a privileged write to the interactive authority
// that passed middleware before hashing. Revocation during bcrypt fails closed.
type AccountManagementActor struct {
	UserID, SessionID            string
	Generation, SecurityRevision int
	ExpiresAt                    time.Time
	APITokenHash                 string
}

var ErrAccountManagementActor = errors.New("administrator authority changed; sign in again")

func (s *Store) accountManagementWrite(now time.Time, actor AccountManagementActor, fn func(context.Context, *sql.Conn, func() time.Time) error) error {
	return s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		actors := []AccountManagementActor{actor}
		if err := guardAccountManagementActor(ctx, conn, actors, clock); err != nil {
			return err
		}
		if err := fn(ctx, conn, clock); err != nil {
			return err
		}
		return guardAccountManagementActor(ctx, conn, actors, clock)
	})
}

// accountManagementPolicyStrict preserves the ordinary default-on-missing
// behavior while refusing an unavailable config store. Security
// decisions must not silently replace an operator's stricter policy merely
// because its database read failed.
func accountManagementPolicyStrict(ctx context.Context, conn *sql.Conn) (lockout.Policy, error) {
	var loadErr error
	policy := lockout.Load(func(key string) (string, error) {
		var value string
		err := conn.QueryRowContext(ctx, "SELECT value FROM _config WHERE key=?", key).Scan(&value)
		if err != nil && !errors.Is(err, sql.ErrNoRows) && loadErr == nil {
			loadErr = err
		}
		return value, err
	})
	if loadErr != nil {
		return lockout.Policy{}, loadErr
	}
	return policy, nil
}
func guardAccountManagementActor(ctx context.Context, conn *sql.Conn, actors []AccountManagementActor, clock func() time.Time) error {
	if len(actors) == 0 {
		return nil
	}
	actor := actors[0]
	var u model.User
	var disabled, activity, reactivated sql.NullString
	var created string
	var admin bool
	err := conn.QueryRowContext(ctx, `SELECT u.token_generation,u.security_revision,u.must_change_password,u.totp_enabled AND u.totp_secret IS NOT NULL,u.disabled_at,u.last_activity_at,u.reactivated_at,u.created_at,u.dormancy_exempt,EXISTS(SELECT 1 FROM user_roles r WHERE r.user_id=u.id AND r.role='admin') FROM users u WHERE u.id=?`, actor.UserID).Scan(&u.TokenGeneration, &u.SecurityRevision, &u.MustChangePassword, &u.TOTPEnabled, &disabled, &activity, &reactivated, &created, &u.DormancyExempt, &admin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAccountManagementActor
		}
		return err
	}
	u.DisabledAt = parseSQLiteTime(disabled)
	u.LastActivityAt = parseSQLiteTime(activity)
	u.ReactivatedAt = parseSQLiteTime(reactivated)
	u.CreatedAt, _ = time.Parse(sqliteTimeFormat, created)
	policy, err := accountManagementPolicyStrict(ctx, conn)
	if err != nil {
		return err
	}
	var actorSession session.State
	var apiExpires, apiRevoked sql.NullString
	var apiUser string
	if actor.APITokenHash != "" {
		err = conn.QueryRowContext(ctx, "SELECT user_id,expires_at,revoked_at FROM api_tokens WHERE token_hash=?", actor.APITokenHash).Scan(&apiUser, &apiExpires, &apiRevoked)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrAccountManagementActor
			}
			return err
		}
	}
	if actor.SessionID != "" {
		actorSession, err = readLiveSession(ctx, conn, actor.SessionID, actor.UserID)
		if err != nil {
			if errors.Is(err, ErrSecurityConflict) {
				return ErrAccountManagementActor
			}
			return err
		}
	}
	// Sample only after every authority read. Absolute and idle expiry continue
	// advancing while SQLite or a policy/session view is blocked.
	now := clock()
	if !admin || !u.TOTPEnabled || u.TokenGeneration != actor.Generation || u.SecurityRevision != actor.SecurityRevision || u.MustChangePassword || u.DisabledAt != nil || account.IsDormant(account.InputFromUser(&u), now, policy.DormantDays) || !actor.ExpiresAt.IsZero() && !now.Before(actor.ExpiresAt) {
		return ErrAccountManagementActor
	}
	if actor.APITokenHash != "" {
		expires := parseSQLiteTime(apiExpires)
		if apiUser != actor.UserID || apiRevoked.Valid || apiExpires.Valid && (expires == nil || !now.Before(*expires)) {
			return ErrAccountManagementActor
		}
	}
	if actor.SessionID != "" && session.Evaluate(actorSession, now, policy) != session.VerdictOK {
		return ErrAccountManagementActor
	}
	return nil
}
