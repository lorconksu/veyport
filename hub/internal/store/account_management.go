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
)

var ErrAccountDisabled = errors.New("account disabled; enable it separately")
var ErrLocalPasswordOnly = errors.New("password recovery is available for local accounts only")
var ErrTemporaryPasswordExpired = errors.New("temporary password expired")

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
func (s *Store) ReactivateUser(id string, now time.Time, dormantDays int, entry model.AuditEntry, actors ...AccountManagementActor) (user *model.User, changed bool, err error) {
	err = s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		if err := guardAccountManagementActor(ctx, conn, actors, now); err != nil {
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
		policy := accountManagementPolicy(ctx, conn)
		changed = account.IsDormant(account.InputFromUser(user), now, policy.DormantDays)
		if changed {
			stamp := now.UTC().Format(sqliteTimeFormat)
			if _, e = conn.ExecContext(ctx, "UPDATE users SET reactivated_at=?,updated_at=? WHERE id=?", stamp, stamp, id); e != nil {
				return e
			}
			user.ReactivatedAt = &now
		}
		detail := "{\"changed\":false}"
		if changed {
			detail = "{\"changed\":true}"
		}
		entry.Detail = &detail
		return logAuditConn(ctx, conn, entry)
	})
	return
}

// ResetLocalPassword installs one credential generation and revokes all durable
// authority in the same write transaction as its history and success audit.
func (s *Store) ResetLocalPassword(target PasswordResetTarget, credential TemporaryPasswordCredential, now time.Time, history int, entry model.AuditEntry, actors ...AccountManagementActor) (user *model.User, err error) {
	id, expected := target.UserID, target.ExpectedGeneration
	hash, expires := credential.Hash, credential.ExpiresAt
	err = s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		if err := guardAccountManagementActor(ctx, conn, actors, now); err != nil {
			return err
		}
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
		if e = appendPasswordHistoryConn(ctx, conn, id, current.PasswordHash, hash, history, now); e != nil {
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
		return e
	})
	return
}

func appendPasswordHistoryConn(ctx context.Context, conn *sql.Conn, id, oldHash, newHash string, limit int, now time.Time) error {
	// Preserve the outgoing credential even for legacy users with no history.
	if _, err := conn.ExecContext(ctx, `INSERT INTO password_history(id,user_id,password_hash,created_at) SELECT ?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM password_history WHERE user_id=? AND password_hash=?)`, uuid.NewString(), id, oldHash, now.Add(-time.Second).UTC().Format(sqliteTimeFormat), id, oldHash); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO password_history(id,user_id,password_hash,created_at) VALUES(?,?,?,?)`, uuid.NewString(), id, newHash, now.UTC().Format(sqliteTimeFormat)); err != nil {
		return err
	}
	_, err := conn.ExecContext(ctx, `DELETE FROM password_history WHERE user_id=? AND id NOT IN(SELECT id FROM password_history WHERE user_id=? ORDER BY created_at DESC,rowid DESC LIMIT ?)`, id, id, limit)
	return err
}

func revokePasswordAuthorityConn(ctx context.Context, conn *sql.Conn, id string, actor *string, now time.Time) error {
	stamp := now.UTC().Format(sqliteTimeFormat)
	queries := []struct {
		q    string
		args []any
	}{
		{`UPDATE api_tokens SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at IS NULL`, []any{stamp, stamp, id}},
		{`UPDATE sessions SET ended_at=?,end_reason='password_changed',ended_by=?,refresh_token_sha256='' WHERE user_id=? AND ended_at IS NULL`, []any{stamp, actor, id}},
		{`UPDATE application_login_anchors SET revoked_at=?,reason='password_changed' WHERE user_id=? AND revoked_at IS NULL`, []any{now.UnixMilli(), id}},
		{`UPDATE application_sessions SET ended_at=?,end_reason='password_changed' WHERE user_id=? AND ended_at IS NULL`, []any{now.UnixMilli(), id}},
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
func (s *Store) ChangeLocalPassword(user *model.User, hash string, now time.Time, history int, requireTemporary bool, entry model.AuditEntry) (int, error) {
	generation := 0
	err := s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
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
		if live.TokenGeneration != user.TokenGeneration || live.PasswordHash != user.PasswordHash || live.DisabledAt != nil {
			return ErrSecurityConflict
		}
		if requireTemporary && (!live.MustChangePassword || live.TempPasswordExpiresAt == nil || !now.Before(*live.TempPasswordExpiresAt)) {
			return ErrTemporaryPasswordExpired
		}
		if err = appendPasswordHistoryConn(ctx, conn, user.ID, live.PasswordHash, hash, history, now); err != nil {
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
		generation = live.TokenGeneration + 1
		return nil
	})
	return generation, err
}

// AccountManagementActor binds a privileged write to the interactive authority
// that passed middleware before hashing. Revocation during bcrypt fails closed.
type AccountManagementActor struct {
	UserID, SessionID            string
	Generation, SecurityRevision int
}

var ErrAccountManagementActor = errors.New("administrator authority changed; sign in again")

func accountManagementPolicy(ctx context.Context, conn *sql.Conn) lockout.Policy {
	return lockout.Load(func(key string) (string, error) {
		var value string
		err := conn.QueryRowContext(ctx, "SELECT value FROM _config WHERE key=?", key).Scan(&value)
		return value, err
	})
}
func guardAccountManagementActor(ctx context.Context, conn *sql.Conn, actors []AccountManagementActor, now time.Time) error {
	if len(actors) == 0 {
		return nil
	}
	actor := actors[0]
	var u model.User
	var disabled, activity, reactivated sql.NullString
	var created string
	var admin bool
	err := conn.QueryRowContext(ctx, `SELECT u.token_generation,u.security_revision,u.must_change_password,u.totp_enabled,u.disabled_at,u.last_activity_at,u.reactivated_at,u.created_at,u.dormancy_exempt,EXISTS(SELECT 1 FROM user_roles r WHERE r.user_id=u.id AND r.role='admin') FROM users u WHERE u.id=?`, actor.UserID).Scan(&u.TokenGeneration, &u.SecurityRevision, &u.MustChangePassword, &u.TOTPEnabled, &disabled, &activity, &reactivated, &created, &u.DormancyExempt, &admin)
	if err != nil {
		return ErrAccountManagementActor
	}
	u.DisabledAt = parseSQLiteTime(disabled)
	u.LastActivityAt = parseSQLiteTime(activity)
	u.ReactivatedAt = parseSQLiteTime(reactivated)
	u.CreatedAt, _ = time.Parse(sqliteTimeFormat, created)
	if !admin || !u.TOTPEnabled || u.TokenGeneration != actor.Generation || u.SecurityRevision != actor.SecurityRevision || u.MustChangePassword || u.DisabledAt != nil || account.IsDormant(account.InputFromUser(&u), now, accountManagementPolicy(ctx, conn).DormantDays) {
		return ErrAccountManagementActor
	}
	if actor.SessionID != "" {
		var live bool
		if err := conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sessions WHERE id=? AND user_id=? AND ended_at IS NULL AND (expires_at IS NULL OR expires_at>?))", actor.SessionID, actor.UserID, now.UTC().Format(sqliteTimeFormat)).Scan(&live); err != nil || !live {
			return ErrAccountManagementActor
		}
	}
	return nil
}
