package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

func auditDetail(value any) *string {
	raw, _ := json.Marshal(value)
	detail := string(raw)
	return &detail
}

func (s *Store) UpdateUserRoleAudited(userID string, role model.Role, now time.Time, roleEntry, exemptionEntry model.AuditEntry, actor AccountManagementActor) (user *model.User, exemptionCleared bool, err error) {
	err = s.accountManagementWrite(now, actor, func(ctx context.Context, conn *sql.Conn, _ func() time.Time) error {
		if err := guardSecurityPrincipal(ctx, conn, userID); err != nil {
			return err
		}
		previous, err := s.scanUser(conn.QueryRowContext(ctx, accountUserByIDQuery, userID))
		if err != nil {
			return err
		}
		exemptionCleared = previous.DormancyExempt && role != model.RoleAdmin
		result, err := conn.ExecContext(ctx, `UPDATE users
 SET role=?,dormancy_exempt=CASE WHEN ?='admin' THEN dormancy_exempt ELSE 0 END,
 token_generation=token_generation+1,updated_at=datetime('now') WHERE id=?`, role, role, userID)
		if err != nil {
			return fmt.Errorf("update role: %w", err)
		}
		if rows, err := result.RowsAffected(); err != nil || rows != 1 {
			if err != nil {
				return err
			}
			return fmt.Errorf(errUserNotFound)
		}
		if err := logAuditConn(ctx, conn, roleEntry); err != nil {
			return err
		}
		if exemptionCleared {
			if err := logAuditConn(ctx, conn, exemptionEntry); err != nil {
				return err
			}
		}
		user, err = s.scanUser(conn.QueryRowContext(ctx, accountUserByIDQuery, userID))
		return err
	})
	if err != nil {
		user, exemptionCleared = nil, false
	}
	return
}

func (s *Store) DeleteUserAudited(userID string, now time.Time, entry model.AuditEntry, actor AccountManagementActor) error {
	return s.accountManagementWrite(now, actor, func(ctx context.Context, conn *sql.Conn, _ func() time.Time) error {
		if err := guardSecurityPrincipal(ctx, conn, userID); err != nil {
			return err
		}
		var exists bool
		if err := conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=?)", userID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf(errUserNotFound)
		}
		if _, err := conn.ExecContext(ctx, "UPDATE audit_logs SET user_id=NULL WHERE user_id=?", userID); err != nil {
			return fmt.Errorf("nullify audit logs: %w", err)
		}
		for _, query := range []string{
			"DELETE FROM security_identity_links WHERE user_id=?",
			"DELETE FROM notification_preferences WHERE user_id=?",
			"DELETE FROM notification_log WHERE user_id=?",
			"DELETE FROM api_tokens WHERE user_id=?",
			"DELETE FROM permissions WHERE user_id=?",
			"DELETE FROM password_history WHERE user_id=?",
			"DELETE FROM audit_saved_filters WHERE created_by=?",
			"DELETE FROM audit_reviews WHERE reviewer_id=?",
			"DELETE FROM audit_flags WHERE created_by=?",
		} {
			if _, err := conn.ExecContext(ctx, query, userID); err != nil {
				return fmt.Errorf("cleanup %s: %w", query, err)
			}
		}
		result, err := conn.ExecContext(ctx, "DELETE FROM users WHERE id=?", userID)
		if err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
		if rows, err := result.RowsAffected(); err != nil || rows != 1 {
			if err != nil {
				return err
			}
			return fmt.Errorf(errUserNotFound)
		}
		return logAuditConn(ctx, conn, entry)
	})
}

type DisableUserResult struct {
	RevokedAPITokens int
	EndedSessionIDs  []string
}

func (s *Store) DisableUserAudited(userID, byID string, now time.Time, entry model.AuditEntry, actor AccountManagementActor) (out DisableUserResult, err error) {
	err = s.accountManagementWrite(now, actor, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		// Disabling a protected security principal is intentionally allowed: it
		// is the immediate revocation path used to invalidate an approver while
		// a governed change is in flight. Other account mutations still require
		// the governed security-change workflow.
		var role model.Role
		var disabled sql.NullString
		if err := conn.QueryRowContext(ctx, "SELECT role,disabled_at FROM users WHERE id=?", userID).Scan(&role, &disabled); err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf(errUserNotFound)
			}
			return err
		}
		stamp := clock().UTC().Format(sqliteTimeFormat)
		if !disabled.Valid {
			if role == model.RoleAdmin {
				var others int
				if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role=? AND disabled_at IS NULL AND id!=?", model.RoleAdmin, userID).Scan(&others); err != nil {
					return err
				}
				if others == 0 {
					return ErrLastAdmin
				}
			}
			if _, err := conn.ExecContext(ctx, `UPDATE users SET disabled_at=?,disabled_by=?,token_generation=token_generation+1,ssh_credential_generation=ssh_credential_generation+1,updated_at=? WHERE id=? AND disabled_at IS NULL`, stamp, byID, stamp, userID); err != nil {
				return err
			}
			result, err := conn.ExecContext(ctx, "UPDATE api_tokens SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at IS NULL", stamp, stamp, userID)
			if err != nil {
				return err
			}
			rows, err := result.RowsAffected()
			if err != nil {
				return err
			}
			out.RevokedAPITokens = int(rows)
		}

		rows, err := conn.QueryContext(ctx, "SELECT id FROM sessions WHERE user_id=? AND ended_at IS NULL", userID)
		if err != nil {
			return fmt.Errorf("select live sessions: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("scan live session id: %w", err)
			}
			out.EndedSessionIDs = append(out.EndedSessionIDs, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate live sessions: %w", err)
		}
		rows.Close()
		for _, id := range out.EndedSessionIDs {
			if _, err := conn.ExecContext(ctx, `UPDATE sessions SET ended_at=?,end_reason=?,ended_by=? WHERE id=? AND ended_at IS NULL`, stamp, model.SessionEndRevokedDisable, byID, id); err != nil {
				return fmt.Errorf("end disabled user session: %w", err)
			}
		}
		entry.Detail = auditDetail(struct {
			RevokedAPITokens int `json:"revoked_api_tokens"`
			EndedSessions    int `json:"ended_sessions"`
		}{RevokedAPITokens: out.RevokedAPITokens, EndedSessions: len(out.EndedSessionIDs)})
		return logAuditConn(ctx, conn, entry)
	})
	if err != nil {
		out = DisableUserResult{}
	}
	return
}

func (s *Store) EnableUserAudited(userID string, now time.Time, entry model.AuditEntry, actor AccountManagementActor) (wasDisabled bool, err error) {
	err = s.accountManagementWrite(now, actor, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		if err := guardSecurityPrincipal(ctx, conn, userID); err != nil {
			return err
		}
		var disabled sql.NullString
		if err := conn.QueryRowContext(ctx, "SELECT disabled_at FROM users WHERE id=?", userID).Scan(&disabled); err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf(errUserNotFound)
			}
			return err
		}
		wasDisabled = disabled.Valid
		stamp := clock().UTC().Format(sqliteTimeFormat)
		if _, err := conn.ExecContext(ctx, `UPDATE users SET disabled_at=NULL,disabled_by=NULL,locked_until=NULL,failed_login_count=0,reactivated_at=CASE WHEN disabled_at IS NOT NULL THEN ? ELSE reactivated_at END,updated_at=? WHERE id=?`, stamp, stamp, userID); err != nil {
			return err
		}
		entry.Detail = auditDetail(struct {
			WasDisabled bool `json:"was_disabled"`
		}{wasDisabled})
		return logAuditConn(ctx, conn, entry)
	})
	if err != nil {
		wasDisabled = false
	}
	return
}

func (s *Store) UnlockUserAudited(userID string, now time.Time, entry model.AuditEntry, actor AccountManagementActor) (wasLocked bool, err error) {
	err = s.accountManagementWrite(now, actor, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		if err := guardSecurityPrincipal(ctx, conn, userID); err != nil {
			return err
		}
		var locked sql.NullString
		if err := conn.QueryRowContext(ctx, "SELECT locked_until FROM users WHERE id=?", userID).Scan(&locked); err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf(errUserNotFound)
			}
			return err
		}
		current := clock()
		if until := parseSQLiteTime(locked); until != nil && until.After(current.UTC()) {
			wasLocked = true
		}
		var reactivated any
		if wasLocked {
			reactivated = current.UTC().Format(sqliteTimeFormat)
		}
		if _, err := conn.ExecContext(ctx, `UPDATE users SET locked_until=NULL,failed_login_count=0,reactivated_at=COALESCE(?,reactivated_at),updated_at=? WHERE id=?`, reactivated, current.UTC().Format(sqliteTimeFormat), userID); err != nil {
			return err
		}
		entry.Detail = auditDetail(struct {
			WasLocked bool `json:"was_locked"`
		}{wasLocked})
		return logAuditConn(ctx, conn, entry)
	})
	if err != nil {
		wasLocked = false
	}
	return
}

func (s *Store) SetDormancyExemptAudited(userID string, exempt bool, now time.Time, entry model.AuditEntry, actor AccountManagementActor) error {
	return s.accountManagementWrite(now, actor, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		if err := guardSecurityPrincipal(ctx, conn, userID); err != nil {
			return err
		}
		result, err := conn.ExecContext(ctx, "UPDATE users SET dormancy_exempt=?,updated_at=? WHERE id=? AND role=?", exempt, clock().UTC().Format(sqliteTimeFormat), userID, model.RoleAdmin)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			var role model.Role
			if err := conn.QueryRowContext(ctx, "SELECT role FROM users WHERE id=?", userID).Scan(&role); err != nil {
				if err == sql.ErrNoRows {
					return fmt.Errorf(errUserNotFound)
				}
				return err
			}
			return ErrNotAdmin
		}
		return logAuditConn(ctx, conn, entry)
	})
}
