package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/model"
)

const configInitialSetupComplete = "initial_setup_completed"

const userSelectColumns = `id, username, email, password_hash, role, auth_provider, external_id,
        ldap_dn, ldap_username, ldap_last_sync_at, terminal_access, totp_secret, totp_enabled,
        token_generation, avatar, must_change_password, temp_password_expires_at, created_at, updated_at`

func (s *Store) CreateUser(u *model.User) error {
	if u.AuthProvider == "" {
		u.AuthProvider = model.AuthProviderLocal
	}
	if u.LDAPUsername == "" && u.AuthProvider == model.AuthProviderLDAP {
		u.LDAPUsername = u.Username
	}
	_, err := s.db.Exec(
		`INSERT INTO users (
			id, username, email, password_hash, role, auth_provider, external_id,
			ldap_dn, ldap_username, ldap_last_sync_at, terminal_access, totp_secret, totp_enabled,
			avatar, token_generation, must_change_password, temp_password_expires_at
		)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.Email, u.PasswordHash, u.Role, u.AuthProvider, u.ExternalID,
		u.LDAPDN, u.LDAPUsername, sqliteTimePtr(u.LDAPLastSyncAt), u.TerminalAccess,
		u.TOTPSecret, u.TOTPEnabled, u.Avatar, u.TokenGeneration, u.MustChangePassword,
		sqliteTimePtr(u.TempPasswordExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (s *Store) GetUserByID(id string) (*model.User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT `+userSelectColumns+` FROM users WHERE id = ?`, id,
	))
}

func (s *Store) GetUserByUsername(username string) (*model.User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT `+userSelectColumns+` FROM users WHERE username = ?`, username,
	))
}

func (s *Store) GetUserByExternalIdentity(provider model.AuthProvider, externalID string) (*model.User, error) {
	if externalID == "" {
		return nil, fmt.Errorf(errUserNotFound)
	}
	return s.scanUser(s.db.QueryRow(
		`SELECT `+userSelectColumns+` FROM users WHERE auth_provider = ? AND external_id = ?`, provider, externalID,
	))
}

func (s *Store) UpsertLDAPUser(u *model.User) (*model.User, error) {
	if err := normalizeLDAPUser(u); err != nil {
		return nil, err
	}
	existing, err := s.findExistingLDAPUser(u)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		if err := s.CreateUser(u); err != nil {
			return nil, err
		}
		return s.GetUserByID(u.ID)
	}
	if err := prepareLDAPUserUpdate(existing, u); err != nil {
		return nil, err
	}
	rotateSessions := existing.Role != u.Role || existing.TerminalAccess != u.TerminalAccess
	if err := s.updateLDAPUser(existing.ID, u); err != nil {
		return nil, err
	}
	if rotateSessions {
		if _, err := s.IncrementTokenGeneration(existing.ID); err != nil {
			return nil, fmt.Errorf("invalidate sessions after ldap attribute change: %w", err)
		}
	}
	return s.GetUserByID(existing.ID)
}

func normalizeLDAPUser(u *model.User) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.Username == "" {
		return fmt.Errorf("username is required")
	}
	if u.Email == "" {
		u.Email = u.Username + "@ldap.local"
	}
	u.AuthProvider = model.AuthProviderLDAP
	u.PasswordHash = ""
	if u.LDAPUsername == "" {
		u.LDAPUsername = u.Username
	}
	now := time.Now().UTC()
	u.LDAPLastSyncAt = &now
	return nil
}

func (s *Store) findExistingLDAPUser(u *model.User) (*model.User, error) {
	if u.ExternalID != "" {
		user, err := s.GetUserByExternalIdentity(model.AuthProviderLDAP, u.ExternalID)
		if err == nil || !isUserNotFound(err) {
			return user, err
		}
	}
	user, err := s.GetUserByUsername(u.Username)
	if err != nil && !isUserNotFound(err) {
		return nil, err
	}
	return user, nil
}

func prepareLDAPUserUpdate(existing, u *model.User) error {
	if existing.AuthProvider != model.AuthProviderLDAP {
		return fmt.Errorf("username is reserved by a local user")
	}
	if existing.ExternalID != "" && u.ExternalID != "" && existing.ExternalID != u.ExternalID {
		return fmt.Errorf("LDAP external identity mismatch")
	}
	if u.ExternalID == "" {
		u.ExternalID = existing.ExternalID
	}
	return nil
}

func (s *Store) updateLDAPUser(userID string, u *model.User) error {
	_, err := s.db.Exec(
		`UPDATE users
				 SET username = ?, email = ?, role = ?, auth_provider = ?, external_id = ?,
				     ldap_dn = ?, ldap_username = ?, ldap_last_sync_at = ?, terminal_access = ?,
			     updated_at = datetime('now')
			 WHERE id = ?`,
		u.Username, u.Email, u.Role, model.AuthProviderLDAP, u.ExternalID,
		u.LDAPDN, u.LDAPUsername, sqliteTimePtr(u.LDAPLastSyncAt), u.TerminalAccess,
		userID,
	)
	if err != nil {
		return fmt.Errorf("update ldap user: %w", err)
	}
	return nil
}

func isUserNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), errUserNotFound)
}

func (s *Store) UserCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// InitializedUserCount returns the number of users that have completed
// full setup (password + TOTP enabled).
func (s *Store) InitializedUserCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE totp_enabled = 1").Scan(&count)
	return count, err
}

// InitialSetupComplete returns true once the system has completed its first
// successful TOTP enable flow. Older installations that predate the config
// flag fall back to the historical "enabled TOTP user exists" check.
func (s *Store) InitialSetupComplete() (bool, error) {
	if value, ok, err := s.LookupConfig(configInitialSetupComplete); err != nil {
		return false, err
	} else if ok {
		return value == "true", nil
	}

	count, err := s.InitializedUserCount()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Store) MarkInitialSetupComplete() error {
	return s.SetConfig(configInitialSetupComplete, "true")
}

// DeleteIncompleteUsers removes users that registered but never finished
// TOTP setup, so the initial setup flow can be retried.
func (s *Store) DeleteIncompleteUsers() error {
	// Delete audit logs first (FK without CASCADE)
	_, err := s.db.Exec(`DELETE FROM audit_logs WHERE user_id IN
		(SELECT id FROM users WHERE totp_enabled = 0)`)
	if err != nil {
		return fmt.Errorf("delete incomplete user audit logs: %w", err)
	}
	_, err = s.db.Exec("DELETE FROM users WHERE totp_enabled = 0")
	if err != nil {
		return fmt.Errorf("delete incomplete users: %w", err)
	}
	return nil
}

func (s *Store) UpdateUserTOTP(userID string, secret *string, enabled bool) error {
	_, err := s.db.Exec(
		"UPDATE users SET totp_secret = ?, totp_enabled = ?, updated_at = datetime('now') WHERE id = ?",
		secret, enabled, userID,
	)
	if err != nil {
		return fmt.Errorf("update totp: %w", err)
	}
	return nil
}

func (s *Store) DeleteUser(userID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin delete user tx: %w", err)
	}
	defer tx.Rollback()

	// Nullify audit log references (belt-and-suspenders with ON DELETE SET NULL migration)
	if _, err := tx.Exec("UPDATE audit_logs SET user_id = NULL WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("nullify audit logs: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM notification_preferences WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("delete notification preferences: %w", err)
	}

	result, err := tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete user rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf(errUserNotFound)
	}
	return tx.Commit()
}

func (s *Store) UpdateUserRole(userID string, role model.Role) error {
	result, err := s.db.Exec(
		"UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?",
		role, userID,
	)
	if err != nil {
		return fmt.Errorf("update role: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update role rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf(errUserNotFound)
	}
	return nil
}

func (s *Store) UpdateUserAvatar(userID string, avatar *string) error {
	_, err := s.db.Exec(
		"UPDATE users SET avatar = ?, updated_at = datetime('now') WHERE id = ?",
		avatar, userID,
	)
	if err != nil {
		return fmt.Errorf("update avatar: %w", err)
	}
	return nil
}

// IncrementTokenGeneration atomically increments the user's token_generation
// and returns the new value. This prevents race conditions where a stale
// in-memory value is used after the increment.
func (s *Store) IncrementTokenGeneration(userID string) (int, error) {
	_, err := s.db.Exec(
		"UPDATE users SET token_generation = token_generation + 1, updated_at = datetime('now') WHERE id = ?",
		userID,
	)
	if err != nil {
		return 0, fmt.Errorf("increment token generation: %w", err)
	}
	var newGen int
	err = s.db.QueryRow("SELECT token_generation FROM users WHERE id = ?", userID).Scan(&newGen)
	if err != nil {
		return 0, fmt.Errorf("read token generation: %w", err)
	}
	return newGen, nil
}

func (s *Store) UpdateUserPassword(userID, passwordHash string) error {
	_, err := s.db.Exec(
		`UPDATE users
		 SET password_hash = ?, must_change_password = 0, temp_password_expires_at = NULL, updated_at = datetime('now')
		 WHERE id = ?`,
		passwordHash, userID,
	)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return nil
}

func (s *Store) SetTemporaryPasswordState(userID string, mustChange bool, expiresAt *time.Time) error {
	_, err := s.db.Exec(
		`UPDATE users
		 SET must_change_password = ?, temp_password_expires_at = ?, updated_at = datetime('now')
		 WHERE id = ?`,
		mustChange, sqliteTimePtr(expiresAt), userID,
	)
	if err != nil {
		return fmt.Errorf("set temporary password state: %w", err)
	}
	return nil
}

func (s *Store) ListUsers() ([]model.User, error) {
	rows, err := s.db.Query(
		`SELECT ` + userSelectColumns + ` FROM users ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []model.User
	for rows.Next() {
		u, err := s.scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

func (s *Store) scanUser(row *sql.Row) (*model.User, error) {
	var u model.User
	var createdAt, updatedAt string
	var ldapLastSyncAt, tempPasswordExpiresAt sql.NullString
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role,
		&u.AuthProvider, &u.ExternalID, &u.LDAPDN, &u.LDAPUsername, &ldapLastSyncAt,
		&u.TerminalAccess, &u.TOTPSecret, &u.TOTPEnabled, &u.TokenGeneration, &u.Avatar,
		&u.MustChangePassword, &tempPasswordExpiresAt, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf(errUserNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	u.CreatedAt, _ = time.Parse(sqliteTimeFormat, createdAt)
	u.UpdatedAt, _ = time.Parse(sqliteTimeFormat, updatedAt)
	if ldapLastSyncAt.Valid {
		if parsed, err := time.Parse(sqliteTimeFormat, ldapLastSyncAt.String); err == nil {
			u.LDAPLastSyncAt = &parsed
		}
	}
	if tempPasswordExpiresAt.Valid {
		if parsed, err := time.Parse(sqliteTimeFormat, tempPasswordExpiresAt.String); err == nil {
			u.TempPasswordExpiresAt = &parsed
		}
	}
	return &u, nil
}

func (s *Store) scanUserRow(rows *sql.Rows) (*model.User, error) {
	var u model.User
	var createdAt, updatedAt string
	var ldapLastSyncAt, tempPasswordExpiresAt sql.NullString
	err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role,
		&u.AuthProvider, &u.ExternalID, &u.LDAPDN, &u.LDAPUsername, &ldapLastSyncAt,
		&u.TerminalAccess, &u.TOTPSecret, &u.TOTPEnabled, &u.TokenGeneration, &u.Avatar,
		&u.MustChangePassword, &tempPasswordExpiresAt, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("scan user row: %w", err)
	}
	u.CreatedAt, _ = time.Parse(sqliteTimeFormat, createdAt)
	u.UpdatedAt, _ = time.Parse(sqliteTimeFormat, updatedAt)
	if ldapLastSyncAt.Valid {
		if parsed, err := time.Parse(sqliteTimeFormat, ldapLastSyncAt.String); err == nil {
			u.LDAPLastSyncAt = &parsed
		}
	}
	if tempPasswordExpiresAt.Valid {
		if parsed, err := time.Parse(sqliteTimeFormat, tempPasswordExpiresAt.String); err == nil {
			u.TempPasswordExpiresAt = &parsed
		}
	}
	return &u, nil
}
