package store

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/wyiu/aerodocs/hub/internal/model"
)

func (s *Store) CreateAPIToken(token *model.APIToken) error {
	_, err := s.db.Exec(
		`INSERT INTO api_tokens (
			id, user_id, name, token_hash, token_prefix, expires_at, last_used_at, revoked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		token.ID,
		token.UserID,
		token.Name,
		token.TokenHash,
		token.TokenPrefix,
		sqliteTimePtr(token.ExpiresAt),
		sqliteTimePtr(token.LastUsedAt),
		sqliteTimePtr(token.RevokedAt),
	)
	if err != nil {
		return fmt.Errorf("create api token: %w", err)
	}
	return nil
}

func (s *Store) GetActiveAPITokenByHash(tokenHash string) (*model.APIToken, error) {
	return scanAPIToken(s.db.QueryRow(
		`SELECT id, user_id, name, token_hash, token_prefix, expires_at, last_used_at,
		        revoked_at, created_at, updated_at
		 FROM api_tokens
		 WHERE token_hash = ?
		   AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > datetime('now'))`,
		tokenHash,
	))
}

func (s *Store) ListAPITokensByUserID(userID string) ([]model.APIToken, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, token_hash, token_prefix, expires_at, last_used_at,
		        revoked_at, created_at, updated_at
		 FROM api_tokens
		 WHERE user_id = ?
		 ORDER BY created_at ASC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()

	var tokens []model.APIToken
	for rows.Next() {
		token, err := scanAPITokenRow(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, *token)
	}
	return tokens, rows.Err()
}

func (s *Store) UpdateAPITokenLastUsed(tokenID string, usedAt time.Time) error {
	_, err := s.db.Exec(
		`UPDATE api_tokens
		 SET last_used_at = ?, updated_at = datetime('now')
		 WHERE id = ?`,
		usedAt.UTC().Format(sqliteTimeFormat), tokenID,
	)
	if err != nil {
		return fmt.Errorf("update api token last used: %w", err)
	}
	return nil
}

func (s *Store) RevokeAllAPITokensByUserID(userID string) error {
	_, err := s.db.Exec(
		`UPDATE api_tokens
		 SET revoked_at = datetime('now'), updated_at = datetime('now')
		 WHERE user_id = ? AND revoked_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("revoke all api tokens: %w", err)
	}
	return nil
}

func (s *Store) RevokeAPIToken(tokenID string) error {
	result, err := s.db.Exec(
		`UPDATE api_tokens
		 SET revoked_at = datetime('now'), updated_at = datetime('now')
		 WHERE id = ? AND revoked_at IS NULL`,
		tokenID,
	)
	if err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke api token rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf(errAPITokenNotFound)
	}
	return nil
}

func scanAPIToken(row *sql.Row) (*model.APIToken, error) {
	var token model.APIToken
	var expiresAt, lastUsedAt, revokedAt sql.NullString
	var createdAt, updatedAt string
	err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.Name,
		&token.TokenHash,
		&token.TokenPrefix,
		&expiresAt,
		&lastUsedAt,
		&revokedAt,
		&createdAt,
		&updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf(errAPITokenNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("scan api token: %w", err)
	}
	parseAPITokenTimes(&token, expiresAt, lastUsedAt, revokedAt, createdAt, updatedAt)
	return &token, nil
}

func scanAPITokenRow(rows *sql.Rows) (*model.APIToken, error) {
	var token model.APIToken
	var expiresAt, lastUsedAt, revokedAt sql.NullString
	var createdAt, updatedAt string
	if err := rows.Scan(
		&token.ID,
		&token.UserID,
		&token.Name,
		&token.TokenHash,
		&token.TokenPrefix,
		&expiresAt,
		&lastUsedAt,
		&revokedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, fmt.Errorf("scan api token row: %w", err)
	}
	parseAPITokenTimes(&token, expiresAt, lastUsedAt, revokedAt, createdAt, updatedAt)
	return &token, nil
}

func parseAPITokenTimes(token *model.APIToken, expiresAt, lastUsedAt, revokedAt sql.NullString, createdAt, updatedAt string) {
	token.CreatedAt, _ = time.Parse(sqliteTimeFormat, createdAt)
	token.UpdatedAt, _ = time.Parse(sqliteTimeFormat, updatedAt)
	if expiresAt.Valid {
		if parsed, err := time.Parse(sqliteTimeFormat, expiresAt.String); err == nil {
			token.ExpiresAt = &parsed
		}
	}
	if lastUsedAt.Valid {
		if parsed, err := time.Parse(sqliteTimeFormat, lastUsedAt.String); err == nil {
			token.LastUsedAt = &parsed
		}
	}
	if revokedAt.Valid {
		if parsed, err := time.Parse(sqliteTimeFormat, revokedAt.String); err == nil {
			token.RevokedAt = &parsed
		}
	}
}
