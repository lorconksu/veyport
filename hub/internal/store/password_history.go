package store

import (
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const defaultPasswordHistoryLimit = 5

func (s *Store) AddPasswordHistory(userID, passwordHash string) error {
	_, err := s.db.Exec(
		`INSERT INTO password_history (id, user_id, password_hash) VALUES (?, ?, ?)`,
		uuid.NewString(), userID, passwordHash,
	)
	if err != nil {
		return fmt.Errorf("insert password history: %w", err)
	}
	if err := s.TrimPasswordHistory(userID, defaultPasswordHistoryLimit); err != nil {
		return err
	}
	return nil
}

func (s *Store) TrimPasswordHistory(userID string, limit int) error {
	_, err := s.db.Exec(
		`DELETE FROM password_history
		 WHERE user_id = ?
		   AND id NOT IN (
		     SELECT id FROM password_history
		     WHERE user_id = ?
		     ORDER BY created_at DESC, rowid DESC
		     LIMIT ?
		   )`,
		userID, userID, limit,
	)
	if err != nil {
		return fmt.Errorf("trim password history: %w", err)
	}
	return nil
}

func (s *Store) PasswordMatchesRecent(userID, candidate string, limit int) (bool, error) {
	rows, err := s.db.Query(
		`SELECT password_hash
		 FROM password_history
		 WHERE user_id = ?
		 ORDER BY created_at DESC, rowid DESC
		 LIMIT ?`,
		userID, limit,
	)
	if err != nil {
		return false, fmt.Errorf("query password history: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var passwordHash string
		if err := rows.Scan(&passwordHash); err != nil {
			return false, fmt.Errorf("scan password history: %w", err)
		}
		if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(candidate)) == nil {
			return true, nil
		}
	}
	return false, rows.Err()
}
