package store

import (
	"database/sql"
	"fmt"
)

func (s *Store) LookupConfig(key string) (string, bool, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM _config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get config %q: %w", key, err)
	}
	return value, true, nil
}

func (s *Store) GetConfig(key string) (string, error) {
	value, ok, err := s.LookupConfig(key)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("config key %q not found", key)
	}
	return value, nil
}

func (s *Store) SetConfig(key, value string) error {
	_, err := s.db.Exec(
		"INSERT INTO _config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set config %q: %w", key, err)
	}
	return nil
}
