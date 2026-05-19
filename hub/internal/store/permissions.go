package store

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

func (s *Store) CreatePermission(userID, serverID, path string) (*model.Permission, error) {
	id := uuid.NewString()
	_, err := s.db.Exec(
		"INSERT INTO permissions (id, user_id, server_id, path) VALUES (?, ?, ?, ?)",
		id, userID, serverID, path,
	)
	if err != nil {
		return nil, fmt.Errorf("create permission: %w", err)
	}
	return s.GetPermissionByID(id)
}

func (s *Store) GetPermissionByID(id string) (*model.Permission, error) {
	var p model.Permission
	err := s.db.QueryRow(
		`SELECT p.id, p.user_id, u.username, p.server_id, p.path, p.created_at
		 FROM permissions p JOIN users u ON p.user_id = u.id WHERE p.id = ?`, id,
	).Scan(&p.ID, &p.UserID, &p.Username, &p.ServerID, &p.Path, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get permission: %w", err)
	}
	return &p, nil
}

func (s *Store) ListPermissionsForServer(serverID string) ([]model.Permission, error) {
	rows, err := s.db.Query(
		`SELECT p.id, p.user_id, u.username, p.server_id, p.path, p.created_at
		 FROM permissions p JOIN users u ON p.user_id = u.id WHERE p.server_id = ? ORDER BY u.username, p.path`, serverID,
	)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	defer rows.Close()

	var perms []model.Permission
	for rows.Next() {
		var p model.Permission
		if err := rows.Scan(&p.ID, &p.UserID, &p.Username, &p.ServerID, &p.Path, &p.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

func (s *Store) GetUserPathsForServer(userID, serverID string) ([]string, error) {
	rows, err := s.db.Query(
		"SELECT path FROM permissions WHERE user_id = ? AND server_id = ?", userID, serverID,
	)
	if err != nil {
		return nil, fmt.Errorf("get user paths: %w", err)
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, rows.Err()
}

// GetExclusiveServerAccess returns server IDs where the given user is the ONLY user with permissions.
func (s *Store) GetExclusiveServerAccess(userID string) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT p1.server_id
		FROM permissions p1
		WHERE p1.user_id = ?
		AND NOT EXISTS (
			SELECT 1 FROM permissions p2
			WHERE p2.server_id = p1.server_id AND p2.user_id != ?
		)`, userID, userID)
	if err != nil {
		return nil, fmt.Errorf("get exclusive server access: %w", err)
	}
	defer rows.Close()

	var serverIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		serverIDs = append(serverIDs, id)
	}
	return serverIDs, rows.Err()
}

func (s *Store) DeletePermission(id string) error {
	result, err := s.db.Exec("DELETE FROM permissions WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete permission: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("permission not found")
	}
	return nil
}
