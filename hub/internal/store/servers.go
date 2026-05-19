package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

func (s *Store) CreateServer(srv *model.Server) error {
	_, err := s.db.Exec(
		`INSERT INTO servers (id, name, hostname, ip_address, os, status, registration_token, token_expires_at, agent_version, labels)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		srv.ID, srv.Name, srv.Hostname, srv.IPAddress, srv.OS, srv.Status,
		srv.RegistrationToken, srv.TokenExpiresAt, srv.AgentVersion, srv.Labels,
	)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}
	return nil
}

func (s *Store) GetServerByID(id string) (*model.Server, error) {
	return s.scanServer(s.db.QueryRow(
		`SELECT id, name, hostname, ip_address, os, status, registration_token, token_expires_at,
		        agent_version, labels, last_seen_at, created_at, updated_at
		 FROM servers WHERE id = ?`, id,
	))
}

func (s *Store) ListServers(filter model.ServerFilter) ([]model.Server, int, error) {
	qb := newQueryBuilder(`SELECT id, name, hostname, ip_address, os, status, registration_token, token_expires_at,
	                 agent_version, labels, last_seen_at, created_at, updated_at
	          FROM servers`)

	if filter.Status != nil {
		qb.Where("status = ?", *filter.Status)
	}
	if filter.Search != nil {
		qb.Where("name LIKE ?", "%"+*filter.Search+"%")
	}

	// Get total count
	var total int
	countQuery, countArgs := qb.CountQuery("servers")
	if err := s.db.QueryRow(countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count servers: %w", err)
	}

	// Get paginated results
	qb.OrderBy("created_at DESC")
	if filter.Limit > 0 {
		qb.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		qb.Offset(filter.Offset)
	}
	query, args := qb.Build()

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query servers: %w", err)
	}
	defer rows.Close()

	var servers []model.Server
	for rows.Next() {
		srv, err := s.scanServerRow(rows)
		if err != nil {
			return nil, 0, err
		}
		servers = append(servers, *srv)
	}

	return servers, total, rows.Err()
}

func (s *Store) ListServersForUser(userID string, filter model.ServerFilter) ([]model.Server, int, error) {
	// Safe: all user inputs are parameterized via queryBuilder.Build() // NOSONAR
	qb := newQueryBuilder("")
	// The JOIN condition on user_id is the first WHERE-like arg.
	qb.Where("p.user_id = ?", userID)
	if filter.Status != nil {
		qb.Where("servers.status = ?", *filter.Status)
	}
	if filter.Search != nil {
		qb.Where("servers.name LIKE ?", "%"+*filter.Search+"%")
	}

	// Build the WHERE clause using BuildWhereClause to avoid string concatenation hotspot.
	whereSQL, allArgs := qb.BuildWhereClause()

	const joinClause = " INNER JOIN permissions p ON servers.id = p.server_id"

	// Get total count
	var total int
	countQuery := "SELECT COUNT(DISTINCT servers.id) FROM servers" + joinClause + whereSQL
	if err := s.db.QueryRow(countQuery, allArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count servers for user: %w", err)
	}

	// Get paginated results
	query := `SELECT DISTINCT servers.id, servers.name, servers.hostname, servers.ip_address,
	                 servers.os, servers.status, servers.registration_token, servers.token_expires_at,
	                 servers.agent_version, servers.labels, servers.last_seen_at,
	                 servers.created_at, servers.updated_at
	          FROM servers` + joinClause + whereSQL + " ORDER BY servers.created_at DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		allArgs = append(allArgs, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		allArgs = append(allArgs, filter.Offset)
	}

	rows, err := s.db.Query(query, allArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query servers for user: %w", err)
	}
	defer rows.Close()

	var servers []model.Server
	for rows.Next() {
		srv, err := s.scanServerRow(rows)
		if err != nil {
			return nil, 0, err
		}
		servers = append(servers, *srv)
	}

	return servers, total, rows.Err()
}

func (s *Store) UpdateServer(id, name, labels string) error {
	result, err := s.db.Exec(
		"UPDATE servers SET name = ?, labels = ?, updated_at = datetime('now') WHERE id = ?",
		name, labels, id,
	)
	if err != nil {
		return fmt.Errorf("update server: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf(errServerNotFound)
	}
	return nil
}

func (s *Store) DeleteServer(id string) error {
	result, err := s.db.Exec("DELETE FROM servers WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete server: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf(errServerNotFound)
	}
	return nil
}

func (s *Store) DeleteServers(ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	values := make([]interface{}, len(ids))
	for i, id := range ids {
		values[i] = id
	}

	qb := newQueryBuilder("DELETE FROM servers")
	qb.WhereIn("id", values)
	query, args := qb.Build()

	_, err := s.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("batch delete servers: %w", err)
	}
	return nil
}

func (s *Store) GetServerByName(name string) (*model.Server, error) {
	return s.scanServer(s.db.QueryRow(
		`SELECT id, name, hostname, ip_address, os, status, registration_token, token_expires_at,
		        agent_version, labels, last_seen_at, created_at, updated_at
		 FROM servers WHERE name = ?`, name,
	))
}

func (s *Store) GetServerByToken(tokenHash string) (*model.Server, error) {
	return s.scanServer(s.db.QueryRow(
		`SELECT id, name, hostname, ip_address, os, status, registration_token, token_expires_at,
		        agent_version, labels, last_seen_at, created_at, updated_at
		 FROM servers WHERE registration_token = ?`, tokenHash,
	))
}

func (s *Store) ActivateServer(id, hostname, ip, os, agentVersion string) error {
	now := time.Now().UTC().Format(sqliteTimeFormat)
	result, err := s.db.Exec(
		`UPDATE servers
		 SET hostname = ?, ip_address = ?, os = ?, agent_version = ?,
		     status = 'pending', registration_token = NULL, token_expires_at = NULL,
		     last_seen_at = ?, updated_at = datetime('now')
		 WHERE id = ?`,
		hostname, ip, os, agentVersion, now, id,
	)
	if err != nil {
		return fmt.Errorf("activate server: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf(errServerNotFound)
	}
	return nil
}

func (s *Store) UpdateServerStatus(id, status string) error {
	result, err := s.db.Exec(
		"UPDATE servers SET status = ?, updated_at = datetime('now') WHERE id = ?",
		status, id,
	)
	if err != nil {
		return fmt.Errorf("update server status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf(errServerNotFound)
	}
	return nil
}

func (s *Store) UpdateServerIP(id, ip string) error {
	_, err := s.db.Exec(
		"UPDATE servers SET ip_address = ?, updated_at = datetime('now') WHERE id = ?",
		ip, id,
	)
	if err != nil {
		return fmt.Errorf("update server ip: %w", err)
	}
	return nil
}

func (s *Store) UpdateServerLastSeen(id string, systemInfo *model.SystemInfo) error {
	now := time.Now().UTC().Format(sqliteTimeFormat)
	result, err := s.db.Exec(
		"UPDATE servers SET last_seen_at = ?, updated_at = datetime('now') WHERE id = ?",
		now, id,
	)
	if err != nil {
		return fmt.Errorf("update server last seen: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf(errServerNotFound)
	}
	return nil
}

func (s *Store) SetServerIP(id, ip string) error {
	_, err := s.db.Exec(
		"UPDATE servers SET ip_address = ?, updated_at = datetime('now') WHERE id = ?",
		ip, id,
	)
	return err
}

func (s *Store) GetOnlineServersNotIn(activeIDs []string) ([]model.Server, error) {
	query := `SELECT id, name, hostname, ip_address, os, status, registration_token, token_expires_at,
	                 agent_version, labels, last_seen_at, created_at, updated_at
	          FROM servers WHERE status = 'online'`
	var args []interface{}
	if len(activeIDs) > 0 {
		placeholders := make([]string, len(activeIDs))
		for i, id := range activeIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		query += " AND id NOT IN (" + strings.Join(placeholders, ",") + ")"
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query stale servers: %w", err)
	}
	defer rows.Close()
	var servers []model.Server
	for rows.Next() {
		srv, err := s.scanServerRow(rows)
		if err != nil {
			return nil, err
		}
		servers = append(servers, *srv)
	}
	return servers, rows.Err()
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

// scanServerFields scans server columns from any rowScanner into a model.Server.
func scanServerFields(sc rowScanner) (*model.Server, error) {
	var srv model.Server
	var createdAt, updatedAt string
	if err := sc.Scan(
		&srv.ID, &srv.Name, &srv.Hostname, &srv.IPAddress, &srv.OS, &srv.Status,
		&srv.RegistrationToken, &srv.TokenExpiresAt,
		&srv.AgentVersion, &srv.Labels, &srv.LastSeenAt, &createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	srv.CreatedAt, _ = time.Parse(sqliteTimeFormat, createdAt)
	srv.UpdatedAt, _ = time.Parse(sqliteTimeFormat, updatedAt)
	return &srv, nil
}

func (s *Store) scanServer(row *sql.Row) (*model.Server, error) {
	srv, err := scanServerFields(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf(errServerNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("scan server: %w", err)
	}
	return srv, nil
}

func (s *Store) scanServerRow(rows *sql.Rows) (*model.Server, error) {
	srv, err := scanServerFields(rows)
	if err != nil {
		return nil, fmt.Errorf("scan server row: %w", err)
	}
	return srv, nil
}
