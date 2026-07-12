package store

import (
	"database/sql"
	"fmt"

	"github.com/wyiu/veyport/hub/internal/model"
)

// SetNodeCrypto stores the node public key, encrypted KEK, and enrollment
// fingerprint for the given server.
func (s *Store) SetNodeCrypto(serverID, nodePubKeyB64, kekEncHex, enrollFingerprint string) error {
	result, err := s.db.Exec(
		`UPDATE servers SET node_pubkey = ?, node_kek_enc = ?, enroll_fingerprint = ?, updated_at = datetime('now') WHERE id = ?`,
		nodePubKeyB64, kekEncHex, enrollFingerprint, serverID,
	)
	if err != nil {
		return fmt.Errorf("set node crypto: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf(errServerNotFound)
	}
	return nil
}

// SetNodeTransportPub stores the node's X25519 transport public key (base64)
// for the given server. The column is additive (migration 020).
func (s *Store) SetNodeTransportPub(serverID, transportPubB64 string) error {
	result, err := s.db.Exec(
		`UPDATE servers SET node_transport_pubkey = ?, updated_at = datetime('now') WHERE id = ?`,
		transportPubB64, serverID,
	)
	if err != nil {
		return fmt.Errorf("set node transport pubkey: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf(errServerNotFound)
	}
	return nil
}

// GetNodeTransportPub retrieves the node's X25519 transport public key (base64)
// for the given server. Returns an empty string if the column is NULL (i.e. the
// node was enrolled before migration 020).
func (s *Store) GetNodeTransportPub(serverID string) (transportPubB64 string, err error) {
	var pub sql.NullString
	err = s.db.QueryRow(
		`SELECT node_transport_pubkey FROM servers WHERE id = ?`, serverID,
	).Scan(&pub)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf(errServerNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("get node transport pubkey: %w", err)
	}
	return pub.String, nil
}

// GetNodeCrypto retrieves the node public key, encrypted KEK, and enrollment
// fingerprint for the given server.
func (s *Store) GetNodeCrypto(serverID string) (nodePubKeyB64, kekEncHex, enrollFingerprint string, err error) {
	var pub, kek, fp sql.NullString
	err = s.db.QueryRow(
		`SELECT node_pubkey, node_kek_enc, enroll_fingerprint FROM servers WHERE id = ?`, serverID,
	).Scan(&pub, &kek, &fp)
	if err == sql.ErrNoRows {
		return "", "", "", fmt.Errorf(errServerNotFound)
	}
	if err != nil {
		return "", "", "", fmt.Errorf("get node crypto: %w", err)
	}
	return pub.String, kek.String, fp.String, nil
}

// CreateReEnrollRequest inserts a new re-enrollment request.
func (s *Store) CreateReEnrollRequest(r *model.ReEnrollRequest) error {
	_, err := s.db.Exec(
		`INSERT INTO reenroll_requests (id, server_id, requested_at, ip_address, fingerprint, status, anomaly_flags, decided_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.ServerID, r.RequestedAt, r.IPAddress, r.Fingerprint, r.Status, r.AnomalyFlags, r.DecidedBy,
	)
	if err != nil {
		return fmt.Errorf("create reenroll request: %w", err)
	}
	return nil
}

// GetReEnrollRequest retrieves a re-enrollment request by ID.
func (s *Store) GetReEnrollRequest(id string) (*model.ReEnrollRequest, error) {
	var r model.ReEnrollRequest
	var ipAddress, fingerprint, anomalyFlags, decidedBy sql.NullString
	err := s.db.QueryRow(
		`SELECT id, server_id, requested_at, ip_address, fingerprint, status, anomaly_flags, decided_by
		 FROM reenroll_requests WHERE id = ?`, id,
	).Scan(&r.ID, &r.ServerID, &r.RequestedAt, &ipAddress, &fingerprint, &r.Status, &anomalyFlags, &decidedBy)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("reenroll request not found")
	}
	if err != nil {
		return nil, fmt.Errorf("get reenroll request: %w", err)
	}
	r.IPAddress = ipAddress.String
	r.Fingerprint = fingerprint.String
	r.AnomalyFlags = anomalyFlags.String
	r.DecidedBy = decidedBy.String
	return &r, nil
}

// ListPendingReEnroll returns all re-enrollment requests with status 'pending',
// ordered by requested_at ascending.
func (s *Store) ListPendingReEnroll() ([]model.ReEnrollRequest, error) {
	rows, err := s.db.Query(
		`SELECT id, server_id, requested_at, ip_address, fingerprint, status, anomaly_flags, decided_by
		 FROM reenroll_requests WHERE status = 'pending' ORDER BY requested_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("list pending reenroll: %w", err)
	}
	defer rows.Close()

	var results []model.ReEnrollRequest
	for rows.Next() {
		var r model.ReEnrollRequest
		if err := rows.Scan(&r.ID, &r.ServerID, &r.RequestedAt, &r.IPAddress, &r.Fingerprint, &r.Status, &r.AnomalyFlags, &r.DecidedBy); err != nil {
			return nil, fmt.Errorf("scan reenroll request: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// UpdateReEnrollStatus updates the status and decided_by fields for the given
// re-enrollment request.
func (s *Store) UpdateReEnrollStatus(id, status, decidedBy string) error {
	result, err := s.db.Exec(
		`UPDATE reenroll_requests SET status = ?, decided_by = ? WHERE id = ?`,
		status, decidedBy, id,
	)
	if err != nil {
		return fmt.Errorf("update reenroll status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("reenroll request not found")
	}
	return nil
}
