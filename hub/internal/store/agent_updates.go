package store

import (
	"encoding/json"
	"errors"
	"github.com/wyiu/veyport/hub/internal/model"
)

var ErrAgentUpdateConflict = errors.New("agent update operation changed or an update is already active")

// The public representation redacts authority; these fields are separate durable
// columns so serialization cannot accidentally discard the grant or ticket hash.
func (s *Store) CreateAgentUpdate(u model.AgentUpdate) error {
	raw, err := marshalAgentUpdate(u)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO agent_updates(id,node_id,actor_id,session_id,state,ticket_hash,expires_at,created_at,updated_at,metadata) VALUES(?,?,?,?,?,?,?,?,?,?)`, u.ID, u.NodeID, u.ActorID, u.SessionID, u.State, u.TicketHash, u.ExpiresAt, u.CreatedAt, u.UpdatedAt, string(raw))
	return err
}
func (s *Store) GetAgentUpdate(id string) (model.AgentUpdate, error) {
	return scanAgentUpdate(s.db.QueryRow("SELECT metadata,actor_id,session_id,ticket_hash FROM agent_updates WHERE id=?", id))
}
func (s *Store) LatestAgentUpdate(node string) (model.AgentUpdate, error) {
	return scanAgentUpdate(s.db.QueryRow("SELECT metadata,actor_id,session_id,ticket_hash FROM agent_updates WHERE node_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1", node))
}
func scanAgentUpdate(row rowScanner) (model.AgentUpdate, error) {
	var u model.AgentUpdate
	var raw string
	err := row.Scan(&raw, &u.ActorID, &u.SessionID, &u.TicketHash)
	if err != nil {
		return u, err
	}
	err = unmarshalAgentUpdate(raw, &u)
	return u, err
}
func (s *Store) UpdateAgentUpdate(u model.AgentUpdate, previousState string) error {
	raw, err := marshalAgentUpdate(u)
	if err != nil {
		return err
	}
	r, err := s.db.Exec(`UPDATE agent_updates SET state=?,ticket_hash=?,expires_at=?,updated_at=?,metadata=? WHERE id=? AND state=?`, u.State, u.TicketHash, u.ExpiresAt, u.UpdatedAt, string(raw), u.ID, previousState)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrAgentUpdateConflict
	}
	return nil
}
func (s *Store) ActiveAgentUpdates() ([]model.AgentUpdate, error) {
	rows, err := s.db.Query(`SELECT metadata,actor_id,session_id,ticket_hash FROM agent_updates WHERE state NOT IN ('succeeded','failed','rolled_back','expired','recovery_acknowledged') LIMIT 33`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.AgentUpdate
	for rows.Next() {
		u, err := scanAgentUpdate(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

type storedAgentUpdate struct {
	Update             model.AgentUpdate     `json:"update"`
	PreviousBootID     string                `json:"previous_boot_id"`
	ObservedBootID     string                `json:"observed_boot_id"`
	BootstrapArtifacts []model.AgentArtifact `json:"bootstrap_artifacts,omitempty"`
}

func marshalAgentUpdate(u model.AgentUpdate) ([]byte, error) {
	return json.Marshal(storedAgentUpdate{u, u.PreviousBootID, u.ObservedBootID, u.BootstrapArtifacts})
}
func unmarshalAgentUpdate(raw string, u *model.AgentUpdate) error {
	var persisted storedAgentUpdate
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil {
		return err
	}
	actor, sid, ticket := u.ActorID, u.SessionID, u.TicketHash
	*u = persisted.Update
	u.ActorID, u.SessionID, u.TicketHash = actor, sid, ticket
	u.PreviousBootID, u.ObservedBootID = persisted.PreviousBootID, persisted.ObservedBootID
	u.BootstrapArtifacts = persisted.BootstrapArtifacts
	return nil
}
func (s *Store) AgentUpdateByTicketHash(hash string) (model.AgentUpdate, error) {
	return scanAgentUpdate(s.db.QueryRow("SELECT metadata,actor_id,session_id,ticket_hash FROM agent_updates WHERE ticket_hash=? AND state='bootstrap_required'", hash))
}
