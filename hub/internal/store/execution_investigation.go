package store

import (
	"errors"
	"strings"

	"github.com/wyiu/veyport/hub/internal/model"
)

// ListExecutions uses one bounded metadata query. Every filter value is bound;
// no raw command, script or output column exists in this table.
func (s *Store) ListExecutions(f model.ExecutionFilter) ([]model.Execution, int, error) {
	if f.Limit < 1 || f.Limit > 100 || f.Offset < 0 || f.Offset > 1000000 {
		return nil, 0, errors.New("bounded execution pagination required")
	}
	clauses := []string{"1=1"}
	args := []any{}
	for _, filter := range []struct{ column, value string }{{"actor_id", f.ActorID}, {"node_id", f.NodeID}, {"json_extract(preparation,'$.identity.username')", f.OSUser}, {"policy_version", f.PolicyVersion}, {"state", f.State}, {"evidence_state", f.EvidenceState}} {
		if filter.value != "" {
			if len(filter.value) > 256 {
				return nil, 0, errors.New("bounded execution filter required")
			}
			clauses = append(clauses, filter.column+"=?")
			args = append(args, filter.value)
		}
	}
	where := strings.Join(clauses, " AND ")
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM executions WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query("SELECT "+executionColumns+" FROM executions WHERE "+where+" ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?", append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []model.Execution{}
	for rows.Next() {
		e, err := scanExecution(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *e)
	}
	return items, total, rows.Err()
}
