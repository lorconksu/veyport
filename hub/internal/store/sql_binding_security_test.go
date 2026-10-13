package store_test

import (
	"github.com/wyiu/veyport/hub/internal/model"
	"testing"
)

func TestExecutionFiltersTreatSQLSyntaxAsData(t *testing.T) {
	s := testStore(t)
	e := protectedExecution(t, s, "sonar-execution")
	if items, total, err := s.ListExecutions(model.ExecutionFilter{Limit: 10}); err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("baseline: %v %d %d", err, total, len(items))
	}
	poison := "' OR 1=1 --"
	fs := []model.ExecutionFilter{{ActorID: poison}, {NodeID: poison}, {OSUser: poison}, {PolicyVersion: poison}, {State: poison}, {EvidenceState: poison}}
	for _, f := range fs {
		f.Limit = 10
		items, total, err := s.ListExecutions(f)
		if err != nil || total != 0 || len(items) != 0 {
			t.Fatalf("filter escaped value binding: %+v %v %d %d", f, err, total, len(items))
		}
	}
	if err := s.FinishExecution(e.ID, "admission_failed", nil, "", ""); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{-1, 0, 1, 1000000} {
		items, err := s.UnqueuedEnhancedExecutions(limit)
		if err != nil || len(items) != 1 || items[0].ID != e.ID {
			t.Fatalf("fixed columns/bound limit: %d %v %+v", limit, err, items)
		}
	}
}
