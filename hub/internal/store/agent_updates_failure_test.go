package store_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestAgentUpdateStoreRejectsCorruptAuthorityMetadata(t *testing.T) {
	s := testStore(t)
	op := model.AgentUpdate{ID: "corrupt-operation", NodeID: "node", State: "installing", ActorID: "admin", SessionID: "session"}
	if err := s.CreateAgentUpdate(op); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec("UPDATE agent_updates SET metadata='invalid-json' WHERE id=?", op.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAgentUpdate(op.ID); err == nil {
		t.Fatal("corrupt durable authority was decoded")
	}
	if _, err := s.ActiveAgentUpdates(); err == nil {
		t.Fatal("startup omitted corrupt active authority instead of refusing")
	}
}

func TestAgentUpdateStoreFailedTransitionRetainsAuthorityAndTicketUniqueness(t *testing.T) {
	s := testStore(t)
	op := model.AgentUpdate{ID: "state-one", NodeID: "node-one", State: "bootstrap_required", ActorID: "admin", SessionID: "session", TicketHash: strings.Repeat("a", 64)}
	if err := s.CreateAgentUpdate(op); err != nil {
		t.Fatal(err)
	}
	duplicate := op
	duplicate.ID = "state-two"
	duplicate.NodeID = "node-two"
	if err := s.CreateAgentUpdate(duplicate); err == nil {
		t.Fatal("one ticket hash bound two nodes")
	}
	if _, err := s.DB().Exec(`CREATE TRIGGER deny_agent_update_state BEFORE UPDATE ON agent_updates BEGIN SELECT RAISE(ABORT,'durable state unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	changed := op
	changed.State = "requested"
	changed.TicketHash = ""
	if err := s.UpdateAgentUpdate(changed, op.State); err == nil {
		t.Fatal("failed durable transition returned success")
	}
	got, err := s.AgentUpdateByTicketHash(op.TicketHash)
	if err != nil || got.State != op.State || got.SessionID != op.SessionID {
		t.Fatal("failed transition consumed or changed authority", got, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ActiveAgentUpdates(); err == nil {
		t.Fatal("unavailable durable store was treated as no active operations")
	}
	if err = s.UpdateAgentUpdate(changed, op.State); err == nil {
		t.Fatal("unavailable durable store accepted transition")
	}
}

func TestAgentUpdateQueriesBindQuotedIdentifiersAndLatestTieOrder(t *testing.T) {
	s := testStore(t)
	first := model.AgentUpdate{ID: "op' OR 1=1--", NodeID: "node' OR 1=1--", State: "bootstrap_required", TicketHash: "ticket' OR 1=1--", ActorID: "owner", SessionID: "session", CreatedAt: 100}
	if err := s.CreateAgentUpdate(first); err != nil {
		t.Fatal(err)
	}
	for _, query := range []func() (model.AgentUpdate, error){func() (model.AgentUpdate, error) { return s.GetAgentUpdate(first.ID) }, func() (model.AgentUpdate, error) { return s.LatestAgentUpdate(first.NodeID) }, func() (model.AgentUpdate, error) { return s.AgentUpdateByTicketHash(first.TicketHash) }} {
		got, err := query()
		if err != nil || got.ID != first.ID || got.ActorID != first.ActorID || got.SessionID != first.SessionID {
			t.Fatal("literal query did not retain exact quoted binding/authority", got, err)
		}
	}
	for _, query := range []func() (model.AgentUpdate, error){func() (model.AgentUpdate, error) { return s.GetAgentUpdate("' OR 1=1--") }, func() (model.AgentUpdate, error) { return s.LatestAgentUpdate("' OR 1=1--") }, func() (model.AgentUpdate, error) { return s.AgentUpdateByTicketHash("' OR 1=1--") }} {
		if _, err := query(); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("identifier escaped SQL parameter binding", err)
		}
	}
	first.State = "expired"
	first.TicketHash = ""
	if err := s.UpdateAgentUpdate(first, "bootstrap_required"); err != nil {
		t.Fatal(err)
	}
	latest := first
	latest.ID = "newer-same-timestamp"
	latest.State = "requested"
	if err := s.CreateAgentUpdate(latest); err != nil {
		t.Fatal(err)
	}
	got, err := s.LatestAgentUpdate(first.NodeID)
	if err != nil || got.ID != latest.ID {
		t.Fatal("same-timestamp operation lookup returned earlier authority", got, err)
	}
}
