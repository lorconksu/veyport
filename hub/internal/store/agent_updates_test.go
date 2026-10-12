package store_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestAgentUpdateStoreDurableAuthorityCASAndRecoveryIndex(t *testing.T) {
	s := testStore(t)
	op := model.AgentUpdate{ID: "update-one", NodeID: "node", ActorID: "admin", SessionID: "session", State: "bootstrap_required", Target: model.AgentArtifact{Version: "2.0.1", SHA256: strings.Repeat("a", 64)}, TicketHash: strings.Repeat("b", 64), PreviousBootID: "original-boot", ObservedBootID: "observed-boot", CreatedAt: 1, ExpiresAt: 2, BootstrapArtifacts: []model.AgentArtifact{{OS: "linux", Arch: "arm64", Version: "2.0.1", SHA256: strings.Repeat("c", 64)}}}
	if err := s.CreateAgentUpdate(op); err != nil {
		t.Fatal(err)
	}
	second := op
	second.ID = "update-two"
	if err := s.CreateAgentUpdate(second); err == nil {
		t.Fatal("concurrent node update persisted")
	}
	got, err := s.GetAgentUpdate(op.ID)
	if err != nil || got.SessionID != op.SessionID || got.TicketHash != op.TicketHash || got.PreviousBootID != op.PreviousBootID || got.ObservedBootID != op.ObservedBootID || len(got.BootstrapArtifacts) != 1 {
		t.Fatalf("lost durable authority %+v %v", got, err)
	}
	public, _ := json.Marshal(got)
	for _, secret := range []string{op.SessionID, op.TicketHash, op.PreviousBootID, op.ObservedBootID, "bootstrap_artifacts"} {
		if strings.Contains(string(public), secret) {
			t.Fatal("public metadata disclosed authority", secret)
		}
	}
	byTicket, err := s.AgentUpdateByTicketHash(op.TicketHash)
	if err != nil || byTicket.ID != op.ID {
		t.Fatal("ticket binding lost", err)
	}
	active, err := s.ActiveAgentUpdates()
	if err != nil || len(active) != 1 {
		t.Fatal("active operation omitted", err)
	}
	op.State = "recovery_acknowledged"
	op.UpdatedAt = 3
	op.TicketHash = ""
	if err = s.UpdateAgentUpdate(op, "bootstrap_required"); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateAgentUpdate(op, "bootstrap_required"); !errors.Is(err, store.ErrAgentUpdateConflict) {
		t.Fatal("duplicate state mutation admitted", err)
	}
	second.CreatedAt = 4
	second.State = "requested"
	second.TicketHash = ""
	if err = s.CreateAgentUpdate(second); err != nil {
		t.Fatal("recovery terminal state retained unique reservation", err)
	}
	latest, err := s.LatestAgentUpdate("node")
	if err != nil || latest.ID != second.ID {
		t.Fatal("latest operation lookup failed", err)
	}
	active, err = s.ActiveAgentUpdates()
	if err != nil || len(active) != 1 || active[0].ID != second.ID {
		t.Fatal("terminal operation returned active", err)
	}
}
