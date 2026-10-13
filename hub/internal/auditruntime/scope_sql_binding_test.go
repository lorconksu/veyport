package auditruntime_test

import (
	"context"
	"github.com/wyiu/veyport/hub/internal/model"
	"testing"
)

func TestScopedActorAndNodeIdentifiersRemainBound(t *testing.T) {
	h := newHarness(t)
	p := h.policy
	h.protected["node"] = false
	poison := "' OR 1=1 --"
	p.Nodes = []string{poison}
	if h.runtime.Evidence().Ready(context.Background(), p) == nil {
		t.Fatal("unknown quoted node accepted")
	}
	p.Nodes = nil
	p.Actors = []string{poison}
	if h.runtime.Evidence().Ready(context.Background(), p) == nil {
		t.Fatal("unknown quoted actor selected a node")
	}
	if err := h.store.CreateServer(&model.Server{ID: poison, Name: "literal", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	h.protected[poison] = true
	p.Nodes = []string{poison}
	p.Actors = nil
	if err := h.runtime.Evidence().Ready(context.Background(), p); err != nil {
		t.Fatalf("literal quote-bearing ID rejected or broadened scope: %v", err)
	}
	p.Nodes = nil
	p.Actors = []string{poison}
	if err := h.store.CreateUser(&model.User{ID: poison, Username: "literal-actor", Email: "literal@test.invalid", Role: model.RoleViewer}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.DB().Exec("INSERT INTO permissions(id,user_id,server_id,path) VALUES('literal-assignment',?,?, '/')", poison, poison); err != nil {
		t.Fatal(err)
	}
	if err := h.runtime.Evidence().Ready(context.Background(), p); err != nil {
		t.Fatalf("literal actor binding failed: %v", err)
	}
}
