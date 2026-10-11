package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestGovernanceHTTPPolicyContinuityPrecedesWebShellRouting(t *testing.T) {
	h := newGovernanceHTTP(t)
	h.s.connMgr = connmgr.New()
	h.s.pending = grpcserver.NewPendingRequests()
	h.s.terminalSessions = grpcserver.NewTerminalSessions()
	stream := &policyTerminalStream{messages: make(chan *pb.HubMessage, 20), pending: h.s.pending, node: "synthetic-node", ack: true}
	h.s.connMgr.Register("synthetic-node", stream)
	t.Cleanup(func() { h.s.connMgr.Unregister("synthetic-node") })
	path := "/api/servers/synthetic-node/terminal/sessions"
	geometry := map[string]int{"cols": 80, "rows": 24}
	h.call(t, "POST", path, "officer", geometry, http.StatusCreated)
	if nextPolicyTerminalMessage(t, stream).GetTerminalOpenRequest() == nil {
		t.Fatal("initial Standalone route did not open a shell")
	}
	h.apply(t, h.approve(t, h.request(t, h.bootstrapPayload(), 1)), http.StatusOK)
	if nextPolicyTerminalMessage(t, stream).GetTerminalClose() == nil {
		t.Fatal("Enhanced bootstrap did not close the earlier Standard shell")
	}
	state, err := h.s.store.GetPolicyState()
	if err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err := h.s.store.DB().QueryRow("SELECT payload FROM audit_policy_versions WHERE version=2").Scan(&original); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"standard", "unrelated_scope"} {
		t.Run(scope, func(t *testing.T) {
			corrupt := state.Active.Policy
			if scope == "standard" {
				corrupt.Profile = "standard"
			} else {
				corrupt.Nodes = []string{"unrelated-node"}
			}
			raw, err := json.Marshal(corrupt)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.s.store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=2", raw, authorization.Digest(raw)); err != nil {
				t.Fatal(err)
			}
			h.call(t, "POST", path, "officer", geometry, http.StatusForbidden)
			if _, err := authorization.New(h.s.store).PolicyForExecution("officer", "synthetic-node"); !errors.Is(err, authorization.ErrRecovery) {
				t.Fatalf("fresh services missed startup continuity binding: %v", err)
			}
			select {
			case message := <-stream.messages:
				t.Fatalf("corrupted policy sent an unaudited agent message: %T", message.Payload)
			default:
			}
			if shells := h.s.terminalSessions.ListByUser("officer"); len(shells) != 0 {
				for _, shell := range shells {
					if !shell.Closed {
						t.Fatal("corrupted policy registered a live web shell")
					}
				}
			}
			if _, err := h.s.store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=2", original, state.Active.SHA256); err != nil {
				t.Fatal(err)
			}
		})
	}
	h.call(t, "POST", path, "officer", geometry, http.StatusForbidden)
	standard := model.AuditPolicy{Profile: "standard", RuntimeSeconds: 60, RetentionHours: 24}
	change := h.request(t, model.SecurityChangePayload{Kind: "policy", Policy: &standard}, 2)
	h.apply(t, h.approve(t, change), http.StatusOK)
	h.archive.SetFault("anchor")
	h.call(t, "POST", path, "officer", geometry, http.StatusCreated)
	if nextPolicyTerminalMessage(t, stream).GetTerminalOpenRequest() == nil {
		t.Fatal("approved Standard disable required external archive availability")
	}
}
