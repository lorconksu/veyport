package grpcserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func TestAgentUpdateManualBootstrapRequiredForLegacyAndPrototype4(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{true: "legacy", false: "prototype4"}[legacy], func(t *testing.T) {
			f := newUpdateFixture(t)
			if legacy {
				f.u.EndConnection("node", f.stream)
			} else {
				c := proto.Clone(f.old).(*pb.UpdateCapabilities)
				c.ActivityQuiescenceVersion = 0
				if err := f.u.ObserveCapabilities("node", f.stream, c); err != nil {
					t.Fatal(err)
				}
			}
			check, err := f.u.Check("admin", "session", "node")
			if err != nil || !check.BootstrapRequired || !check.BootstrapIdleConfirmationRequired || check.ConnectionID == "" || check.Supported {
				t.Fatal(check, err)
			}
			for _, a := range []BootstrapIdleAssertion{{}, {Confirmed: true}, {Confirmed: true, ConnectionID: "stale"}} {
				if _, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, a); err == nil || ticket != "" {
					t.Fatal("unasserted/stale bootstrap issued authority", a, err)
				}
			}
			conn := f.h.connMgr.GetConn("node")
			request := &pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{RequestId: "live"}}}
			active, err := f.h.connMgr.BeginRequest(conn, request)
			if err != nil {
				t.Fatal(err)
			}
			if err = active.Send(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			assertion := BootstrapIdleAssertion{Confirmed: true, ConnectionID: check.ConnectionID}
			if _, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, assertion); err == nil || ticket != "" {
				t.Fatal("manual assertion overrode active work")
			}
			active.Abandon()
			op, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, assertion)
			if err != nil || len(ticket) != 64 || !op.BootstrapIdleConfirmed || op.BootstrapConnectionID != conn.GenerationID {
				t.Fatal(op, err)
			}
			persisted, err := f.st.GetAgentUpdate(op.ID)
			if err != nil || !persisted.BootstrapIdleConfirmed || persisted.BootstrapConnectionID != conn.GenerationID {
				t.Fatal("assertion not durable", persisted, err)
			}
			raw, _ := json.Marshal(persisted)
			if strings.Contains(string(raw), "bootstrap_idle_confirmed") || strings.Contains(string(raw), conn.GenerationID) {
				t.Fatal("private authority leaked", string(raw))
			}
			var actor string
			if err = f.st.DB().QueryRow("SELECT actor_type FROM audit_logs WHERE action='server.agent_update.manual_bootstrap_idle_confirmed'").Scan(&actor); err != nil || actor != "user" {
				t.Fatal("manual assertion not attributed to administrator", actor, err)
			}
			before := len(f.stream.sent)
			if _, err = f.h.BootstrapUpdate(enrolledUpdateContext("node"), &pb.UpdateBootstrapRequest{Ticket: ticket, Capabilities: f.old}); err != nil {
				t.Fatal("asserted ticket could not redeem", err)
			}
			if len(f.stream.sent) != before {
				t.Fatal("old agent received native update request")
			}
		})
	}
}
func TestAgentUpdateNativeRejectsBusyCountAndUnsupportedManualOverride(t *testing.T) {
	f := newUpdateFixture(t)
	c := proto.Clone(f.old).(*pb.UpdateCapabilities)
	c.ActiveActivities = 1
	if err := f.u.ObserveCapabilities("node", f.stream, c); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision); err == nil {
		t.Fatal("native carried worker did not block update")
	}
	c.ActiveActivities = 0
	if err := f.u.ObserveCapabilities("node", f.stream, c); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, BootstrapIdleAssertion{Confirmed: true, ConnectionID: f.h.connMgr.GetConn("node").GenerationID}); err == nil {
		t.Fatal("manual flag became native escape hatch")
	}
	c.Supported = false
	c.Reason = "noncanonical"
	c.ActivityQuiescenceVersion = 0
	if err := f.u.ObserveCapabilities("node", f.stream, c); err != nil {
		t.Fatal(err)
	}
	check, err := f.u.Check("admin", "session", "node")
	if err != nil || check.BootstrapRequired {
		t.Fatal("unsafe installation gained bootstrap permission", check, err)
	}
}
func TestAgentUpdateCountChangesDoNotRewriteUnchangedObservedVersion(t *testing.T) {
	f := newUpdateFixture(t)
	if _, err := f.st.DB().Exec(`CREATE TRIGGER reject_version_rewrite BEFORE UPDATE OF agent_version ON servers BEGIN SELECT RAISE(ABORT,'redundant observed version write'); END`); err != nil {
		t.Fatal(err)
	}
	for _, count := range []uint32{1, 0, 2, 0} {
		c := proto.Clone(f.old).(*pb.UpdateCapabilities)
		c.ActiveActivities = count
		if err := f.u.ObserveCapabilities("node", f.stream, c); err != nil {
			t.Fatal("activity-only observation rewrote SQL", err)
		}
	}
	current := &mockStream{}
	f.h.connMgr.Register("node", current)
	if err := f.u.ObserveCapabilities("node", current, f.old); err == nil {
		t.Fatal("new generation skipped required durable version write")
	}
}
func TestAgentUpdateActivityResponsesBindExactConnectionAndCloseTerminalLogs(t *testing.T) {
	f := newUpdateFixture(t)
	f.h.pending = NewPendingRequests()
	f.h.logSessions = NewLogSessions()
	conn := f.h.connMgr.GetConn("node")
	logRequest := &pb.HubMessage{Payload: &pb.HubMessage_LogStreamRequest{LogStreamRequest: &pb.LogStreamRequest{RequestId: "tail"}}}
	a, err := f.h.connMgr.BeginRequest(conn, logRequest)
	if err != nil {
		t.Fatal(err)
	}
	ch := f.h.logSessions.Register("node", "tail")
	if err = a.Send(context.Background(), logRequest); err != nil {
		t.Fatal(err)
	}
	if err = f.h.routeAgentMessage("node", f.stream, &pb.AgentMessage{Payload: &pb.AgentMessage_LogStreamChunk{LogStreamChunk: &pb.LogStreamChunk{RequestId: "tail", Data: []byte("data")}}}); err != nil {
		t.Fatal(err)
	}
	if err = f.h.connMgr.ReserveMaintenance(conn, "too-early", func() error { return nil }); err == nil {
		t.Fatal("log data claimed terminal completion")
	}
	if err = f.h.routeAgentMessage("node", f.stream, &pb.AgentMessage{Payload: &pb.AgentMessage_LogStreamChunk{LogStreamChunk: &pb.LogStreamChunk{RequestId: "tail", Done: true, Data: []byte("error: tail ended"), Error: "tail ended"}}}); err != nil {
		t.Fatal(err)
	}
	if got := string(<-ch); got != "data" {
		t.Fatal(got)
	}
	if got := string(<-ch); got != "error: tail ended" {
		t.Fatal(got)
	}
	if _, ok := <-ch; ok {
		t.Fatal("terminal log left SSE waiter alive")
	}
	if err = f.h.connMgr.ReserveMaintenance(conn, "ready", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.h.connMgr.ReleaseMaintenance("node", "ready")
	read := &pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{RequestId: "read"}}}
	if err = f.h.connMgr.SendToAgent("node", read); err != nil {
		t.Fatal(err)
	}
	replacement := &mockStream{}
	newConn := f.h.connMgr.Register("node", replacement)
	if err = f.h.connMgr.SendToAgent("node", read); err != nil {
		t.Fatal(err)
	}
	waiter := f.h.pending.Register("node", "read")
	response := &pb.AgentMessage{Payload: &pb.AgentMessage_FileReadResponse{FileReadResponse: &pb.FileReadResponse{RequestId: "read"}}}
	if err = f.h.routeAgentMessage("node", f.stream, response); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waiter:
		t.Fatal("old response delivered to replacement waiter")
	default:
	}
	if err = f.h.routeAgentMessage("node", replacement, response); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waiter:
	default:
		t.Fatal("current response not delivered")
	}
	if err = f.h.connMgr.ObserveActivityCapabilities("node", replacement, 1, 0); err != nil {
		t.Fatal(err)
	}
	if err = f.h.connMgr.ReserveMaintenance(newConn, "new-ready", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
func TestAgentUpdateUnassertedPersistedTicketCannotRedeem(t *testing.T) {
	f := newUpdateFixture(t)
	f.u.EndConnection("node", f.stream)
	op, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, f.idleAssertion())
	if err != nil {
		t.Fatal(err)
	}
	op.BootstrapIdleConfirmed = false
	if err = f.st.UpdateAgentUpdate(op, "bootstrap_required"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.BootstrapUpdate(enrolledUpdateContext("node"), &pb.UpdateBootstrapRequest{Ticket: ticket, Capabilities: f.old}); err == nil {
		t.Fatal("old unasserted ticket gained new authority")
	}
}
