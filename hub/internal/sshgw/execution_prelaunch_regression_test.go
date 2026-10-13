package sshgw

import (
	"fmt"
	"testing"

	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// The local audit trigger withdraws authority after the bridge's first check
// and durable claim. The fake stream records messages and never runs a process.
func TestStandardExecutionChecksLiveAuthorityAfterDispatchAudit(t *testing.T) {
	for _, change := range []struct {
		name, mutation string
	}{
		{"policy", "UPDATE audit_policy_state SET state='recovery_required' WHERE id=1"},
		{"credential", "UPDATE users SET security_revision=security_revision+1"},
		{"access", "UPDATE users SET must_change_password=1"},
		{"actor", "DELETE FROM security_identity_links"},
		{"node", "UPDATE servers SET status='offline'"},
	} {
		t.Run(change.name, func(t *testing.T) {
			f := newFixture(t, nil)
			executions := grpcserver.NewExecutionSessions(f.terminals, f.connMgr)
			f.srv.cfg.Executions = executions
			a := &failingExecBridgeAgent{stubAgent: f.agent, executions: executions, phase: "start-send", fixture: f}
			f.connMgr.Register(testServerID, a)
			executions.SetCapabilities(testServerID, a, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "bridge-boot"})
			gs := grpcserver.New(grpcserver.Config{Store: f.store, ConnMgr: f.connMgr, TerminalSessions: f.terminals, ExecutionSessions: executions})
			a.handler = gs.Handler()
			t.Cleanup(gs.Stop)
			t.Cleanup(a.closeStream)
			u, err := f.store.GetUserByID(testUserID)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := f.srv.securityService().PolicyForExecution(testUserID, testServerID)
			if err != nil || policy.Enhanced {
				t.Fatal("fixture did not admit Standard execution:", err)
			}
			const command = "synthetic submission"
			p := execParams{user: u, policy: policy, bridgeParams: bridgeParams{serverID: testServerID, serverName: testServerName, userID: testUserID, username: testUsername}}
			p.session, err = executions.Register(testServerID, "standard-prelaunch", testUserID, "", []byte(command))
			if err != nil {
				t.Fatal(err)
			}
			p.metadata, err = f.srv.newExecutionMetadata(p, p.session.ID, command)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.CreateExecution(p.metadata); err != nil {
				t.Fatal(err)
			}
			trigger := fmt.Sprintf("CREATE TRIGGER execution_prelaunch_change AFTER INSERT ON audit_logs WHEN NEW.action='%s' BEGIN %s; END", model.AuditExecutionDispatched, change.mutation)
			if _, err := f.store.DB().Exec(trigger); err != nil {
				t.Fatal(err)
			}
			ch := newFakeChannel()
			t.Cleanup(func() { _ = ch.Close() })
			done := make(chan struct{})
			go func() { defer close(done); f.srv.runExec(ch, p, command) }()
			waitForDone(t, done, "Standard prelaunch denial")
			a.mu.Lock()
			stream := a.stream
			a.mu.Unlock()
			if stream == nil {
				t.Fatal("fixture did not reach attached execution transport")
			}
			a.closeStream()
			waitForDone(t, stream.done, "denied execution RPC cleanup")
			if stream.starts.Load() != 0 || p.session.StartAttempted() {
				t.Fatal("withdrawn authority became a Standard Start attempt")
			}
			if admissionDispatchCount(t, f.srv, p.session.ID) != 1 || f.store.ClaimExecutionDispatch(p.session.ID, p.session.Binding().PreparationId) == nil {
				t.Fatal("denial lost the one-use durable dispatch boundary")
			}
			got, err := f.store.GetExecution(p.session.ID)
			if err != nil || got.FinishedAt == nil || got.ExitCode != nil || got.State == "exited" || got.State == "outcome_unknown" || !ch.isClosed() || len(f.terminals.ListByUser(testUserID)) != 0 {
				t.Fatalf("denial fabricated an outcome or retained capacity: %+v %v", got, err)
			}
		})
	}
}
