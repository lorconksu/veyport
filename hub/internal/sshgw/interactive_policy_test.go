package sshgw

import (
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/authorization"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestBridgeRevalidatesPolicyBeforeRegistration(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	if err := authorization.New(f.store).GuardInteractive(testUserID, testServerID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RequirePolicyRecovery(); err != nil {
		t.Fatal(err)
	}
	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	waitForDone(t, done, "stale Standard authorization refusal")
	if got := ch.exitStatus(t); got == 0 {
		t.Fatal("stale Standard authorization opened a covered shell")
	}
	for _, m := range f.agent.messages() {
		if m.GetTerminalOpenRequest() != nil {
			t.Fatal("stale Standard authorization reached agent open")
		}
	}
	if sessions := f.terminals.ListByUser(testUserID); len(sessions) != 0 {
		t.Fatal("refused session left a registration")
	}
}

func TestActualSSHPolicyRecoveryCancelsPendingOpen(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.agent.setSilent(true)
	f.start()
	client := f.mustDial(testUsername + "+" + testServerName)
	defer client.Close()
	sess, _, _ := startPTYShell(t, client)
	defer sess.Close()
	sessionID := f.openSessionID()
	if err := f.store.RequirePolicyRecovery(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("policy-cancelled SSH shell succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("policy did not cancel pending SSH open")
	}
	f.agent.waitForMessage(t, "exact pending shell close", func(m *pb.HubMessage) bool {
		return m.GetTerminalClose() != nil && m.GetTerminalClose().SessionId == sessionID
	})
	if _, ok := f.terminals.Get(testServerID, sessionID); ok {
		t.Fatal("cancelled pending open left a registry entry")
	}
}
