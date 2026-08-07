package sshgw

import (
	"errors"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// T013 (continued) — bridge failure paths.
//
// Every case here is a way the hub↔agent relay can go wrong AFTER the session
// has been authorized. The invariant under test is always the same: the
// operator is told what happened, the terminal session is not left registered,
// and the refusal or close is audited. A silent freeze is the failure mode
// FR-011 exists to prevent.

// TestBridgeUnexpectedAckTypeRefuses covers an agent that answers the open
// request with something other than a TerminalOpenAck. The correlation registry
// is type-agnostic, so the bridge — not the registry — has to catch it.
func TestBridgeUnexpectedAckTypeRefuses(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.agent.setWrongAck(true)

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	waitForDone(t, done, "bridge refusal after an unexpected ack type")

	if got := ch.errBuf.String(); !strings.Contains(got, "unexpected response") {
		t.Errorf("stderr = %q, want an unexpected-response explanation", got)
	}
	if got := ch.exitStatus(t); got != exitRefused {
		t.Errorf("exit-status = %d, want %d", got, exitRefused)
	}
	f.waitForAudit(model.AuditSSHSessionRefused)
	if len(f.auditEntries(model.AuditSSHSessionOpened)) != 0 {
		t.Error("a refused open must not be audited as ssh.session_opened")
	}
}

// TestBridgeAttachFailureRefuses covers the session disappearing between the
// agent's ack and the bridge attaching its stream — the window in which the
// unattached-session reaper, or an operator-triggered close, can remove it.
func TestBridgeAttachFailureRefuses(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.agent.setOnOpen(func(sessionID string) {
		f.terminals.Remove(testServerID, sessionID)
	})

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	waitForDone(t, done, "bridge refusal after a failed attach")

	if got := ch.errBuf.String(); !strings.Contains(got, "could not be attached") {
		t.Errorf("stderr = %q, want an attach-failure explanation", got)
	}
	f.waitForAudit(model.AuditSSHSessionRefused)
	if len(f.auditEntries(model.AuditSSHSessionOpened)) != 0 {
		t.Error("a refused open must not be audited as ssh.session_opened")
	}
}

// TestBridgeHubClosedSessionReportsAbort covers the event channel closing
// without an exit event, which is what an operator-side or reaper-side removal
// looks like from the relay. The client must be told, not left hanging.
func TestBridgeHubClosedSessionReportsAbort(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitFor(t, "session attach", func() bool {
		_, ok := f.terminals.Get(testServerID, sessionID)
		return ok
	})

	f.terminals.Remove(testServerID, sessionID)
	waitForDone(t, done, "bridge teardown after the hub closed the session")

	if got := ch.errBuf.String(); !strings.Contains(got, "closed by the hub") {
		t.Errorf("stderr = %q, want an explanation that the hub closed the session", got)
	}
	if got := ch.exitStatus(t); got != exitAborted {
		t.Errorf("exit-status = %d, want %d for an aborted session", got, exitAborted)
	}
	f.waitForAudit(model.AuditSSHSessionClosed)
}

// TestBridgeDeadClientChannelTearsDownSession covers agent output that can no
// longer be written to the client: the session must end and the agent must be
// told to close its terminal, rather than the relay spinning on a dead channel.
func TestBridgeDeadClientChannelTearsDownSession(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitFor(t, "session attach", func() bool {
		_, ok := f.terminals.Get(testServerID, sessionID)
		return ok
	})

	// The client's transport is gone; every later write to the channel fails.
	_ = ch.Close()
	if !f.terminals.DeliverData(testServerID, sessionID, []byte("output nobody can receive")) {
		t.Fatal("DeliverData() dropped the payload")
	}
	waitForDone(t, done, "bridge teardown after the client channel died")

	f.agent.waitForMessage(t, "TerminalClose", func(m *pb.HubMessage) bool {
		return m.GetTerminalClose() != nil && m.GetTerminalClose().SessionId == sessionID
	})
	if _, ok := f.terminals.Get(testServerID, sessionID); ok {
		t.Error("terminal session was left registered after the client channel died")
	}
	f.waitForAudit(model.AuditSSHSessionClosed)
}

// TestBridgeAgentSendFailuresAreNonFatal covers a stream that dies after the
// terminal is open: input, resize and the closing TerminalClose all fail to
// send. None of those may wedge the session — it must still tear down and
// audit cleanly.
func TestBridgeAgentSendFailuresAreNonFatal(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, win := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitFor(t, "session attach", func() bool {
		_, ok := f.terminals.Get(testServerID, sessionID)
		return ok
	})

	f.agent.setSendErr(errors.New("stream closed"))

	// io.Pipe is synchronous, so this returns only once the input reader has
	// taken the bytes and is on its way to the (now failing) send.
	ch.clientWrite(t, "typed after the stream died\r")
	win <- windowSize{cols: 100, rows: 30}
	waitFor(t, "the resize to be consumed by the relay", func() bool { return len(win) == 0 })

	f.disconnect(ch)
	waitForDone(t, done, "bridge teardown despite agent send failures")

	// Only the open request was ever recorded: everything after the break was
	// rejected by the stream itself.
	if got := len(f.agent.messages()); got != 1 {
		t.Errorf("agent recorded %d messages, want only the open request", got)
	}
	f.waitForAudit(model.AuditSSHSessionClosed)
}

// TestBridgeSurvivesUnwritableStderr covers the operator message itself failing
// to send. The refusal must still be audited: the audit trail cannot depend on
// the client being reachable.
func TestBridgeSurvivesUnwritableStderr(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.agent.setAck(false, "pty allocation failed")

	ch := newFakeChannel()
	ch.breakStderr()
	done, _ := f.startBridge(ch, nil)
	waitForDone(t, done, "bridge refusal with an unwritable stderr")

	if got := ch.errBuf.String(); got != "" {
		t.Errorf("stderr buffer = %q, want nothing: the writer was broken", got)
	}
	entry := f.waitForAudit(model.AuditSSHSessionRefused)
	if entry.Outcome != model.AuditOutcomeFailure {
		t.Errorf("audit outcome = %q, want %q", entry.Outcome, model.AuditOutcomeFailure)
	}
}
