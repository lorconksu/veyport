package sshgw

import (
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// T014 — an SSH shell closed by the hub rather than by the person using it.
//
// Revoking a session or disabling an account has to reach the shells opened
// over the gateway, and the person at the terminal has to learn why their
// session went away instead of watching it freeze. These cases drive the same
// registry call the session endpoints make and assert on everything the
// operator and the auditor see afterwards.

const forcedCloseMessage = "veyport: session ended by an administrator"

// waitForShell blocks until a registered shell for the session appears.
func waitForShell(t *testing.T, f *fixture, sessionID string) grpcserver.TerminalSessionInfo {
	t.Helper()
	waitFor(t, "session attach", func() bool {
		_, ok := f.terminals.Get(testServerID, sessionID)
		return ok
	})
	info, ok := f.terminals.Get(testServerID, sessionID)
	if !ok {
		t.Fatal("the shell disappeared from the registry")
	}
	return info
}

// A gateway shell registers as an SSH shell on its target server, which is
// what lets it appear in the sessions list and be addressed there.
func TestBridgeRegistersShellAsSSH(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	info := waitForShell(t, f, f.openSessionID())

	if info.Kind != grpcserver.TerminalKindSSH {
		t.Errorf("kind = %q, want %q", info.Kind, grpcserver.TerminalKindSSH)
	}
	if info.ServerID != testServerID {
		t.Errorf("server = %q, want %q", info.ServerID, testServerID)
	}
	if info.UserID != testUserID {
		t.Errorf("user = %q, want %q", info.UserID, testUserID)
	}
	// A certificate-authenticated shell belongs to no web or CLI session, so
	// per-session revocation must never sweep it up by accident.
	if info.SID != "" {
		t.Errorf("sid = %q, want a gateway shell to carry none", info.SID)
	}
	if len(f.terminals.ListByUser(testUserID)) != 1 {
		t.Errorf("the shell must be listed for its user")
	}

	f.disconnect(ch)
	waitForDone(t, done, "bridge teardown")
}

// Ending a user's shells from the hub prints the reason on the client's
// stderr, exits non-zero, tells the agent to close the remote shell, and is
// audited as a forced close (FR-009, FR-010).
func TestBridgeForcedCloseExplainsAndAudits(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitForShell(t, f, sessionID)

	if closed := f.terminals.EndByUser(testUserID, 1, forcedCloseMessage); closed != 1 {
		t.Fatalf("EndByUser closed %d shells, want 1", closed)
	}
	waitForDone(t, done, "bridge teardown after a forced close")

	// The message carries its own prefix, so it must reach the client exactly
	// once rather than being announced twice.
	if got := ch.errBuf.String(); got != forcedCloseMessage+"\r\n" {
		t.Errorf("client stderr = %q, want %q", got, forcedCloseMessage+"\r\n")
	}
	if got := ch.exitStatus(t); got != 1 {
		t.Errorf("exit-status = %d, want 1", got)
	}
	if !ch.isClosed() {
		t.Error("the ssh channel must be closed after a forced close")
	}

	// The remote shell is on the agent, so a forced close is only real once
	// the agent has been told to end it.
	f.agent.waitForMessage(t, "TerminalClose", func(m *pb.HubMessage) bool {
		return m.GetTerminalClose() != nil && m.GetTerminalClose().SessionId == sessionID
	})

	entry := f.waitForAudit(model.AuditSSHSessionClosed)
	if entry.Detail == nil || !strings.Contains(*entry.Detail, "reason=forced") {
		t.Errorf("audit detail = %v, want it to record reason=forced", entry.Detail)
	}
	if entry.Detail != nil && !strings.Contains(*entry.Detail, sessionID) {
		t.Errorf("audit detail = %q, want it to name session %q", *entry.Detail, sessionID)
	}
}

// Closing one session's shells leaves the rest alone: revocation is per
// session, and a shell that belongs to nobody's revoked session keeps running.
func TestBridgeSessionScopedCloseLeavesGatewayShellAlone(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	waitForShell(t, f, f.openSessionID())

	if closed := f.terminals.EndBySession("some-web-session", 1, forcedCloseMessage); closed != 0 {
		t.Fatalf("EndBySession closed %d gateway shells, want 0", closed)
	}
	if len(f.terminals.ListByUser(testUserID)) != 1 {
		t.Fatal("the gateway shell must still be live")
	}

	f.disconnect(ch)
	waitForDone(t, done, "bridge teardown")
}

// A shell the agent itself ended is not a forced close: the audit trail has to
// keep telling the two apart.
func TestBridgeAgentExitIsNotAuditedAsForced(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()

	ch := newFakeChannel()
	done, _ := f.startBridge(ch, nil)
	sessionID := f.openSessionID()
	waitForShell(t, f, sessionID)

	if !f.terminals.End(testServerID, sessionID, 0, "") {
		t.Fatal("End() did not close the terminal session")
	}
	waitForDone(t, done, "bridge teardown after the remote shell exited")

	entry := f.waitForAudit(model.AuditSSHSessionClosed)
	if entry.Detail == nil || strings.Contains(*entry.Detail, "reason=forced") {
		t.Errorf("audit detail = %v, want no forced marker for a normal exit", entry.Detail)
	}
}
