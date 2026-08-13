package sshgw

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/server"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// Session-channel semantics: the request loop must survive malformed and
// duplicate requests without disturbing a session that is otherwise valid
// (FR-010), and the geometry a shell starts with must be whatever the client
// last said, whichever request carried it.

// TestGatewayWindowChangeBeforeShellSetsInitialGeometry pins that a resize
// arriving before the shell is folded into the geometry the agent is asked to
// open, rather than being queued for a shell that does not exist yet.
func TestGatewayWindowChangeBeforeShellSetsInitialGeometry(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	ch := openRawSession(t, f.mustDial(testUsername+"+"+testServerName))
	sendChannelRequest(t, ch, reqWindowChange, ssh.Marshal(windowChangeRequest{Cols: 111, Rows: 41}))
	if !sendChannelRequest(t, ch, reqShell, nil) {
		t.Fatal("shell request was refused")
	}

	f.assertOpenRequestGeometry(t, 111, 41)
}

// TestGatewayZeroGeometryFallsBackToDefaults pins the degenerate pty-req: a
// client that asks for a 0x0 terminal gets the standard 80x24 instead.
func TestGatewayZeroGeometryFallsBackToDefaults(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	ch := openRawSession(t, f.mustDial(testUsername+"+"+testServerName))
	if !sendChannelRequest(t, ch, reqPTY, ssh.Marshal(ptyRequest{Term: "xterm"})) {
		t.Fatal("pty-req with a zero geometry was refused")
	}
	if !sendChannelRequest(t, ch, reqShell, nil) {
		t.Fatal("shell request was refused")
	}

	f.assertOpenRequestGeometry(t, defaultCols, defaultRows)
}

// TestGatewayMalformedRequestsDoNotKillTheSession pins FR-010's "refuse without
// tearing down": an undecodable pty-req or window-change is answered with a
// failure, and the very same channel still opens a working shell afterwards.
func TestGatewayMalformedRequestsDoNotKillTheSession(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	ch := openRawSession(t, f.mustDial(testUsername+"+"+testServerName))
	if sendChannelRequest(t, ch, reqPTY, []byte{0x01, 0x02}) {
		t.Error("a malformed pty-req was accepted")
	}
	if sendChannelRequest(t, ch, reqWindowChange, []byte{0x01, 0x02}) {
		t.Error("a malformed window-change was accepted")
	}
	if !sendChannelRequest(t, ch, reqPTY, ssh.Marshal(ptyRequest{Term: "xterm", Cols: 90, Rows: 30})) {
		t.Fatal("a valid pty-req after malformed ones was refused")
	}
	if !sendChannelRequest(t, ch, reqShell, nil) {
		t.Fatal("shell request was refused after malformed requests")
	}

	f.assertOpenRequestGeometry(t, 90, 30)
}

// TestGatewayRefusesSecondShellRequest pins one shell per session channel: the
// second request is denied and no second terminal is opened on the agent.
func TestGatewayRefusesSecondShellRequest(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	ch := openRawSession(t, f.mustDial(testUsername+"+"+testServerName))
	if !sendChannelRequest(t, ch, reqPTY, ssh.Marshal(ptyRequest{Term: "xterm", Cols: 80, Rows: 24})) {
		t.Fatal("pty-req was refused")
	}
	if !sendChannelRequest(t, ch, reqShell, nil) {
		t.Fatal("the first shell request was refused")
	}
	f.openSessionID()

	if sendChannelRequest(t, ch, reqShell, nil) {
		t.Fatal("a second shell request on the same channel was accepted")
	}
	if got := countOpenRequests(f.agent.messages()); got != 1 {
		t.Errorf("agent received %d TerminalOpenRequests, want exactly 1", got)
	}
}

func countOpenRequests(msgs []*pb.HubMessage) int {
	n := 0
	for _, m := range msgs {
		if m.GetTerminalOpenRequest() != nil {
			n++
		}
	}
	return n
}

// TestGatewayResolvesTargetByServerID pins the FR-012 fallback: a target that is
// not a server name is resolved as a server ID.
func TestGatewayResolvesTargetByServerID(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()

	client := f.mustDial(testUsername + "+" + testServerID)
	sess, _, _ := startPTYShell(t, client)
	defer func() { _ = sess.Close() }()

	f.assertOpenRequestGeometry(t, 80, 24)
}

// ---------------------------------------------------------------------------
// pure session helpers
// ---------------------------------------------------------------------------

// TestAuthorizationMessageTracksCoreSentinels pins the SSH wording to the shared
// core's own sentinels: the operator must read the web terminal's reason, and
// anything unrecognized must fall back to the least-informative refusal rather
// than leaking an internal error.
func TestAuthorizationMessageTracksCoreSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"no assignment", server.ErrTerminalNoAssignment, server.ErrTerminalNoAssignment.Error()},
		{"no execution user", server.ErrTerminalNoExecUser, server.ErrTerminalNoExecUser.Error()},
		{"lookup failed", server.ErrTerminalLookupFailed, server.ErrTerminalLookupFailed.Error()},
		{"not authorized", server.ErrTerminalNotAuthorized, server.ErrTerminalNotAuthorized.Error()},
		{"wrapped sentinel", fmt.Errorf("check: %w", server.ErrTerminalNoExecUser), server.ErrTerminalNoExecUser.Error()},
		{"unrecognized", errors.New("some internal detail"), server.ErrTerminalNotAuthorized.Error()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := authorizationMessage(c.err); got != c.want {
				t.Errorf("authorizationMessage(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}

// TestIdentityFromWithoutPermissions pins the defensive read: a connection with
// no proven identity yields empty strings rather than panicking.
func TestIdentityFromWithoutPermissions(t *testing.T) {
	username, target := identityFrom(&ssh.ServerConn{})
	if username != "" || target != "" {
		t.Errorf("identityFrom() = (%q, %q), want empty strings", username, target)
	}
}

func TestSanitizeGeometrySubstitutesDefaults(t *testing.T) {
	cases := []struct {
		inCols, inRows     uint32
		wantCols, wantRows uint32
	}{
		{0, 0, defaultCols, defaultRows},
		{0, 40, defaultCols, 40},
		{120, 0, 120, defaultRows},
		{120, 40, 120, 40},
	}
	for _, c := range cases {
		cols, rows := sanitizeGeometry(c.inCols, c.inRows)
		if cols != c.wantCols || rows != c.wantRows {
			t.Errorf("sanitizeGeometry(%d, %d) = %dx%d, want %dx%d",
				c.inCols, c.inRows, cols, rows, c.wantCols, c.wantRows)
		}
	}
}

// TestPushWindowKeepsOnlyTheLatestGeometry pins that a backed-up resize queue
// discards the stale geometry rather than the new one: only the most recent
// size matters.
func TestPushWindowKeepsOnlyTheLatestGeometry(t *testing.T) {
	win := make(chan windowSize, 1)
	pushWindow(win, windowSize{cols: 10, rows: 10})
	pushWindow(win, windowSize{cols: 20, rows: 20})

	got := <-win
	if got.cols != 20 || got.rows != 20 {
		t.Errorf("queued geometry = %dx%d, want the latest 20x20", got.cols, got.rows)
	}
	select {
	case extra := <-win:
		t.Errorf("resize queue still holds %dx%d, want it drained", extra.cols, extra.rows)
	default:
	}
}

// TestPushWindowNeverBlocksTheRequestLoop pins the load-bearing property: the
// SSH request loop must never stall on a relay that is not consuming resizes.
func TestPushWindowNeverBlocksTheRequestLoop(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Unbuffered and unread: sending and draining both fail.
		pushWindow(make(chan windowSize), windowSize{cols: 30, rows: 30})
	}()
	waitForDone(t, done, "pushWindow to give up on an unreadable queue")
}
