package sshgw

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
)

// Default PTY geometry for a client that opens a shell without pty-req.
const (
	defaultCols uint32 = 80
	defaultRows uint32 = 24
	// windowBuffer holds pending resizes so the request loop never blocks on
	// the relay; only the most recent geometry matters.
	windowBuffer = 8
)

// Channel and request types the gateway understands. Everything else is
// refused cleanly (FR-010).
const (
	channelSession = "session"

	reqPTY          = "pty-req"
	reqShell        = "shell"
	reqWindowChange = "window-change"
	reqExitStatus   = "exit-status"
)

// outOfScope maps a refused request type to the explanation written to the
// client's stderr. v1 is an interactive-PTY gateway only.
var outOfScope = map[string]string{
	"exec":                       "remote command execution is not available through the Veyport SSH gateway; open an interactive session instead",
	"subsystem":                  "file-transfer subsystems (sftp/scp) are not available through the Veyport SSH gateway",
	"auth-agent-req@openssh.com": "SSH agent forwarding is not available through the Veyport SSH gateway",
	"x11-req":                    "X11 forwarding is not available through the Veyport SSH gateway",
}

// serverChannelMessage explains a refused channel open.
const forwardingRefusal = "veyport: port forwarding is not available through the Veyport SSH gateway"

// serveChannels dispatches the connection's channels, refusing every type but
// "session" without disturbing the ones already open.
func (s *Server) serveChannels(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for newChannel := range chans {
		if newChannel.ChannelType() != channelSession {
			// direct-tcpip (-L) and any other channel type land here.
			_ = newChannel.Reject(ssh.Prohibited, forwardingRefusal)
			continue
		}
		ch, reqs, err := newChannel.Accept()
		if err != nil {
			log.Printf("SSH gateway: accept session channel from %s: %v", sshConn.RemoteAddr(), err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveSession(sshConn, ch, reqs)
		}()
	}
}

// sessionState is the mutable state of one session channel: the PTY geometry
// agreed so far, the resize queue, and whether a shell has already started.
type sessionState struct {
	cols    uint32
	rows    uint32
	win     chan windowSize
	started bool

	// clientGone closes when the session channel is finished. That, and not a
	// half-closed stdin, is the authoritative end-of-session signal.
	clientGone chan struct{}
	shellWG    sync.WaitGroup
}

func newSessionState() *sessionState {
	return &sessionState{
		cols:       defaultCols,
		rows:       defaultRows,
		win:        make(chan windowSize, windowBuffer),
		clientGone: make(chan struct{}),
	}
}

// finish releases the session: the shell is told the client is gone and awaited,
// and only then is the channel closed.
func (st *sessionState) finish(ch ssh.Channel) {
	close(st.clientGone)
	st.shellWG.Wait()
	_ = ch.Close()
}

// applyPTY records the geometry carried by a pty-req.
func (st *sessionState) applyPTY(req *ssh.Request) {
	var payload ptyRequest
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		replyTo(req, false)
		return
	}
	st.cols, st.rows = sanitizeGeometry(payload.Cols, payload.Rows)
	replyTo(req, true)
}

// applyWindowChange relays a resize to a running shell, or folds it into the
// geometry the shell will start with.
func (st *sessionState) applyWindowChange(req *ssh.Request) {
	var payload windowChangeRequest
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		replyTo(req, false)
		return
	}
	c, r := sanitizeGeometry(payload.Cols, payload.Rows)
	if st.started {
		pushWindow(st.win, windowSize{cols: c, rows: r})
	} else {
		st.cols, st.rows = c, r
	}
	replyTo(req, false)
}

// serveSession handles one session channel: it collects the PTY geometry,
// starts at most one shell, relays window changes, and refuses everything
// else without tearing the channel down (an out-of-scope request must not kill
// a session that is otherwise valid).
func (s *Server) serveSession(sshConn *ssh.ServerConn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	st := newSessionState()
	defer st.finish(ch)

	for req := range reqs {
		s.handleSessionRequest(sshConn, ch, req, st)
	}
}

// handleSessionRequest dispatches one channel request against the session state.
func (s *Server) handleSessionRequest(sshConn *ssh.ServerConn, ch ssh.Channel, req *ssh.Request, st *sessionState) {
	switch req.Type {
	case reqPTY:
		st.applyPTY(req)
	case reqWindowChange:
		st.applyWindowChange(req)
	case reqShell:
		s.startShell(sshConn, ch, req, st)
	default:
		s.refuseRequest(ch, req)
	}
}

// startShell honours the first shell request on a channel and refuses every
// later one: a session channel carries exactly one shell.
func (s *Server) startShell(sshConn *ssh.ServerConn, ch ssh.Channel, req *ssh.Request, st *sessionState) {
	if st.started {
		replyTo(req, false)
		return
	}
	st.started = true
	replyTo(req, true)
	shellCols, shellRows := st.cols, st.rows
	st.shellWG.Add(1)
	go func() {
		defer st.shellWG.Done()
		s.runShell(sshConn, ch, shellCols, shellRows, st.win, st.clientGone)
	}()
}

// refuseRequest denies an out-of-scope or unknown channel request. SSH's
// channel-failure message carries no text, so the explanation goes to the
// channel's stderr, where an operator will actually see it. The channel itself
// stays open: a rejected "env" or "exec" must not disturb a live PTY (FR-010).
func (s *Server) refuseRequest(ch ssh.Channel, req *ssh.Request) {
	if msg, ok := outOfScope[req.Type]; ok {
		writeClientMessage(ch, msg)
	}
	replyTo(req, false)
}

// runShell authorizes the session against live state and, if allowed, bridges
// it to the agent. Authorization failures are reported on the channel rather
// than by failing the shell request, so the operator sees an actionable reason
// instead of "shell request failed".
func (s *Server) runShell(sshConn *ssh.ServerConn, ch ssh.Channel, cols, rows uint32, win <-chan windowSize, clientGone <-chan struct{}) {
	username, target := identityFrom(sshConn)
	ip := remoteHost(sshConn.RemoteAddr())

	user, err := s.cfg.Store.GetUserByUsername(username)
	if err != nil {
		// The certificate was valid, but the account is gone or disabled:
		// live state wins over a still-valid credential (FR-007, SC-009).
		s.refuseShell(ch, "", "", ip, fmt.Sprintf("ssh_user=%q target=%q reason=unknown_account", username, target),
			"account "+username+" is not available for terminal access")
		return
	}

	srv, err := s.resolveServer(target)
	if err != nil {
		s.refuseShell(ch, user.ID, "", ip,
			fmt.Sprintf("ssh_user=%q target=%q reason=%v", username, target, err), err.Error())
		return
	}

	// The single shared authorization decision (research R5). An authorized
	// LOCAL admin legitimately yields an EMPTY execution user, which means
	// "the agent's default RunAsUser" — success, not failure.
	executionUser, err := server.AuthorizeTerminalExecution(s.cfg.Store, user.ID, srv.ID)
	if err != nil {
		s.refuseShell(ch, user.ID, srv.ID, ip,
			fmt.Sprintf("ssh_user=%q target=%q reason=%v", username, srv.Name, err), authorizationMessage(err))
		return
	}

	s.bridge(ch, bridgeParams{
		serverID:      srv.ID,
		serverName:    srv.Name,
		userID:        user.ID,
		username:      username,
		executionUser: executionUser,
		remoteIP:      ip,
		cols:          cols,
		rows:          rows,
		win:           win,
		clientGone:    clientGone,
	})
}

// refuseShell reports an authorization or resolution failure to the operator,
// audits it, and ends the session with a non-zero status.
func (s *Server) refuseShell(ch ssh.Channel, userID, serverID, ip, detail, message string) {
	writeClientMessage(ch, message)
	s.logAudit(model.AuditSSHSessionRefused, model.AuditOutcomeFailure, userID, serverID, detail, ip)
	sendExitStatus(ch, exitRefused)
	_ = ch.Close()
}

// Target resolution outcomes. Each is a distinct, actionable failure (FR-012).
var (
	errServerUnknown     = errors.New("unknown server")
	errServerAmbiguous   = errors.New("ambiguous server name")
	errServerUnavailable = errors.New("server unavailable")
)

// resolveServer maps the target half of the login name to a server, by exact
// name first and then by ID. Server names are unique, so the only possible
// ambiguity is a token that is one server's name and another server's ID.
func (s *Server) resolveServer(target string) (*model.Server, error) {
	byName, nameErr := s.cfg.Store.GetServerByName(target)
	byID, idErr := s.cfg.Store.GetServerByID(target)

	switch {
	case nameErr == nil && idErr == nil && byName.ID != byID.ID:
		return nil, fmt.Errorf("%w: %q is both a server name and another server's ID; use the ID you mean",
			errServerAmbiguous, target)
	case nameErr == nil:
		return s.requireOnline(byName)
	case idErr == nil:
		return s.requireOnline(byID)
	default:
		return nil, fmt.Errorf("%w: %q — check `vey servers list`", errServerUnknown, target)
	}
}

// requireOnline rejects a target whose agent is not currently connected.
func (s *Server) requireOnline(srv *model.Server) (*model.Server, error) {
	if s.cfg.ConnMgr.GetConn(srv.ID) == nil {
		return nil, fmt.Errorf("%w: no agent is connected for %q", errServerUnavailable, srv.Name)
	}
	return srv, nil
}

// authorizationMessage renders an authorization outcome for the operator. The
// sentinel errors come from the shared core, so the SSH wording tracks the web
// terminal's decisions exactly.
func authorizationMessage(err error) string {
	switch {
	case errors.Is(err, server.ErrTerminalNoAssignment):
		return server.ErrTerminalNoAssignment.Error()
	case errors.Is(err, server.ErrTerminalNoExecUser):
		return server.ErrTerminalNoExecUser.Error()
	case errors.Is(err, server.ErrTerminalLookupFailed):
		return server.ErrTerminalLookupFailed.Error()
	default:
		return server.ErrTerminalNotAuthorized.Error()
	}
}

// identityFrom reads the identity the auth callback proved and stashed.
func identityFrom(sshConn *ssh.ServerConn) (username, target string) {
	if sshConn.Permissions == nil {
		return "", ""
	}
	return sshConn.Permissions.Extensions[extUsername], sshConn.Permissions.Extensions[extTarget]
}

// ptyRequest is the RFC 4254 §6.2 pty-req payload.
type ptyRequest struct {
	Term     string
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    string
}

// windowChangeRequest is the RFC 4254 §6.7 window-change payload.
type windowChangeRequest struct {
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
}

// sanitizeGeometry substitutes defaults for a degenerate PTY size.
func sanitizeGeometry(cols, rows uint32) (uint32, uint32) {
	if cols == 0 {
		cols = defaultCols
	}
	if rows == 0 {
		rows = defaultRows
	}
	return cols, rows
}

// pushWindow enqueues a resize without ever blocking the request loop,
// discarding a stale pending geometry if the relay has not caught up.
func pushWindow(win chan windowSize, size windowSize) {
	for {
		select {
		case win <- size:
			return
		default:
			select {
			case <-win:
			default:
				return
			}
		}
	}
}

func replyTo(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}
