package sshgw

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	// maxTerminalInputBytes bounds one client→agent write, matching the web
	// terminal's per-request limit.
	maxTerminalInputBytes = 8192

	// exitRefused is reported to the client when the gateway declines to open
	// or continue a session.
	exitRefused uint32 = 1
	// exitAborted is reported when a session ends abnormally (for example the
	// agent disconnecting) and the agent supplied no usable status.
	exitAborted uint32 = 255

	// sessionIDDetailPrefix matches the web terminal's audit detail format.
	sessionIDDetailPrefix = "session_id="

	// clientMessagePrefix identifies the gateway on every line it writes to a
	// client's stderr.
	clientMessagePrefix = "veyport: "

	// forcedCloseDetail marks the audit entry of a session the hub closed —
	// a revoked session, a disabled account, an administrator ending one
	// shell — rather than one that ended on its own.
	forcedCloseDetail = "reason=forced"
)

// windowSize is a PTY geometry update from a window-change request.
type windowSize struct {
	cols uint32
	rows uint32
}

// bridgeParams is everything the relay needs about an already-authorized
// session.
type bridgeParams struct {
	serverID      string
	serverName    string
	userID        string
	username      string
	executionUser string
	remoteIP      string
	cols          uint32
	rows          uint32
	win           <-chan windowSize
	// clientGone closes when the SSH session channel is finished. It is the
	// authoritative end-of-session signal: a client that merely half-closes
	// its stdin (`ssh ... < /dev/null`) must keep the remote shell running,
	// exactly as OpenSSH does, so an EOF from the channel reader is not it.
	clientGone <-chan struct{}
}

// exitInfo is how a relayed session ended.
type exitInfo struct {
	code uint32
	// message, when set, is shown to the operator on stderr.
	message string
	// agentInitiated reports that the agent already closed the session, so no
	// TerminalClose needs to be sent back to it.
	agentInitiated bool
	// forced reports that the hub ended the session under the person using
	// it. The remote shell is then still running on the agent, so it has to be
	// closed explicitly, and the audit trail records why the session went away.
	forced bool
}

// bridge runs one authorized SSH session against the agent terminal channel,
// following the research-R4 sequence: register, open, ack, attach, relay, tear
// down. It returns only once the session is fully closed.
func (s *Server) bridge(ch ssh.Channel, p bridgeParams) {
	sessionID := uuid.NewString()

	events, created := s.cfg.Terminals.Register(p.serverID, sessionID, p.userID, p.executionUser,
		grpcserver.WithKind(grpcserver.TerminalKindSSH))
	if !created {
		s.refuseBridge(ch, p, sessionID, "terminal session could not be registered")
		return
	}

	if err := s.openAgentTerminal(sessionID, p); err != nil {
		s.cfg.Terminals.Remove(p.serverID, sessionID)
		s.refuseBridge(ch, p, sessionID, err.Error())
		return
	}

	// Flip streaming on so the unattached-session reaper cannot claim it. The
	// returned info carries the same channel Register handed back.
	_, exists, attached := s.cfg.Terminals.AttachStream(p.serverID, sessionID, p.userID)
	if !exists || !attached {
		s.cfg.Terminals.Remove(p.serverID, sessionID)
		s.refuseBridge(ch, p, sessionID, "terminal session could not be attached")
		return
	}

	s.logAudit(model.AuditSSHSessionOpened, model.AuditOutcomeSuccess, p.userID, p.serverID,
		openDetail(sessionID, p), p.remoteIP)

	var inputWG sync.WaitGroup
	inputWG.Add(1)
	go func() {
		defer inputWG.Done()
		s.forwardClientInput(ch, sessionID, p)
	}()

	exit := s.relay(ch, events, sessionID, p)
	// teardown closes the channel, which is what unblocks the input reader;
	// only then can we wait for it, so the session leaves nothing running.
	s.teardown(ch, p, sessionID, exit)
	inputWG.Wait()
}

// openAgentTerminal sends TerminalOpenRequest and waits for the agent's ack.
func (s *Server) openAgentTerminal(sessionID string, p bridgeParams) error {
	ackCh := s.cfg.Pending.Register(p.serverID, sessionID)
	defer s.cfg.Pending.Remove(p.serverID, sessionID)

	err := s.cfg.ConnMgr.SendToAgent(p.serverID, &pb.HubMessage{
		Payload: &pb.HubMessage_TerminalOpenRequest{
			TerminalOpenRequest: &pb.TerminalOpenRequest{
				SessionId: sessionID,
				Cols:      p.cols,
				Rows:      p.rows,
				RunAsUser: p.executionUser,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("could not reach the agent for %q: %w", p.serverName, err)
	}

	timer := time.NewTimer(s.openTimeout())
	defer timer.Stop()

	select {
	case msg := <-ackCh:
		ack, ok := msg.(*pb.TerminalOpenAck)
		if !ok {
			return fmt.Errorf("unexpected response from the agent for %q", p.serverName)
		}
		if !ack.Success {
			return fmt.Errorf("the agent refused the terminal: %s", ack.Error)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("the agent on %q timed out opening the terminal", p.serverName)
	}
}

// relay pumps bytes in both directions until either side ends the session.
//
// Agent→client runs on this goroutine and does nothing but drain: the event
// channel holds 256 slots and TerminalSessions.DeliverData DROPS on a full
// buffer, so any extra work on this path would silently lose output.
func (s *Server) relay(ch ssh.Channel, events <-chan grpcserver.TerminalEvent, sessionID string, p bridgeParams) exitInfo {
	for {
		select {
		case event, ok := <-events:
			if !ok {
				// The session was closed underneath us without an exit event.
				return exitInfo{code: exitAborted, message: "the session was closed by the hub", agentInitiated: true}
			}
			switch event.Type {
			case grpcserver.TerminalEventData:
				if _, err := ch.Write(event.Data); err != nil {
					return exitInfo{code: exitAborted}
				}
			case grpcserver.TerminalEventExit:
				return agentExit(event)
			}

		case size := <-p.win:
			s.sendResize(sessionID, p, size)

		case <-p.clientGone:
			return exitInfo{}
		}
	}
}

// agentExit maps a terminal exit event to an SSH exit status. A negative code
// means the agent never produced one (for example because its stream died), so
// the session is reported as aborted.
//
// A forced exit is the hub's own doing: the agent knows nothing about it and
// its shell is still running, so the session is not treated as agent-initiated
// however the registry closed the channel.
func agentExit(event grpcserver.TerminalEvent) exitInfo {
	exit := exitInfo{
		code:           uint32(event.ExitCode),
		message:        event.Error,
		agentInitiated: !event.Forced,
		forced:         event.Forced,
	}
	if event.ExitCode < 0 {
		exit.code = exitAborted
	}
	return exit
}

// forwardClientInput relays keystrokes to the agent until the client stops
// sending. Returning here means "no more input" — the session itself ends only
// via p.clientGone or an agent-side exit.
func (s *Server) forwardClientInput(ch ssh.Channel, sessionID string, p bridgeParams) {
	buf := make([]byte, maxTerminalInputBytes)
	for {
		n, err := ch.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			sendErr := s.cfg.ConnMgr.SendToAgent(p.serverID, &pb.HubMessage{
				Payload: &pb.HubMessage_TerminalInput{
					TerminalInput: &pb.TerminalInput{SessionId: sessionID, Data: data},
				},
			})
			if sendErr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("SSH gateway: read from client for session %s: %v", sessionID, err)
			}
			return
		}
	}
}

func (s *Server) sendResize(sessionID string, p bridgeParams, size windowSize) {
	err := s.cfg.ConnMgr.SendToAgent(p.serverID, &pb.HubMessage{
		Payload: &pb.HubMessage_TerminalResize{
			TerminalResize: &pb.TerminalResize{SessionId: sessionID, Cols: size.cols, Rows: size.rows},
		},
	})
	if err != nil {
		log.Printf("SSH gateway: resize session %s: %v", sessionID, err)
	}
}

// teardown closes the session on both sides exactly once and audits it. The
// TerminalClose send is suppressed when the agent already reported the exit,
// mirroring the web terminal's closeTerminalSession.
func (s *Server) teardown(ch ssh.Channel, p bridgeParams, sessionID string, exit exitInfo) {
	alreadyClosed, removed := s.cfg.Terminals.RemoveIfHubInitiated(p.serverID, sessionID)
	// A forced close closes the registry entry before the relay ever sees the
	// exit, so alreadyClosed says nothing about the agent there: its shell is
	// still running and has to be told to stop.
	if removed && (!alreadyClosed || exit.forced) {
		err := s.cfg.ConnMgr.SendToAgent(p.serverID, &pb.HubMessage{
			Payload: &pb.HubMessage_TerminalClose{
				TerminalClose: &pb.TerminalClose{SessionId: sessionID},
			},
		})
		if err != nil {
			log.Printf("SSH gateway: close session %s on agent: %v", sessionID, err)
		}
	}

	// An abnormal end must be visible to the operator, never a silent freeze
	// (FR-011).
	if exit.message != "" {
		writeClientMessage(ch, exit.message)
	}
	sendExitStatus(ch, exit.code)
	_ = ch.Close()

	detail := sessionIDDetailPrefix + sessionID
	if exit.agentInitiated {
		detail += " agent_initiated"
	}
	if exit.forced {
		detail += " " + forcedCloseDetail
	}
	s.logAudit(model.AuditSSHSessionClosed, model.AuditOutcomeSuccess, p.userID, p.serverID, detail, p.remoteIP)
}

// refuseBridge reports a failed session open and audits it.
func (s *Server) refuseBridge(ch ssh.Channel, p bridgeParams, sessionID, message string) {
	writeClientMessage(ch, message)
	detail := fmt.Sprintf("%s%s ssh_user=%q target=%q reason=%s",
		sessionIDDetailPrefix, sessionID, p.username, p.serverName, message)
	s.logAudit(model.AuditSSHSessionRefused, model.AuditOutcomeFailure, p.userID, p.serverID, detail, p.remoteIP)
	sendExitStatus(ch, exitRefused)
	_ = ch.Close()
}

func openDetail(sessionID string, p bridgeParams) string {
	detail := sessionIDDetailPrefix + sessionID + fmt.Sprintf(" ssh_user=%q server=%q", p.username, p.serverName)
	if p.executionUser != "" {
		detail += " execution_user=" + p.executionUser
	}
	return detail
}

// writeClientMessage puts an operator-facing line on the channel's stderr.
//
// Messages that already name the gateway — the ones the session endpoints hand
// to the registry, which the web terminal shows verbatim too — are written as
// they are rather than announced twice.
func writeClientMessage(ch ssh.Channel, message string) {
	line := message
	if !strings.HasPrefix(line, clientMessagePrefix) {
		line = clientMessagePrefix + line
	}
	if _, err := fmt.Fprintf(ch.Stderr(), "%s\r\n", line); err != nil {
		return
	}
}

// sendExitStatus sends the RFC 4254 §6.10 exit-status request.
func sendExitStatus(ch ssh.Channel, code uint32) {
	payload := ssh.Marshal(struct{ Status uint32 }{Status: code})
	if _, err := ch.SendRequest(reqExitStatus, false, payload); err != nil {
		return
	}
}

// newID returns an identifier for an audit entry.
func newID() string { return uuid.NewString() }
