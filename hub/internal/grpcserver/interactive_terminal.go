package grpcserver

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

var (
	ErrInteractiveSessionClosed     = errors.New("terminal session is closed or its authorization changed")
	ErrInteractiveRegistration      = errors.New("terminal session could not be registered")
	ErrInteractiveAgentNotConnected = errors.New("agent not connected")
)

// An admission retains the exact control connection and a live local grant
// check. It is never redirected to a replacement agent connection.
type interactiveAdmission struct {
	st                  *store.Store
	cm                  *connmgr.ConnManager
	conn                *connmgr.AgentConn
	validate            func() (string, error)
	executionUser       string
	serverID, sessionID string
	closeOnce           sync.Once
}

func (a *interactiveAdmission) close() {
	a.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.cm.SendToConnectionChecked(ctx, a.conn, &pb.HubMessage{Payload: &pb.HubMessage_TerminalClose{TerminalClose: &pb.TerminalClose{SessionId: a.sessionID}}}, nil)
	})
}

func (ts *TerminalSessions) observeInteractivePolicy(st *store.Store) {
	ts.interactiveObserveMu.Lock()
	defer ts.interactiveObserveMu.Unlock()
	ts.mu.Lock()
	if ts.interactiveStores == nil {
		ts.interactiveStores = make(map[*store.Store]bool)
	}
	if ts.interactiveStores[st] {
		ts.mu.Unlock()
		return
	}
	ts.interactiveStores[st] = true
	ts.mu.Unlock()
	st.ObserveInteractivePolicy(func() {
		ts.mu.Lock()
		var sessions []*terminalSession
		for _, s := range ts.sessions {
			if !s.closed && s.interactive != nil && s.interactive.st == st {
				sessions = append(sessions, s)
			}
		}
		ts.mu.Unlock()
		for _, s := range sessions {
			executionUser, err := s.interactive.validate()
			if err == nil && executionUser == s.executionUser {
				continue
			}
			ts.mu.Lock()
			// Compare registration objects: delayed work cannot invalidate a later
			// registration that happens to reuse the same key.
			current := ts.sessions[makeKey(s.serverID, s.sessionID)]
			ended := current == s && endLocked(s, 1, "Security policy or terminal authorization changed.", true)
			ts.mu.Unlock()
			if ended {
				go s.interactive.close()
			}
		}
	})
}

// RegisterInteractive revalidates and registers under the same local lock as
// pending/active/recovery policy changes. Earlier transport checks are hints,
// not authority to open the agent terminal.
func (ts *TerminalSessions) RegisterInteractive(st *store.Store, cm *connmgr.ConnManager, serverID, sessionID, userID string, validate func() (string, error), opts ...RegisterOption) (chan TerminalEvent, string, error) {
	ts.observeInteractivePolicy(st)
	var events chan TerminalEvent
	var executionUser string
	err := st.WithInteractivePolicy(func() error {
		var err error
		executionUser, err = validate()
		if err != nil {
			return err
		}
		conn := cm.GetConn(serverID)
		if conn == nil {
			return ErrInteractiveAgentNotConnected
		}
		var created bool
		events, created = ts.Register(serverID, sessionID, userID, executionUser, opts...)
		if !created {
			return ErrInteractiveRegistration
		}
		ts.mu.Lock()
		ts.sessions[makeKey(serverID, sessionID)].interactive = &interactiveAdmission{st: st, cm: cm, conn: conn, validate: validate, executionUser: executionUser, serverID: serverID, sessionID: sessionID}
		ts.mu.Unlock()
		return nil
	})
	return events, executionUser, err
}

// SendInteractive checks the exact live registration, grant, policy and control
// generation immediately before its ordered send. A policy observer marks the
// registration closed locally and queues its close after an in-flight send.
func (ts *TerminalSessions) SendInteractive(ctx context.Context, serverID, sessionID string, msg *pb.HubMessage) error {
	ts.mu.Lock()
	s := ts.sessions[makeKey(serverID, sessionID)]
	if s == nil || s.closed || s.interactive == nil {
		ts.mu.Unlock()
		return ErrInteractiveSessionClosed
	}
	a := s.interactive
	ts.mu.Unlock()
	err := a.cm.SendToConnectionChecked(ctx, a.conn, msg, func() error {
		return a.st.WithInteractivePolicy(func() error {
			ts.mu.Lock()
			current := ts.sessions[makeKey(serverID, sessionID)]
			live := current == s && !s.closed
			ts.mu.Unlock()
			if !live || a.cm.GetConn(serverID) != a.conn {
				return ErrInteractiveSessionClosed
			}
			executionUser, err := a.validate()
			if err != nil {
				return err
			}
			if executionUser != a.executionUser {
				return ErrInteractiveSessionClosed
			}
			return nil
		})
	})
	if err != nil {
		ts.mu.Lock()
		current := ts.sessions[makeKey(serverID, sessionID)]
		ended := current == s && endLocked(s, 1, "Terminal authorization or agent connection changed.", true)
		ts.mu.Unlock()
		if ended {
			go a.close()
		}
	}
	return err
}

// CloseInteractive closes the captured control generation once. Call before
// removing the registration; legacy registrations are left to their caller.
func (ts *TerminalSessions) CloseInteractive(serverID, sessionID string) bool {
	ts.mu.Lock()
	s := ts.sessions[makeKey(serverID, sessionID)]
	if s == nil || s.interactive == nil {
		ts.mu.Unlock()
		return false
	}
	a := s.interactive
	endLocked(s, 0, "Terminal closed by the hub.", true)
	ts.mu.Unlock()
	a.close()
	return true
}
