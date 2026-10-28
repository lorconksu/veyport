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
	admissionValidate   func() (string, error)
	liveValidate        func() (string, error)
	executionUser       string
	serverID, sessionID string
	controlMu           sync.Mutex
	admitted            bool
	closeOnce           sync.Once
}

func (a *interactiveAdmission) validate() (string, error) {
	if !a.admitted {
		return a.admissionValidate()
	}
	return a.liveValidate()
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
			if s.interactive != nil && s.interactive.st == st {
				sessions = append(sessions, s)
			}
		}
		ts.mu.Unlock()
		for _, s := range sessions {
			a := s.interactive
			a.controlMu.Lock()
			executionUser, err := a.validate()
			if err == nil && executionUser == s.executionUser {
				a.controlMu.Unlock()
				continue
			}
			ts.mu.Lock()
			// Compare registration objects: delayed work cannot invalidate a later
			// registration that happens to reuse the same key.
			current := ts.sessions[makeKey(s.serverID, s.sessionID)]
			ended := current == s && endLocked(s, 1, "Security policy or terminal authorization changed.", true)
			ts.mu.Unlock()
			a.controlMu.Unlock()
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
		admission := &interactiveAdmission{st: st, cm: cm, conn: conn, admissionValidate: validate, liveValidate: validate, executionUser: executionUser, serverID: serverID, sessionID: sessionID}
		var registered *terminalSession
		// Publish only a fully initialized interactive registration. Revocation
		// helpers retain session pointers after releasing ts.mu, so assigning the
		// immutable admission after Register made that publication racy.
		registerOpts := append([]RegisterOption(nil), opts...)
		registerOpts = append(registerOpts, func(s *terminalSession) {
			if s.interactiveLiveValidate != nil {
				admission.liveValidate = s.interactiveLiveValidate
			}
			s.interactive = admission
			registered = s
		})
		var created bool
		events, created = ts.Register(serverID, sessionID, userID, executionUser, registerOpts...)
		if !created {
			return ErrInteractiveRegistration
		}
		// A revocation may already have closed or removed this exact registration,
		// but its reserved watcher slot must still be released. Starting the
		// watcher unconditionally lets a later registration removal perform cleanup.
		if registered.credentialWatchDone != nil {
			go ts.watchCredential(registered)
		}
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
	err := a.cm.SendToConnectionGuarded(ctx, a.conn, msg, func(send func() error) error {
		return a.st.WithInteractivePolicy(func() error {
			a.controlMu.Lock()
			defer a.controlMu.Unlock()
			if !a.admitted && msg.GetTerminalOpenRequest() == nil {
				return ErrInteractiveSessionClosed
			}
			return a.st.WithTerminalAuthorizationBoundary(ctx, func() error {
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
				if err := send(); err != nil {
					return err
				}
				if msg.GetTerminalOpenRequest() != nil {
					a.admitted = true
				}
				return nil
			})
		})
	})
	if err != nil {
		ended := ts.endInteractiveExact(s, 1, "Terminal authorization or agent connection changed.")
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
	ts.mu.Unlock()
	ts.endInteractiveExact(s, 0, "Terminal closed by the hub.")
	a.close()
	return true
}

func (ts *TerminalSessions) endInteractiveExact(s *terminalSession, exitCode int32, msg string) bool {
	a := s.interactive
	if a != nil {
		a.controlMu.Lock()
		defer a.controlMu.Unlock()
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	current := ts.sessions[makeKey(s.serverID, s.sessionID)]
	return current == s && endLocked(s, exitCode, msg, true)
}

// endInteractiveAndClose ends the exact registration under its local
// authorization boundary, then closes only the captured agent connection after
// those locks are released. This covers forced closures even when no browser or
// SSH transport is attached to perform teardown.
func (ts *TerminalSessions) endInteractiveAndClose(s *terminalSession, exitCode int32, msg string) bool {
	ended := ts.endInteractiveExact(s, exitCode, msg)
	if ended {
		go s.interactive.close()
	}
	return ended
}

// One watcher per credential-bound shell, capped by the registry's 256-shell
// budget. Registration removal cancels it. An agent-reported exit can leave
// buffered output for the transport, so it does not end revalidation.
// Output generates no additional DB work.
const CredentialRevalidationInterval = time.Second

// credentialLive shares the watcher query budget and deadline with synchronous
// post-transition cleanup. Neither path can fan out unbounded database work.
func (ts *TerminalSessions) credentialLive(st *store.Store, s *terminalSession) bool {
	ts.mu.Lock()
	interactive := s.interactive != nil
	ts.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), store.TerminalCredentialTimeout)
	defer cancel()
	select {
	case ts.credentialChecks <- struct{}{}:
		defer func() { <-ts.credentialChecks }()
		if interactive {
			if s.interactive.cm.GetConn(s.serverID) != s.interactive.conn {
				return false
			}
			if !s.sshGeneration && s.sid != "" {
				return st.TerminalAuthorizationLive(ctx, s.userID, s.serverID, s.executionUser, *s.credentialGeneration, false, s.sid)
			}
			return st.TerminalAuthorizationLive(ctx, s.userID, s.serverID, s.executionUser, *s.credentialGeneration, s.sshGeneration)
		}
		return st.TerminalCredentialLive(ctx, s.userID, *s.credentialGeneration, s.sshGeneration)
	case <-s.removed:
		return false
	case <-s.credentialInvalidated:
		return false
	case <-ctx.Done():
		return false
	}
}

func (ts *TerminalSessions) endStaleCredential(s *terminalSession) {
	a := s.interactive
	if a != nil {
		a.controlMu.Lock()
		defer a.controlMu.Unlock()
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	current := ts.sessions[makeKey(s.serverID, s.sessionID)]
	if current != s || s.credentialRevoked {
		return
	}
	s.credentialRevoked = true
	endLocked(s, 1, "Terminal credentials or authorization revoked.", true)
}

// EndStaleCredentials uses captured credential epochs, never a user-wide sweep.
// Every production browser/SSH admission binds an epoch. Execution markers use
// the same epoch checks and their existing cancellation path, without watchers.
func (ts *TerminalSessions) EndStaleCredentials(st *store.Store, user string) {
	ts.mu.Lock()
	var sessions []*terminalSession
	for _, s := range ts.sessions {
		if s.userID == user && !s.credentialRevoked && s.credentialGeneration != nil {
			sessions = append(sessions, s)
		}
	}
	ts.mu.Unlock()
	for _, s := range sessions {
		if !ts.credentialLive(st, s) {
			ts.endStaleCredential(s)
		}
	}
}

func (ts *TerminalSessions) watchCredential(s *terminalSession) {
	defer func() {
		ts.mu.Lock()
		revoked := s.credentialRevoked
		ts.mu.Unlock()
		// Retain the bounded watcher slot through captured-connection cleanup,
		// including revocation initiated synchronously by apply/reconcile.
		if revoked {
			s.interactive.close()
		}
		ts.mu.Lock()
		ts.credentialWatchers--
		close(s.credentialWatchDone)
		ts.mu.Unlock()
	}()
	ticker := time.NewTicker(CredentialRevalidationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.removed:
			return
		case <-s.credentialInvalidated:
			return
		case <-s.interactive.conn.Done():
			ts.endStaleCredential(s)
			return
		case <-ticker.C:
			if ts.credentialLive(s.interactive.st, s) {
				continue
			}
			ts.endStaleCredential(s)
			return
		}
	}
}
