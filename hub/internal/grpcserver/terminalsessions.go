package grpcserver

import (
	"sort"
	"sync"
	"time"
)

// Terminal kinds distinguish the transport a shell arrived on. They are the
// values surfaced in the sessions list.
const (
	TerminalKindWeb = "web"
	TerminalKindSSH = "ssh"
)

// activityThrottle is how often a stream of output is allowed to move a
// session's lastActivity. Terminal data arrives in a hot loop, so bumping the
// timestamp on every chunk would be pure lock churn.
const activityThrottle = time.Second

type TerminalEventType string

const (
	TerminalEventData TerminalEventType = "data"
	TerminalEventExit TerminalEventType = "exit"
)

type TerminalEvent struct {
	Type     TerminalEventType
	Data     []byte
	ExitCode int32
	Error    string
	// Forced marks an exit the hub imposed — a revoked session, a disabled
	// account, an administrator ending one shell — rather than one the agent
	// reported. The transports use it to tell the operator why the shell went
	// away and to close the still-running remote shell on the agent.
	Forced bool
}

type terminalSession struct {
	serverID      string
	sessionID     string
	userID        string
	executionUser string
	// kind is the transport the shell came in on: TerminalKindWeb or
	// TerminalKindSSH.
	kind string
	// sid is the server-side session that owns this shell, so revoking that
	// session can take its terminals with it. Empty for SSH gateway shells,
	// which authenticate with a certificate rather than a web/CLI session.
	sid          string
	startedAt    time.Time
	lastActivity time.Time
	ch           chan TerminalEvent
	streaming    bool
	closed       bool
}

type TerminalSessionInfo struct {
	ServerID      string
	SessionID     string
	UserID        string
	ExecutionUser string
	Kind          string
	SID           string
	StartedAt     time.Time
	LastActivity  time.Time
	Ch            <-chan TerminalEvent
	Closed        bool
}

type TerminalSessions struct {
	mu       sync.Mutex
	sessions map[string]*terminalSession
	// nowFunc is swapped in tests to drive startedAt/lastActivity.
	nowFunc func() time.Time
}

func NewTerminalSessions() *TerminalSessions {
	return &TerminalSessions{
		sessions: make(map[string]*terminalSession),
		nowFunc:  time.Now,
	}
}

// RegisterOption sets optional metadata on a terminal session at registration
// time. Options keep Register's signature stable for the callers that only
// need the defaults.
type RegisterOption func(*terminalSession)

// WithKind records the transport a shell arrived on. Registrations without it
// are web terminals.
func WithKind(kind string) RegisterOption {
	return func(s *terminalSession) { s.kind = kind }
}

// WithSessionID ties a shell to the server-side session that opened it, so
// revoking that session closes the shell too.
func WithSessionID(sid string) RegisterOption {
	return func(s *terminalSession) { s.sid = sid }
}

func (ts *TerminalSessions) Register(serverID, sessionID, userID, executionUser string, opts ...RegisterOption) (chan TerminalEvent, bool) {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if _, exists := ts.sessions[key]; exists {
		return nil, false
	}
	ch := make(chan TerminalEvent, 256)
	now := ts.nowFunc()
	s := &terminalSession{
		serverID:      serverID,
		sessionID:     sessionID,
		userID:        userID,
		executionUser: executionUser,
		kind:          TerminalKindWeb,
		startedAt:     now,
		lastActivity:  now,
		ch:            ch,
	}
	for _, opt := range opts {
		opt(s)
	}
	ts.sessions[key] = s
	return ch, true
}

// infoOf snapshots a session for callers. ts.mu must be held.
func infoOf(s *terminalSession) TerminalSessionInfo {
	return TerminalSessionInfo{
		ServerID:      s.serverID,
		SessionID:     s.sessionID,
		UserID:        s.userID,
		ExecutionUser: s.executionUser,
		Kind:          s.kind,
		SID:           s.sid,
		StartedAt:     s.startedAt,
		LastActivity:  s.lastActivity,
		Ch:            s.ch,
		Closed:        s.closed,
	}
}

func (ts *TerminalSessions) Get(serverID, sessionID string) (TerminalSessionInfo, bool) {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s, ok := ts.sessions[key]
	if !ok {
		return TerminalSessionInfo{}, false
	}
	return infoOf(s), true
}

func (ts *TerminalSessions) AttachStream(serverID, sessionID, userID string) (TerminalSessionInfo, bool, bool) {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s, ok := ts.sessions[key]
	if !ok || s.userID != userID {
		return TerminalSessionInfo{}, false, false
	}
	if s.streaming {
		return TerminalSessionInfo{}, true, false
	}
	s.streaming = true
	return infoOf(s), true, true
}

func (ts *TerminalSessions) DeliverData(serverID, sessionID string, data []byte) bool {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	s, ok := ts.sessions[key]
	if !ok || s.closed {
		ts.mu.Unlock()
		return false
	}
	select {
	case s.ch <- TerminalEvent{Type: TerminalEventData, Data: data}:
		if now := ts.nowFunc(); now.Sub(s.lastActivity) >= activityThrottle {
			s.lastActivity = now
		}
		ts.mu.Unlock()
		return true
	default:
		ts.mu.Unlock()
		return false
	}
}

// End records an agent-reported exit for a session.
func (ts *TerminalSessions) End(serverID, sessionID string, exitCode int32, err string) bool {
	return ts.endSession(serverID, sessionID, exitCode, err, false)
}

// endSession ends one session, marking the exit as hub-imposed or not.
func (ts *TerminalSessions) endSession(serverID, sessionID string, exitCode int32, msg string, forced bool) bool {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s, ok := ts.sessions[key]
	if !ok {
		return false
	}
	return endLocked(s, exitCode, msg, forced)
}

// endLocked delivers the exit event and closes a live session, reporting
// whether it did anything. Already-closed sessions are left alone, which is
// what makes every End* variant idempotent. ts.mu must be held.
func endLocked(s *terminalSession, exitCode int32, msg string, forced bool) bool {
	if s.closed {
		return false
	}
	deliverExit(s.ch, TerminalEvent{
		Type: TerminalEventExit, ExitCode: exitCode, Error: msg, Forced: forced,
	})
	close(s.ch)
	s.closed = true
	return true
}

// ListByUser returns the user's live shells, oldest first.
func (ts *TerminalSessions) ListByUser(userID string) []TerminalSessionInfo {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var out []TerminalSessionInfo
	for _, s := range ts.sessions {
		if s.closed || s.userID != userID {
			continue
		}
		out = append(out, infoOf(s))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.Before(out[j].StartedAt)
		}
		return makeKey(out[i].ServerID, out[i].SessionID) < makeKey(out[j].ServerID, out[j].SessionID)
	})
	return out
}

// EndByUser closes every live shell owned by a user and returns how many it
// closed. Used when an account is disabled or all its sessions are revoked.
func (ts *TerminalSessions) EndByUser(userID string, exitCode int32, msg string) int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ended := 0
	for _, s := range ts.sessions {
		if s.userID != userID {
			continue
		}
		if endLocked(s, exitCode, msg, true) {
			ended++
		}
	}
	return ended
}

// EndBySession closes every live shell opened under one server-side session.
// An empty sid matches nothing, so shells with no owning session (the SSH
// gateway's) are never caught by it.
func (ts *TerminalSessions) EndBySession(sid string, exitCode int32, msg string) int {
	if sid == "" {
		return 0
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ended := 0
	for _, s := range ts.sessions {
		if s.sid != sid {
			continue
		}
		if endLocked(s, exitCode, msg, true) {
			ended++
		}
	}
	return ended
}

// EndOne closes a single live shell on the hub's initiative, reporting whether
// it was live.
func (ts *TerminalSessions) EndOne(serverID, sessionID string, exitCode int32, msg string) bool {
	return ts.endSession(serverID, sessionID, exitCode, msg, true)
}

// RemoveIfHubInitiated removes the session entry from the map and returns
// (alreadyClosed, removed). When alreadyClosed is true the caller should
// suppress the redundant TerminalClose gRPC send to the agent — the agent
// already reported its exit via End().
func (ts *TerminalSessions) RemoveIfHubInitiated(serverID, sessionID string) (bool, bool) {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s, ok := ts.sessions[key]
	if !ok {
		return false, false
	}
	alreadyClosed := s.closed
	if !s.closed {
		close(s.ch)
		s.closed = true
	}
	delete(ts.sessions, key)
	return alreadyClosed, true
}

func (ts *TerminalSessions) EndAll(serverID string, exitCode int32, err string) {
	prefix := serverID + ":"
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for key, s := range ts.sessions {
		if len(key) < len(prefix) || key[:len(prefix)] != prefix {
			continue
		}
		endLocked(s, exitCode, err, false)
	}
}

// deliverExit guarantees that a terminal exit event is enqueued by evicting the
// oldest buffered data event when the channel is full. Without this, a slow or
// unattached SSE consumer would surface the channel close as a generic
// "connection lost" instead of the agent-reported exit code/error.
func deliverExit(ch chan TerminalEvent, evt TerminalEvent) {
	for len(ch) == cap(ch) {
		select {
		case <-ch:
		default:
			return
		}
	}
	ch <- evt
}

func (ts *TerminalSessions) RemoveUnattached(serverID, sessionID string) bool {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s, ok := ts.sessions[key]
	if !ok || s.streaming {
		return false
	}
	if !s.closed {
		close(s.ch)
	}
	delete(ts.sessions, key)
	return true
}

func (ts *TerminalSessions) Remove(serverID, sessionID string) bool {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	removed := false
	if s, ok := ts.sessions[key]; ok {
		if !s.closed {
			close(s.ch)
		}
		delete(ts.sessions, key)
		removed = true
	}
	ts.mu.Unlock()
	return removed
}
