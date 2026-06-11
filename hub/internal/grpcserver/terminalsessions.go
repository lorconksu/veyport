package grpcserver

import "sync"

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
}

type terminalSession struct {
	userID        string
	executionUser string
	ch            chan TerminalEvent
	streaming     bool
	closed        bool
}

type TerminalSessionInfo struct {
	UserID        string
	ExecutionUser string
	Ch            <-chan TerminalEvent
	Closed        bool
}

type TerminalSessions struct {
	mu       sync.Mutex
	sessions map[string]*terminalSession
}

func NewTerminalSessions() *TerminalSessions {
	return &TerminalSessions{
		sessions: make(map[string]*terminalSession),
	}
}

func (ts *TerminalSessions) Register(serverID, sessionID, userID, executionUser string) (chan TerminalEvent, bool) {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if _, exists := ts.sessions[key]; exists {
		return nil, false
	}
	ch := make(chan TerminalEvent, 256)
	ts.sessions[key] = &terminalSession{
		userID:        userID,
		executionUser: executionUser,
		ch:            ch,
	}
	return ch, true
}

func (ts *TerminalSessions) Get(serverID, sessionID string) (TerminalSessionInfo, bool) {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s, ok := ts.sessions[key]
	if !ok {
		return TerminalSessionInfo{}, false
	}
	return TerminalSessionInfo{
		UserID:        s.userID,
		ExecutionUser: s.executionUser,
		Ch:            s.ch,
		Closed:        s.closed,
	}, true
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
	return TerminalSessionInfo{
		UserID:        s.userID,
		ExecutionUser: s.executionUser,
		Ch:            s.ch,
		Closed:        s.closed,
	}, true, true
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
		ts.mu.Unlock()
		return true
	default:
		ts.mu.Unlock()
		return false
	}
}

func (ts *TerminalSessions) End(serverID, sessionID string, exitCode int32, err string) bool {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s, ok := ts.sessions[key]
	if !ok || s.closed {
		return false
	}
	deliverExit(s.ch, TerminalEvent{Type: TerminalEventExit, ExitCode: exitCode, Error: err})
	close(s.ch)
	s.closed = true
	return true
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
		if len(key) < len(prefix) || key[:len(prefix)] != prefix || s.closed {
			continue
		}
		deliverExit(s.ch, TerminalEvent{Type: TerminalEventExit, ExitCode: exitCode, Error: err})
		close(s.ch)
		s.closed = true
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
