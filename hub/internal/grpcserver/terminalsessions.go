package grpcserver

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/store"
)

// Terminal kinds distinguish the transport a shell arrived on. They are the
// values surfaced in the sessions list.
const (
	TerminalKindWeb  = "web"
	TerminalKindSSH  = "ssh"
	TerminalKindExec = "exec"
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

// terminalOutput serializes forwarding with revocation for this exact
// registration. A transport abort unblocks a write already in progress; queued
// or dequeued data cannot start a write after the revocation boundary.
type terminalOutput struct {
	writeMu sync.Mutex
	stateMu sync.Mutex
	exit    atomic.Pointer[TerminalEvent]
	writing bool
	abort   func()
}

func (o *terminalOutput) forward(write func() error) (bool, error) {
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	o.stateMu.Lock()
	if o.exit.Load() != nil {
		o.stateMu.Unlock()
		return false, nil
	}
	o.writing = true
	o.stateMu.Unlock()
	defer func() { o.stateMu.Lock(); o.writing = false; o.stateMu.Unlock() }()
	return true, write()
}
func (o *terminalOutput) revoke(exit TerminalEvent) {
	o.stateMu.Lock()
	o.exit.Store(&exit)
	abort, writing := o.abort, o.writing
	o.stateMu.Unlock()
	if writing && abort != nil {
		abort()
	}
	// Never retain stateMu while waiting for writeMu. forward acquires writeMu
	// before stateMu, so releasing here prevents an inverse-lock cycle.
	// The transport abort must release any in-flight data write before closure
	// returns. Bytes already accepted by the transport cannot be recalled.
	o.writeMu.Lock()
	o.writeMu.Unlock()
}

func (i TerminalSessionInfo) ForwardData(write func() error) (bool, error) {
	if i.output == nil {
		return false, nil
	}
	return i.output.forward(write)
}
func (i TerminalSessionInfo) ForcedExit() (TerminalEvent, bool) {
	if i.output != nil {
		if exit := i.output.exit.Load(); exit != nil {
			return *exit, true
		}
	}
	return TerminalEvent{}, false
}
func (i TerminalSessionInfo) SetOutputAbort(abort func()) {
	if i.output == nil {
		return
	}
	i.output.stateMu.Lock()
	i.output.abort = abort
	i.output.stateMu.Unlock()
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
	done         chan struct{}
	// removed is the registration lifetime. Agent-reported exit closes done,
	// but the transport may still be draining buffered output; credential and
	// authorization revalidation therefore continues until removal.
	removed     chan struct{}
	streaming   bool
	closed      bool
	interactive *interactiveAdmission
	// interactiveLiveValidate is the authority check used after admission.
	// When nil, RegisterInteractive reuses its admission validator. Browser
	// terminals set this separately so the opening access token's expiry is an
	// admission boundary, while the durable owning session remains the live
	// authority after a normal token refresh.
	interactiveLiveValidate func() (string, error)
	credentialGeneration    *int
	credentialWatchDone     chan struct{}
	credentialInvalidated   chan struct{}
	credentialWatchStopped  bool
	credentialRevoked       bool
	sshGeneration           bool
	output                  terminalOutput
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
	Done          <-chan struct{}
	AgentDone     <-chan struct{}
	output        *terminalOutput
}

type TerminalSessions struct {
	mu                   sync.Mutex
	sessions             map[string]*terminalSession
	maintenance          map[string]string
	interactiveStores    map[*store.Store]bool
	interactiveObserveMu sync.Mutex
	credentialWatchers   int
	credentialChecks     chan struct{}
	// nowFunc is swapped in tests to drive startedAt/lastActivity.
	nowFunc func() time.Time
}

func NewTerminalSessions() *TerminalSessions {
	return &TerminalSessions{
		sessions:         make(map[string]*terminalSession),
		credentialChecks: make(chan struct{}, 8),
		nowFunc:          time.Now,
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

// WithCredentialGeneration binds a shell to durable credential authority.
func WithCredentialGeneration(generation int, ssh bool) RegisterOption {
	return func(s *terminalSession) { s.credentialGeneration = &generation; s.sshGeneration = ssh }
}

// WithInteractiveLiveValidation supplies the authorization check retained by
// an established interactive terminal. Admission still uses the validator
// passed directly to RegisterInteractive.
func WithInteractiveLiveValidation(validate func() (string, error)) RegisterOption {
	return func(s *terminalSession) { s.interactiveLiveValidate = validate }
}

func (ts *TerminalSessions) Register(serverID, sessionID, userID, executionUser string, opts ...RegisterOption) (chan TerminalEvent, bool) {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.maintenance[serverID] != "" {
		return nil, false
	}
	if _, exists := ts.sessions[key]; exists {
		return nil, false
	}
	s := &terminalSession{serverID: serverID, sessionID: sessionID, userID: userID, executionUser: executionUser, kind: TerminalKindWeb}
	for _, opt := range opts {
		opt(s)
	}
	// Reservation and registration share this lock so simultaneous web, SSH
	// shell and execution submissions cannot exceed a common budget.
	var actor, node, total, interactive int
	for _, active := range ts.sessions {
		if active.closed {
			continue
		}
		if active.kind != TerminalKindExec {
			interactive++
		}
		if active.kind == TerminalKindExec {
			total++
		}
		if active.kind == TerminalKindExec && active.userID == userID {
			actor++
		}
		if active.serverID == serverID {
			node++
		}
	}
	watchCredential := s.credentialGeneration != nil && s.kind != TerminalKindExec
	if (watchCredential && ts.credentialWatchers >= 256) || (s.kind != TerminalKindExec && interactive >= 256) || node >= 8 || (s.kind == TerminalKindExec && (actor >= 4 || total >= 32)) {
		return nil, false
	}
	ch := make(chan TerminalEvent, 256)
	now := ts.nowFunc()
	s.ch, s.done, s.removed, s.startedAt, s.lastActivity = ch, make(chan struct{}), make(chan struct{}), now, now
	if watchCredential {
		ts.credentialWatchers++
		s.credentialWatchDone = make(chan struct{})
		s.credentialInvalidated = make(chan struct{})
	}
	ts.sessions[key] = s
	return ch, true
}

// ReserveMaintenance atomically requires an idle node and blocks every new
// shell/prepared execution registration until the operation is reconciled.
func (ts *TerminalSessions) ReserveMaintenance(node, id string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.maintenance[node] != "" {
		return errors.New("node update maintenance is active")
	}
	for _, s := range ts.sessions {
		if s.serverID == node && !s.closed {
			return errors.New("node has active terminal or command sessions")
		}
	}
	if ts.maintenance == nil {
		ts.maintenance = make(map[string]string)
	}
	ts.maintenance[node] = id
	return nil
}
func (ts *TerminalSessions) SetMaintenance(node, id string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.maintenance == nil {
		ts.maintenance = make(map[string]string)
	}
	if id == "" {
		delete(ts.maintenance, node)
	} else {
		ts.maintenance[node] = id
	}
}
func (ts *TerminalSessions) ReleaseMaintenance(node, id string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.maintenance[node] == id {
		delete(ts.maintenance, node)
	}
}
func (ts *TerminalSessions) MaintenanceIdle(node, id string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.maintenance[node] != id {
		return false
	}
	for _, s := range ts.sessions {
		if s.serverID == node && !s.closed {
			return false
		}
	}
	return true
}

// infoOf snapshots a session for callers. ts.mu must be held.
func infoOf(s *terminalSession) TerminalSessionInfo {
	info := TerminalSessionInfo{
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
		Done:          s.done,
		output:        &s.output,
	}
	if s.interactive != nil {
		info.AgentDone = s.interactive.conn.Done()
	}
	return info
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
	defer ts.mu.Unlock()
	s, ok := ts.sessions[key]
	if !ok || s.closed {
		return false
	}
	return ts.deliverDataLocked(s, data)
}

// AcceptAgentConnection verifies that an inbound control message belongs to
// the exact connection captured when this terminal was admitted.
func (ts *TerminalSessions) AcceptAgentConnection(serverID, sessionID string, conn *connmgr.AgentConn) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s := ts.sessions[makeKey(serverID, sessionID)]
	return s != nil && !s.closed && s.interactive != nil && s.interactive.conn == conn
}

func (ts *TerminalSessions) DeliverDataFrom(conn *connmgr.AgentConn, serverID, sessionID string, data []byte) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s := ts.sessions[makeKey(serverID, sessionID)]
	if s == nil || s.closed || s.interactive == nil || s.interactive.conn != conn {
		return false
	}
	return ts.deliverDataLocked(s, data)
}

func (ts *TerminalSessions) deliverDataLocked(s *terminalSession, data []byte) bool {
	select {
	case s.ch <- TerminalEvent{Type: TerminalEventData, Data: data}:
		if now := ts.nowFunc(); now.Sub(s.lastActivity) >= activityThrottle {
			s.lastActivity = now
		}
		return true
	default:
		return false
	}
}

// EndFrom accepts an agent-reported exit only from the connection generation
// that opened this exact terminal registration.
func (ts *TerminalSessions) EndFrom(conn *connmgr.AgentConn, serverID, sessionID string, exitCode int32, err string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s := ts.sessions[makeKey(serverID, sessionID)]
	if s == nil || s.closed || s.interactive == nil || s.interactive.conn != conn {
		return false
	}
	return endLocked(s, exitCode, err, false)
}

// End records an agent-reported exit for a session.
func (ts *TerminalSessions) End(serverID, sessionID string, exitCode int32, err string) bool {
	return ts.endSession(serverID, sessionID, exitCode, err, false)
}

// endSession ends one session, marking the exit as hub-imposed or not.
func (ts *TerminalSessions) endSession(serverID, sessionID string, exitCode int32, msg string, forced bool) bool {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	s, ok := ts.sessions[key]
	ts.mu.Unlock()
	if !ok {
		return false
	}
	if forced && s.interactive != nil {
		return ts.endInteractiveAndClose(s, exitCode, msg)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.sessions[key] != s {
		return false
	}
	return endLocked(s, exitCode, msg, forced)
}

// endLocked delivers the exit event and closes a live session, reporting
// whether it did anything. Already-closed sessions are left alone, which is
// what makes every End* variant idempotent. ts.mu must be held.
func endLocked(s *terminalSession, exitCode int32, msg string, forced bool) bool {
	if s.closed && (!forced || s.output.exit.Load() != nil) {
		return false
	}
	exit := TerminalEvent{Type: TerminalEventExit, ExitCode: exitCode, Error: msg, Forced: forced}
	if forced {
		stopCredentialWatchLocked(s)
		s.output.revoke(exit)
		discardTerminalQueue(s.ch)
	}
	if s.closed {
		return false
	}
	deliverExit(s.ch, exit)
	close(s.ch)
	close(s.done)
	s.closed = true
	return true
}

// stopCredentialWatchLocked wakes a registration's bounded revalidation
// worker without implying that worker must send TerminalClose. The caller that
// imposed a non-credential closure already owns agent cleanup. ts.mu must be
// held by the caller.
func stopCredentialWatchLocked(s *terminalSession) {
	if s.credentialInvalidated == nil || s.credentialWatchStopped {
		return
	}
	s.credentialWatchStopped = true
	close(s.credentialInvalidated)
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
	var sessions []*terminalSession
	for _, s := range ts.sessions {
		if s.userID == userID {
			sessions = append(sessions, s)
		}
	}
	ts.mu.Unlock()
	ended := 0
	for _, s := range sessions {
		if s.interactive != nil {
			if ts.endInteractiveAndClose(s, exitCode, msg) {
				ended++
			}
			continue
		}
		if ts.endSession(s.serverID, s.sessionID, exitCode, msg, true) {
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
	var sessions []*terminalSession
	for _, s := range ts.sessions {
		if s.sid == sid {
			sessions = append(sessions, s)
		}
	}
	ts.mu.Unlock()
	ended := 0
	for _, s := range sessions {
		if s.interactive != nil {
			if ts.endInteractiveAndClose(s, exitCode, msg) {
				ended++
			}
			continue
		}
		if ts.endSession(s.serverID, s.sessionID, exitCode, msg, true) {
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
	s, ok := ts.sessions[key]
	ts.mu.Unlock()
	if !ok {
		return false, false
	}
	if s.interactive != nil {
		s.interactive.controlMu.Lock()
		defer s.interactive.controlMu.Unlock()
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.sessions[key] != s {
		return false, false
	}
	alreadyClosed := s.closed
	removeLocked(s)
	delete(ts.sessions, key)
	close(s.removed)
	return alreadyClosed, true
}

func (ts *TerminalSessions) EndAll(serverID string, exitCode int32, err string) {
	ts.prepareEndAll(serverID, exitCode, err)()
}

// prepareEndAll captures exact registration objects before detaching the
// current control connection. Later disconnect bookkeeping must not close
// registrations added by an authenticated replacement connection.
func (ts *TerminalSessions) prepareEndAll(serverID string, exitCode int32, err string) func() {
	prefix := serverID + ":"
	ts.mu.Lock()
	var captured []*terminalSession
	for key, s := range ts.sessions {
		if len(key) < len(prefix) || key[:len(prefix)] != prefix {
			continue
		}
		captured = append(captured, s)
	}
	ts.mu.Unlock()
	return func() {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		for _, s := range captured {
			endLocked(s, exitCode, err, false)
		}
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
	_, removed := ts.RemoveUnattachedWithClose(serverID, sessionID)
	return removed
}

// RemoveUnattachedWithClose captures cleanup and removes one registration under
// the same lock. A delayed timer can never close a replacement connection.
func (ts *TerminalSessions) RemoveUnattachedWithClose(serverID, sessionID string) (func(), bool) {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	s, ok := ts.sessions[key]
	if !ok || s.streaming {
		ts.mu.Unlock()
		return nil, false
	}
	ts.mu.Unlock()
	if s.interactive != nil {
		s.interactive.controlMu.Lock()
		defer s.interactive.controlMu.Unlock()
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.sessions[key] != s || s.streaming {
		return nil, false
	}
	removeLocked(s)
	var closeAgent func()
	if s.interactive != nil {
		closeAgent = s.interactive.close
	}
	delete(ts.sessions, key)
	close(s.removed)
	return closeAgent, true
}

func (ts *TerminalSessions) Remove(serverID, sessionID string) bool {
	key := makeKey(serverID, sessionID)
	ts.mu.Lock()
	s, ok := ts.sessions[key]
	ts.mu.Unlock()
	if !ok {
		return false
	}
	if s.interactive != nil {
		s.interactive.controlMu.Lock()
		defer s.interactive.controlMu.Unlock()
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.sessions[key] != s {
		return false
	}
	removeLocked(s)
	delete(ts.sessions, key)
	close(s.removed)
	return true
}

// Removal invalidates retained output handles without adding an event to a
// removed channel. Active transports read the closure from their exact gate.
func removeLocked(s *terminalSession) {
	s.output.revoke(TerminalEvent{Type: TerminalEventExit, ExitCode: -1, Error: "Terminal closed by the hub.", Forced: true})
	discardTerminalQueue(s.ch)
	if !s.closed {
		close(s.ch)
		close(s.done)
		s.closed = true
	}
}
func discardTerminalQueue(ch chan TerminalEvent) {
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		default:
			return
		}
	}
}
