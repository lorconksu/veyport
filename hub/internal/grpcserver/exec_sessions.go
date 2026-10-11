package grpcserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

const (
	MaxExecutionCommandBytes = 32 * 1024
	MaxExecutionFrameBytes   = 64 * 1024
	ExecutionAttachTimeout   = 60 * time.Second
	executionQueueFrames     = 8
)

var ErrExecutionUnsupported = errors.New("the connected agent does not support command execution; upgrade the agent")
var ErrExecutionInputFinished = errors.New("execution no longer accepts stdin")

func DefaultExecutionLimits() *pb.ExecutionLimits {
	return &pb.ExecutionLimits{MaxFrameBytes: MaxExecutionFrameBytes, MaxBufferBytes: 2 * 1024 * 1024, RuntimeSeconds: 3600, TermGraceSeconds: 5, BlockedConsumerSeconds: 60}
}

type executionCapability struct {
	connection *connmgr.AgentConn
	capability *pb.ExecutionCapabilities
}

// ExecutionSessions owns preparation and one-use attachment, never raw commands.
// Three eight-frame queues plus in-flight frames stay below the 2MiB budget.
type ExecutionSessions struct {
	mu           sync.Mutex
	sessions     map[string]*ExecutionSession
	capabilities map[string]executionCapability
	terminals    *TerminalSessions
	connections  *connmgr.ConnManager
	rpcSlots     chan struct{}
}

type ExecutionSession struct {
	ID, NodeID, ActorID, RequestedUser string
	Revocations                        <-chan TerminalEvent
	Stdout                             <-chan []byte
	Stderr                             <-chan []byte
	Result                             <-chan *pb.ExecutionResult
	Attached                           <-chan struct{}
	Started                            <-chan struct{}
	Done                               <-chan struct{}
	registry                           *ExecutionSessions
	connection                         *connmgr.AgentConn
	bootID                             string
	commandHash                        [32]byte
	mu                                 sync.Mutex
	prepared                           *pb.ExecutionPrepared
	preparedReady                      chan struct{}
	prepareErr                         error
	ticket                             [32]byte
	ticketIssued, ticketUsed, dispatch bool
	attached                           chan struct{}
	started                            chan struct{}
	start                              chan *pb.ExecutionStart
	stdin                              chan *pb.ExecutionHubMessage
	stdout, stderr                     chan []byte
	result                             chan *pb.ExecutionResult
	done                               chan struct{}
	transportDone                      chan struct{}
	cancelOnce                         sync.Once
	reason                             string
	inputSequence                      uint64
	inputClosed                        bool
	inputMu                            sync.Mutex
}

func NewExecutionSessions(terminals *TerminalSessions, connections *connmgr.ConnManager) *ExecutionSessions {
	if terminals == nil {
		terminals = NewTerminalSessions()
	}
	return &ExecutionSessions{sessions: make(map[string]*ExecutionSession), capabilities: make(map[string]executionCapability), terminals: terminals, connections: connections, rpcSlots: make(chan struct{}, 32)}
}

func executionConnectionOpen(connection *connmgr.AgentConn) bool {
	if connection == nil {
		return false
	}
	select {
	case <-connection.Done():
		return false
	default:
		return true
	}
}

func (es *ExecutionSessions) SetCapabilities(node string, stream pb.AgentService_ConnectServer, caps *pb.ExecutionCapabilities) {
	conn := es.connections.GetConn(node)
	if !executionConnectionOpen(conn) || conn.Stream != stream {
		return
	}
	es.mu.Lock()
	valid := caps != nil && caps.ProtocolVersion == 1 && caps.StandardExec && caps.BootId != "" && len(caps.BootId) <= 128
	previous := es.capabilities[node]
	var cancelled []*ExecutionSession
	if !valid || (previous.capability != nil && previous.capability.BootId != caps.BootId) {
		for _, s := range es.sessions {
			if s.NodeID == node {
				cancelled = append(cancelled, s)
			}
		}
	}
	if valid {
		es.capabilities[node] = executionCapability{conn, proto.Clone(caps).(*pb.ExecutionCapabilities)}
	} else {
		delete(es.capabilities, node)
	}
	es.mu.Unlock()
	for _, s := range cancelled {
		s.Cancel("agent execution capability or boot changed")
	}
}

func (es *ExecutionSessions) Supports(node string) bool {
	es.mu.Lock()
	defer es.mu.Unlock()
	caps, ok := es.capabilities[node]
	if !ok || caps.connection != es.connections.GetConn(node) {
		return false
	}
	return executionConnectionOpen(caps.connection)
}

func (es *ExecutionSessions) Register(node, id, actor, runAs string, command []byte) (*ExecutionSession, error) {
	if node == "" || id == "" || actor == "" || len(id) > 128 || len(command) == 0 || len(command) > MaxExecutionCommandBytes || !utf8.Valid(command) || strings.ContainsRune(string(command), '\x00') {
		return nil, errors.New("invalid execution submission")
	}
	es.mu.Lock()
	defer es.mu.Unlock()
	caps, ok := es.capabilities[node]
	if !ok || caps.connection != es.connections.GetConn(node) || !executionConnectionOpen(caps.connection) {
		return nil, ErrExecutionUnsupported
	}
	key := makeKey(node, id)
	if _, exists := es.sessions[key]; exists {
		return nil, errors.New("execution already registered")
	}
	marker, ok := es.terminals.Register(node, id, actor, runAs, WithKind(TerminalKindExec))
	if !ok {
		return nil, errors.New("shared terminal and execution capacity reached")
	}
	_, _, _ = es.terminals.AttachStream(node, id, actor)
	s := &ExecutionSession{ID: id, NodeID: node, ActorID: actor, RequestedUser: runAs, Revocations: marker, registry: es, connection: caps.connection, bootID: caps.capability.BootId, commandHash: sha256.Sum256(command), preparedReady: make(chan struct{}), attached: make(chan struct{}), started: make(chan struct{}), start: make(chan *pb.ExecutionStart, 1), stdin: make(chan *pb.ExecutionHubMessage, executionQueueFrames), stdout: make(chan []byte, executionQueueFrames), stderr: make(chan []byte, executionQueueFrames), result: make(chan *pb.ExecutionResult, 1), done: make(chan struct{})}
	s.Stdout, s.Stderr, s.Result, s.Attached, s.Started, s.Done = s.stdout, s.stderr, s.result, s.attached, s.started, s.done
	s.transportDone = make(chan struct{})
	es.sessions[key] = s
	return s, nil
}

func (es *ExecutionSessions) Remove(node, id string) {
	es.mu.Lock()
	s := es.sessions[makeKey(node, id)]
	delete(es.sessions, makeKey(node, id))
	es.mu.Unlock()
	if s != nil {
		s.Cancel("execution closed")
		es.terminals.Remove(node, id)
	}
}

func (es *ExecutionSessions) EndAll(node, reason string) {
	es.mu.Lock()
	var sessions []*ExecutionSession
	for _, s := range es.sessions {
		if s.NodeID == node {
			sessions = append(sessions, s)
		}
	}
	delete(es.capabilities, node)
	es.mu.Unlock()
	for _, s := range sessions {
		s.Cancel(reason)
	}
}

func (es *ExecutionSessions) DeliverPrepared(node string, stream pb.AgentService_ConnectServer, p *pb.ExecutionPrepared) bool {
	if p == nil {
		return false
	}
	es.mu.Lock()
	s := es.sessions[makeKey(node, p.ExecutionId)]
	es.mu.Unlock()
	if s == nil || s.connection.Stream != stream || s.connection != es.connections.GetConn(node) || !executionConnectionOpen(s.connection) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepared != nil || s.prepareErr != nil {
		return false
	}
	err := s.validatePrepared(p)
	if err != nil {
		s.prepareErr = err
	} else {
		s.prepared = proto.Clone(p).(*pb.ExecutionPrepared)
	}
	close(s.preparedReady)
	return err == nil
}

func (es *ExecutionSessions) hasExecution(node, id string) bool {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.sessions[makeKey(node, id)] != nil
}

func (s *ExecutionSession) validatePrepared(p *pb.ExecutionPrepared) error {
	if p.Error != "" {
		return errors.New("agent could not prepare execution")
	}
	b, i := p.Binding, p.Identity
	if b == nil || b.ExecutionId != s.ID || b.NodeId != s.NodeID || b.PreparationId == "" || len(b.PreparationId) > 128 || b.BootId != s.bootID || b.ExpiresUnixMilli <= time.Now().UnixMilli() || b.ExpiresUnixMilli > time.Now().Add(ExecutionAttachTimeout).UnixMilli() {
		return errors.New("invalid execution preparation binding")
	}
	if !bytes.Equal(p.CommandSha256, s.commandHash[:]) || !proto.Equal(p.Limits, DefaultExecutionLimits()) {
		return errors.New("execution preparation content or limits changed")
	}
	if i == nil || i.Username == "" || len(i.Username) > 256 || i.Shell == "" || len(i.Shell) > 4096 || i.Cwd == "" || len(i.Cwd) > 4096 || len(i.Home) > 4096 || len(i.Groups) > 1024 || len(i.IdentitySha256) != 32 || len(i.GroupsSha256) != 32 || (s.RequestedUser != "" && i.Username != s.RequestedUser) {
		return errors.New("invalid prepared execution identity")
	}
	return nil
}

func (s *ExecutionSession) WaitPrepared(ctx context.Context) (*pb.ExecutionPrepared, error) {
	select {
	case <-s.preparedReady:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, errors.New(s.Reason())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepareErr != nil {
		return nil, s.prepareErr
	}
	return proto.Clone(s.prepared).(*pb.ExecutionPrepared), nil
}

func (s *ExecutionSession) IssueAttach() (*pb.ExecutionAttachRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepared == nil || s.ticketIssued || s.prepared.Binding.ExpiresUnixMilli <= time.Now().UnixMilli() {
		return nil, errors.New("preparation not available for attachment")
	}
	if _, err := rand.Read(s.ticket[:]); err != nil {
		return nil, err
	}
	s.ticketIssued = true
	return &pb.ExecutionAttachRequest{Binding: proto.Clone(s.prepared.Binding).(*pb.ExecutionBinding), Ticket: append([]byte(nil), s.ticket[:]...)}, nil
}

func (es *ExecutionSessions) Attach(node string, a *pb.ExecutionAttachRequest) (*ExecutionSession, error) {
	if a == nil || a.Binding == nil || a.Binding.NodeId != node || len(a.Ticket) != 32 {
		return nil, errors.New("invalid execution attachment")
	}
	es.mu.Lock()
	defer es.mu.Unlock()
	s := es.sessions[makeKey(node, a.Binding.ExecutionId)]
	if s == nil || s.connection != es.connections.GetConn(node) || !executionConnectionOpen(s.connection) {
		return nil, errors.New("execution preparation unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return nil, errors.New("execution cancelled")
	default:
	}
	if s.prepared == nil || !s.ticketIssued || s.ticketUsed || !proto.Equal(a.Binding, s.prepared.Binding) || a.Binding.ExpiresUnixMilli <= time.Now().UnixMilli() || subtle.ConstantTimeCompare(a.Ticket, s.ticket[:]) != 1 {
		return nil, errors.New("invalid or consumed execution attachment")
	}
	s.ticketUsed = true
	clear(s.ticket[:])
	return s, nil
}

// Dispatch allows exactly one Start after the caller's live authorization check.
func (s *ExecutionSession) Dispatch() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepared == nil || !s.ticketUsed || s.dispatch || s.connection != s.registry.connections.GetConn(s.NodeID) || !executionConnectionOpen(s.connection) || s.prepared.Binding.ExpiresUnixMilli <= time.Now().UnixMilli() {
		return errors.New("execution is not dispatchable")
	}
	select {
	case <-s.done:
		return errors.New(s.reason)
	default:
	}
	s.dispatch = true
	p := s.prepared
	s.start <- &pb.ExecutionStart{Binding: proto.Clone(p.Binding).(*pb.ExecutionBinding), CommandSha256: append([]byte(nil), p.CommandSha256...), IdentitySha256: append([]byte(nil), p.Identity.IdentitySha256...), Limits: proto.Clone(p.Limits).(*pb.ExecutionLimits), PolicyVersion: "standard-v1"}
	return nil
}

func (s *ExecutionSession) SendInput(ctx context.Context, data []byte) error {
	if len(data) > MaxExecutionFrameBytes {
		return errors.New("execution input frame too large")
	}
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	if s.inputClosed {
		return errors.New("execution stdin already closed")
	}
	msg := &pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_Input{Input: &pb.ExecutionData{Sequence: s.inputSequence, Data: append([]byte(nil), data...)}}}
	if err := s.enqueueInput(ctx, msg); err != nil {
		return err
	}
	s.inputSequence++
	return nil
}

func (s *ExecutionSession) CloseInput(ctx context.Context) error {
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	if s.inputClosed {
		return nil
	}
	msg := &pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_InputEof{InputEof: &pb.ExecutionInputEOF{Sequence: s.inputSequence}}}
	if err := s.enqueueInput(ctx, msg); err != nil {
		return err
	}
	s.inputClosed = true
	return nil
}

func (s *ExecutionSession) enqueueInput(ctx context.Context, msg *pb.ExecutionHubMessage) error {
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	select {
	case s.stdin <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return errors.New("execution cancelled")
	case <-s.transportDone:
		return ErrExecutionInputFinished
	case <-timer.C:
		return errors.New("execution input consumer stalled")
	}
}

func (s *ExecutionSession) Cancel(reason string) {
	s.cancelOnce.Do(func() { s.mu.Lock(); s.reason = reason; s.mu.Unlock(); close(s.done) })
}
func (s *ExecutionSession) Reason() string { s.mu.Lock(); defer s.mu.Unlock(); return s.reason }

func (s *ExecutionSession) Binding() *pb.ExecutionBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepared == nil {
		return &pb.ExecutionBinding{ExecutionId: s.ID, NodeId: s.NodeID, BootId: s.bootID}
	}
	return proto.Clone(s.prepared.Binding).(*pb.ExecutionBinding)
}

func (s *ExecutionSession) String() string {
	return fmt.Sprintf("execution %s on node %s", s.ID, s.NodeID)
}
