// Package execution owns prepared, noninteractive processes. It never uses the
// interactive terminal transport, a PTY, or a dropping output queue.
package execution

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/wyiu/veyport/agent/internal/executionidentity"
	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const (
	MaxCommandBytes = 32 * 1024
	MaxFrameBytes   = 64 * 1024
	MaxBufferBytes  = 2 * 1024 * 1024
	// 1MiB of queued data leaves room for reader buffers, in-flight frames,
	// command/identity metadata and serialization within the 2MiB budget.
	queueFrames = 8
)

type Config struct {
	NodeID          string
	Journal         *Journal
	Budget          *sessionlimit.Budget
	Resolve         func(string, string) (*executionidentity.Identity, error)
	PreparationTTL  time.Duration
	TermGrace       time.Duration
	BlockedConsumer time.Duration
}
type preparation struct {
	response     *pb.ExecutionPrepared
	identity     *executionidentity.Identity
	command      string
	runAsUser    string
	timer        *time.Timer
	attached     bool
	launchCancel context.CancelFunc
}
type Manager struct {
	mu                  sync.Mutex
	nodeID, bootID      string
	journal             *Journal
	budget              *sessionlimit.Budget
	resolve             func(string, string) (*executionidentity.Identity, error)
	ttl, grace, blocked time.Duration
	prepared            map[string]*preparation
	pending             map[string]bool
	launching           map[string]*preparation
	launchWG            sync.WaitGroup
	runs                map[string]*Run
	closed              bool
}

func NewManager(cfg Config) (*Manager, error) {
	if cfg.NodeID == "" || cfg.Journal == nil {
		return nil, fmt.Errorf("node and durable execution journal required")
	}
	boot, err := randomID()
	if err != nil {
		return nil, err
	}
	if cfg.Budget == nil {
		cfg.Budget = sessionlimit.New(8)
	}
	if cfg.Resolve == nil {
		cfg.Resolve = executionidentity.Resolve
	}
	if cfg.PreparationTTL <= 0 {
		cfg.PreparationTTL = time.Minute
	}
	if cfg.TermGrace <= 0 {
		cfg.TermGrace = 5 * time.Second
	}
	if cfg.BlockedConsumer <= 0 {
		cfg.BlockedConsumer = time.Minute
	}
	return &Manager{nodeID: cfg.NodeID, bootID: boot, journal: cfg.Journal, budget: cfg.Budget, resolve: cfg.Resolve, ttl: cfg.PreparationTTL, grace: cfg.TermGrace, blocked: cfg.BlockedConsumer, prepared: make(map[string]*preparation), pending: make(map[string]bool), launching: make(map[string]*preparation), runs: make(map[string]*Run)}, nil
}
func randomID() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}
func (m *Manager) Capabilities() *pb.ExecutionCapabilities {
	return &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, ProtectedScript: false, BootId: m.bootID}
}
func normalizeLimits(limits *pb.ExecutionLimits) (*pb.ExecutionLimits, error) {
	result := &pb.ExecutionLimits{MaxFrameBytes: MaxFrameBytes, MaxBufferBytes: MaxBufferBytes, RuntimeSeconds: 3600, TermGraceSeconds: 5, BlockedConsumerSeconds: 60}
	if limits == nil {
		return result, nil
	}
	if (limits.MaxFrameBytes != 0 && limits.MaxFrameBytes != MaxFrameBytes) || (limits.MaxBufferBytes != 0 && limits.MaxBufferBytes != MaxBufferBytes) || (limits.TermGraceSeconds != 0 && limits.TermGraceSeconds != 5) || (limits.BlockedConsumerSeconds != 0 && limits.BlockedConsumerSeconds != 60) || limits.RuntimeSeconds > 3600 {
		return nil, fmt.Errorf("unsupported execution limits")
	}
	if limits.RuntimeSeconds != 0 {
		result.RuntimeSeconds = limits.RuntimeSeconds
	}
	return result, nil
}
func (m *Manager) Prepare(req *pb.ExecutionPrepare) *pb.ExecutionPrepared {
	response := &pb.ExecutionPrepared{}
	if req == nil {
		response.Error = "execution preparation required"
		return response
	}
	response.ExecutionId = req.ExecutionId
	fail := func(err error) *pb.ExecutionPrepared { response.Error = err.Error(); return response }
	if req.ExecutionId == "" || len(req.ExecutionId) > 128 || req.NodeId != m.nodeID {
		return fail(fmt.Errorf("invalid execution ownership"))
	}
	if req.Enhanced || len(req.ScriptSha256) != 0 || req.ScriptLength != 0 {
		return fail(fmt.Errorf("protected execution is not supported by this agent"))
	}
	if req.Command == "" || len(req.Command) > MaxCommandBytes || !utf8.ValidString(req.Command) || strings.IndexByte(req.Command, 0) >= 0 {
		return fail(fmt.Errorf("invalid execution command"))
	}
	if _, exists := m.journal.Status(req.ExecutionId); exists {
		return fail(ErrAlreadyClaimed)
	}
	limits, err := normalizeLimits(req.Limits)
	if err != nil {
		return fail(err)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return fail(fmt.Errorf("execution manager unavailable"))
	}
	if m.pending[req.ExecutionId] || m.prepared[req.ExecutionId] != nil || m.launching[req.ExecutionId] != nil || m.runs[req.ExecutionId] != nil {
		m.mu.Unlock()
		return fail(fmt.Errorf("execution already prepared"))
	}
	if !m.budget.Acquire() {
		m.mu.Unlock()
		return fail(fmt.Errorf("too many active terminal/execution sessions"))
	}
	m.pending[req.ExecutionId] = true
	m.mu.Unlock()
	installed := false
	defer func() {
		m.mu.Lock()
		delete(m.pending, req.ExecutionId)
		m.mu.Unlock()
		if !installed {
			m.budget.Release()
		}
	}()
	identity, err := m.resolve(req.RunAsUser, req.Cwd)
	if err != nil {
		return fail(err)
	}
	prepID, err := randomID()
	if err != nil {
		return fail(err)
	}
	hash := sha256.Sum256([]byte(req.Command))
	response.Binding = &pb.ExecutionBinding{ExecutionId: req.ExecutionId, NodeId: m.nodeID, PreparationId: prepID, BootId: m.bootID, ExpiresUnixMilli: time.Now().Add(m.ttl).UnixMilli()}
	response.Identity = &pb.ExecutionIdentity{Username: identity.Username, Uid: identity.UID, Gid: identity.GID, Groups: append([]uint32(nil), identity.Groups...), GroupsSha256: identity.GroupsDigest(), Home: identity.Home, Shell: identity.Shell, Cwd: identity.Cwd, IdentitySha256: identity.Digest()}
	response.CommandSha256 = hash[:]
	response.Limits = limits
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fail(fmt.Errorf("execution manager unavailable"))
	}
	if _, exists := m.prepared[req.ExecutionId]; exists {
		return fail(fmt.Errorf("execution already prepared"))
	}
	if _, exists := m.runs[req.ExecutionId]; exists {
		return fail(ErrAlreadyClaimed)
	}
	p := &preparation{response: response, identity: identity, command: req.Command, runAsUser: req.RunAsUser}
	m.prepared[req.ExecutionId] = p
	installed = true
	p.timer = time.AfterFunc(m.ttl, func() { m.expire(req.ExecutionId, p) })
	return proto.Clone(response).(*pb.ExecutionPrepared)
}
func (m *Manager) expire(id string, p *preparation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.prepared[id] == p {
		delete(m.prepared, id)
		m.budget.Release()
	}
}

// Attach reserves one execution transport for this preparation, before dialing.
func (m *Manager) Attach(binding *pb.ExecutionBinding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || binding == nil {
		return fmt.Errorf("execution manager unavailable")
	}
	p := m.prepared[binding.ExecutionId]
	if p == nil || !proto.Equal(p.response.Binding, binding) || time.Now().UnixMilli() >= binding.ExpiresUnixMilli {
		return fmt.Errorf("invalid or expired execution preparation")
	}
	if p.attached {
		return fmt.Errorf("execution transport already attached")
	}
	p.attached = true
	return nil
}
func (m *Manager) Status(id string) *pb.ExecutionStatus {
	if record, ok := m.journal.Status(id); ok {
		return &pb.ExecutionStatus{ExecutionId: id, Binding: record.Binding, State: record.State, Result: record.Result}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.prepared[id]; p != nil {
		return &pb.ExecutionStatus{ExecutionId: id, Binding: proto.Clone(p.response.Binding).(*pb.ExecutionBinding), State: "prepared"}
	}
	return &pb.ExecutionStatus{ExecutionId: id, State: "not_found"}
}

func (m *Manager) Start(ctx context.Context, start *pb.ExecutionStart) (*Run, error) {
	if start == nil || start.Binding == nil {
		return nil, fmt.Errorf("execution start binding required")
	}
	if len(start.PolicyVersion) > 128 || !utf8.ValidString(start.PolicyVersion) || strings.IndexByte(start.PolicyVersion, 0) >= 0 {
		return nil, fmt.Errorf("invalid execution policy version")
	}
	binding := start.Binding
	m.mu.Lock()

	if m.closed {
		m.mu.Unlock()
		return nil, fmt.Errorf("execution manager unavailable")
	}
	if record, ok := m.journal.Status(binding.ExecutionId); ok {
		if !proto.Equal(record.Binding, binding) {
			m.mu.Unlock()
			return nil, fmt.Errorf("execution ownership mismatch")
		}
		m.mu.Unlock()
		return nil, ErrAlreadyClaimed
	}
	p := m.prepared[binding.ExecutionId]
	if p == nil || !proto.Equal(p.response.Binding, binding) || time.Now().UnixMilli() >= binding.ExpiresUnixMilli {
		m.mu.Unlock()
		return nil, fmt.Errorf("invalid or expired execution preparation")
	}
	if !bytes.Equal(start.CommandSha256, p.response.CommandSha256) || !bytes.Equal(start.IdentitySha256, p.response.Identity.IdentitySha256) || !proto.Equal(start.Limits, p.response.Limits) {
		m.mu.Unlock()
		return nil, fmt.Errorf("execution admission binding mismatch")
	}
	if len(start.AdmissionReceipt) != 0 {
		m.mu.Unlock()
		return nil, fmt.Errorf("protected admission is not supported by this agent")
	}
	p.timer.Stop()
	delete(m.prepared, binding.ExecutionId)
	launchCtx, launchCancel := context.WithCancel(ctx)
	p.launchCancel = launchCancel
	m.launching[binding.ExecutionId] = p
	m.launchWG.Add(1)
	m.mu.Unlock()
	launched := false
	defer func() {
		m.mu.Lock()
		delete(m.launching, binding.ExecutionId)
		m.mu.Unlock()
		if !launched {
			launchCancel()
			m.budget.Release()
		}
		m.launchWG.Done()
	}()
	ctx = launchCtx
	identity, err := m.resolve(p.runAsUser, p.identity.Cwd)
	if err != nil || !bytes.Equal(identity.Digest(), p.identity.Digest()) {
		return nil, fmt.Errorf("prepared operating-system identity changed")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if _, err = m.journal.Claim(binding, p.response.CommandSha256, p.response.Identity.IdentitySha256, start.PolicyVersion); err != nil {
		return nil, err
	}
	if ctx.Err() != nil || time.Now().UnixMilli() >= binding.ExpiresUnixMilli {
		result := &pb.ExecutionResult{Binding: binding, State: "launch_failed", Reason: "preparation expired or cancelled before launch"}
		_ = m.journal.RecordResult(result)
		return nil, fmt.Errorf("execution cancelled or expired before launch")
	}
	cmd := exec.Command(p.identity.Shell, "-c", p.command)
	cmd.Dir = p.identity.Cwd
	cmd.Env = p.identity.Env()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: p.identity.CredentialForExecution()}
	launchFailure := func(reason string) (*Run, error) {
		result := &pb.ExecutionResult{Binding: binding, State: "launch_failed", Reason: reason}
		_ = m.journal.RecordResult(result)
		return nil, fmt.Errorf("%s", reason)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return launchFailure("execution input pipe unavailable")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return launchFailure("execution output pipe unavailable")
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return launchFailure("execution error pipe unavailable")
	}
	if err = cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		result := &pb.ExecutionResult{Binding: binding, State: "launch_failed", Reason: "target process could not start"}
		_ = m.journal.RecordResult(result)
		return nil, fmt.Errorf("target process could not start")
	}
	if err = m.journal.RecordRunning(binding.ExecutionId); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		_ = stdin.Close()
		return nil, fmt.Errorf("launch outcome could not be durably recorded")
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(p.response.Limits.RuntimeSeconds)*time.Second)
	r := &Run{binding: proto.Clone(binding).(*pb.ExecutionBinding), cmd: cmd, stdin: stdin, stdout: stdout, stderr: stderr, input: make(chan inputFrame, queueFrames), output: make(chan *pb.ExecutionAgentMessage, queueFrames), ctx: runCtx, cancel: func() { cancel(); launchCancel() }, done: make(chan struct{}), processExited: make(chan struct{}), inputStopped: make(chan struct{}), manager: m, grace: m.grace, blocked: m.blocked}
	m.mu.Lock()
	m.runs[binding.ExecutionId] = r
	m.mu.Unlock()
	launched = true
	r.output <- &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Started{Started: &pb.ExecutionStarted{Binding: r.binding}}}
	go r.inputLoop()
	go r.lifecycle()
	return r, nil
}
func (m *Manager) Cancel(cancel *pb.ExecutionCancel) error {
	if cancel == nil || cancel.Binding == nil {
		return fmt.Errorf("execution cancellation binding required")
	}
	m.mu.Lock()
	if p := m.prepared[cancel.Binding.ExecutionId]; p != nil {
		if !proto.Equal(p.response.Binding, cancel.Binding) {
			m.mu.Unlock()
			return fmt.Errorf("execution ownership mismatch")
		}
		p.timer.Stop()
		delete(m.prepared, cancel.Binding.ExecutionId)
		m.budget.Release()
		m.mu.Unlock()
		return nil
	}
	if p := m.launching[cancel.Binding.ExecutionId]; p != nil {
		if !proto.Equal(p.response.Binding, cancel.Binding) {
			m.mu.Unlock()
			return fmt.Errorf("execution ownership mismatch")
		}
		p.launchCancel()
		m.mu.Unlock()
		return nil
	}
	r := m.runs[cancel.Binding.ExecutionId]
	m.mu.Unlock()
	if r != nil {
		if !proto.Equal(r.binding, cancel.Binding) {
			return fmt.Errorf("execution ownership mismatch")
		}
		r.Cancel(cancel.Reason)
		return nil
	}
	if record, ok := m.journal.Status(cancel.Binding.ExecutionId); ok && proto.Equal(record.Binding, cancel.Binding) {
		return nil
	}
	return fmt.Errorf("execution not found")
}
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	for id, p := range m.prepared {
		p.timer.Stop()
		delete(m.prepared, id)
		m.budget.Release()
	}
	for _, p := range m.launching {
		p.launchCancel()
	}
	m.mu.Unlock()
	m.launchWG.Wait()
	m.mu.Lock()
	runs := make([]*Run, 0, len(m.runs))
	for _, r := range m.runs {
		runs = append(runs, r)
	}
	m.mu.Unlock()
	for _, r := range runs {
		r.Cancel("control_transport_lost")
	}
	for _, r := range runs {
		<-r.Done()
	}
}
func (m *Manager) finish(r *Run) {
	m.mu.Lock()
	delete(m.runs, r.binding.ExecutionId)
	m.mu.Unlock()
	m.budget.Release()
}

type inputFrame struct {
	data []byte
	eof  bool
}
type Run struct {
	signalMu                       sync.Mutex
	binding                        *pb.ExecutionBinding
	cmd                            *exec.Cmd
	stdin                          io.WriteCloser
	stdout, stderr                 io.ReadCloser
	input                          chan inputFrame
	output                         chan *pb.ExecutionAgentMessage
	ctx                            context.Context
	cancel                         context.CancelFunc
	done, processExited            chan struct{}
	inputStopped                   chan struct{}
	manager                        *Manager
	grace, blocked                 time.Duration
	inputMu                        sync.Mutex
	inputSequence                  uint64
	inputClosed                    bool
	cancelOnce                     sync.Once
	reasonMu                       sync.Mutex
	reason                         string
	integrityMu                    sync.Mutex
	stdoutComplete, stderrComplete bool
}

func (r *Run) Messages() <-chan *pb.ExecutionAgentMessage { return r.output }
func (r *Run) Done() <-chan struct{}                      { return r.done }
func (r *Run) Input(data *pb.ExecutionData) error {
	r.inputMu.Lock()
	defer r.inputMu.Unlock()
	if data == nil || r.inputClosed || data.Sequence != r.inputSequence || len(data.Data) > MaxFrameBytes {
		return fmt.Errorf("invalid execution input sequence or frame")
	}
	frame := inputFrame{data: append([]byte(nil), data.Data...)}
	// A command may close or ignore stdin and exit before the SSH client has
	// sent all its input. Validate framing, then discard those unread bytes;
	// they cannot invalidate already completed output or the real exit status.
	select {
	case <-r.inputStopped:
		r.inputSequence++
		return nil
	case <-r.processExited:
		r.inputSequence++
		return nil
	default:
	}
	select {
	case r.input <- frame:
		r.inputSequence++
		return nil
	case <-r.ctx.Done():
		select {
		case <-r.processExited:
			r.inputSequence++
			return nil
		case <-r.inputStopped:
			r.inputSequence++
			return nil
		default:
		}
		return r.ctx.Err()
	case <-r.done:
		r.inputSequence++
		return nil
	case <-r.inputStopped:
		r.inputSequence++
		return nil
	}
}
func (r *Run) InputEOF(eof *pb.ExecutionInputEOF) error {
	r.inputMu.Lock()
	defer r.inputMu.Unlock()
	if eof == nil || r.inputClosed || eof.Sequence != r.inputSequence {
		return fmt.Errorf("invalid execution input EOF")
	}
	select {
	case <-r.inputStopped:
		r.inputClosed = true
		return nil
	case <-r.processExited:
		r.inputClosed = true
		return nil
	default:
	}
	select {
	case r.input <- inputFrame{eof: true}:
		r.inputClosed = true
		return nil
	case <-r.ctx.Done():
		select {
		case <-r.processExited:
			r.inputClosed = true
			return nil
		case <-r.inputStopped:
			r.inputClosed = true
			return nil
		default:
		}
		return r.ctx.Err()
	case <-r.done:
		r.inputClosed = true
		return nil
	case <-r.inputStopped:
		r.inputClosed = true
		return nil
	}
}
func (r *Run) inputLoop() {
	defer close(r.inputStopped)
	defer r.stdin.Close()
	for {
		select {
		case frame := <-r.input:
			if frame.eof {
				return
			}
			if _, err := r.stdin.Write(frame.data); err != nil {
				return
			}
		case <-r.ctx.Done():
			return
		case <-r.done:
			return
		}
	}
}
func (r *Run) Cancel(reason string) {
	r.cancelOnce.Do(func() {
		if reason == "" || len(reason) > 128 || !utf8.ValidString(reason) || strings.IndexByte(reason, 0) >= 0 {
			reason = "cancelled"
		}
		r.reasonMu.Lock()
		r.reason = reason
		r.reasonMu.Unlock()
		r.cancel()
	})
}
func (r *Run) emit(msg *pb.ExecutionAgentMessage) bool {
	select {
	case r.output <- msg:
		return true
	default:
	}
	timer := time.NewTimer(r.blocked)
	defer timer.Stop()
	select {
	case r.output <- msg:
		return true
	case <-timer.C:
		r.Cancel("blocked_output_consumer")
		return false
	case <-r.ctx.Done():
		return false
	}
}
func (r *Run) readOutput(reader io.ReadCloser, kind pb.ExecutionOutput, wg *sync.WaitGroup) {
	defer wg.Done()
	defer reader.Close()
	buf := make([]byte, MaxFrameBytes)
	var sequence uint64
	complete := true
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			data := &pb.ExecutionData{Sequence: sequence, Data: append([]byte(nil), buf[:n]...)}
			msg := &pb.ExecutionAgentMessage{}
			if kind == pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT {
				msg.Payload = &pb.ExecutionAgentMessage_Stdout{Stdout: data}
			} else {
				msg.Payload = &pb.ExecutionAgentMessage_Stderr{Stderr: data}
			}
			if !r.emit(msg) {
				complete = false
				break
			}
			sequence++
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				complete = false
			}
			break
		}
	}
	eof := &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_OutputEof{OutputEof: &pb.ExecutionOutputEOF{Output: kind, Sequence: sequence}}}
	select {
	case r.output <- eof:
	default:
		select {
		case r.output <- eof:
		case <-r.ctx.Done():
			complete = false
		case <-time.After(r.blocked):
			complete = false
		}
	}
	r.integrityMu.Lock()
	if kind == pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT {
		r.stdoutComplete = complete
	} else {
		r.stderrComplete = complete
	}
	r.integrityMu.Unlock()
}
func (r *Run) terminate() {
	select {
	case <-r.processExited:
		return
	default:
	}
	r.signalMu.Lock()
	select {
	case <-r.processExited:
		r.signalMu.Unlock()
		return
	default:
	}
	_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGTERM)
	r.signalMu.Unlock()
	timer := time.NewTimer(r.grace)
	defer timer.Stop()
	select {
	case <-r.processExited:
		return
	case <-timer.C:
		r.signalMu.Lock()
		select {
		case <-r.processExited:
		default:
			_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGKILL)
		}
		r.signalMu.Unlock()
	}
}

// The unreaped leader pins its PID/PGID while ordinary background children
// are cleaned. Deliberately detached process groups are outside v1 containment.
func (r *Run) cleanupBackgroundGroup() bool {
	if !hasLiveGroupMembers(r.cmd.Process.Pid) {
		return false
	}
	r.signalMu.Lock()
	_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGTERM)
	r.signalMu.Unlock()
	timer := time.NewTimer(r.grace)
	<-timer.C
	r.signalMu.Lock()
	_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGKILL)
	r.signalMu.Unlock()
	// SIGKILL delivery is asynchronous. Bound the wait for ordinary descendants
	// to stop; the leader stays unreaped throughout, preventing PGID reuse.
	deadline := time.Now().Add(time.Second)
	for hasLiveGroupMembers(r.cmd.Process.Pid) && time.Now().Before(deadline) {
		timer := time.NewTimer(5 * time.Millisecond)
		<-timer.C
	}
	return true
}
func hasLiveGroupMembers(group int) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return true
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == group {
			continue
		}
		data, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		end := strings.LastIndexByte(string(data), ')')
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) < 3 || fields[0] == "Z" || fields[0] == "X" {
			continue
		}
		pgid, err := strconv.Atoi(fields[2])
		if err == nil && pgid == group {
			return true
		}
	}
	return false
}
func (r *Run) lifecycle() {
	defer close(r.done)
	defer close(r.output)
	defer r.cancel()
	defer r.manager.finish(r)
	var readers sync.WaitGroup
	readers.Add(2)
	go r.readOutput(r.stdout, pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT, &readers)
	go r.readOutput(r.stderr, pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR, &readers)
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-r.ctx.Done():
			r.terminate()
			_ = r.stdin.Close()
			_ = r.stdout.Close()
			_ = r.stderr.Close()
		case <-r.processExited:
		}
	}()
	// Read all pipes before Wait closes them. Context cancellation bounds reads
	// held open by ordinary descendants and supplies process-group cleanup.
	// Observe exit without reaping: the leader PID/PGID cannot be reused while
	// cancellation still owns its process group. Serialize the final release
	// against group signals, then let exec.Cmd reap its own child.
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, r.cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			break
		}
	}
	backgroundCleaned := r.cleanupBackgroundGroup()
	readers.Wait()
	r.signalMu.Lock()
	close(r.processExited)
	waitErr := r.cmd.Wait()
	r.signalMu.Unlock()
	<-watcherDone
	result := &pb.ExecutionResult{Binding: r.binding, State: "exited", ExitCode: 0, StdoutComplete: r.stdoutComplete, StderrComplete: r.stderrComplete}
	if backgroundCleaned {
		result.Reason = "background_descendants_terminated"
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			result.ExitCode = int32(exitErr.ExitCode())
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				result.Signal = status.Signal().String()
			}
		} else {
			result.State = "outcome_unknown"
			result.ExitCode = -1
			result.Reason = "process result unavailable"
		}
	}
	r.reasonMu.Lock()
	reason := r.reason
	r.reasonMu.Unlock()
	if r.ctx.Err() != nil {
		result.State = "cancelled"
		result.Reason = reason
		if result.Reason == "" {
			result.Reason = "runtime_or_transport_expired"
		}
	}
	if !result.StdoutComplete || !result.StderrComplete {
		if result.State == "exited" {
			result.State = "transport_lost"
			result.Reason = "output integrity incomplete"
		}
	}
	if err := r.manager.journal.RecordResult(result); err != nil {
		result.State = "outcome_unknown"
		result.Reason = "completion not durable"
	}
	// Cancellation must still expose its final metadata when the consumer drains.
	final := &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Result{Result: result}}
	select {
	case r.output <- final:
	default:
		select {
		case r.output <- final:
		case <-r.ctx.Done():
		case <-time.After(r.blocked):
		}
	}
}
