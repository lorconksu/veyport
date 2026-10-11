package terminal

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/wyiu/veyport/agent/internal/executionidentity"
	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	defaultCols        = 120
	defaultRows        = 36
	maxCols            = 300
	maxRows            = 120
	maxSessions        = 8
	terminalBufferSize = 4096
	terminalPath       = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	getentPath         = "/usr/bin/getent"
	idPath             = "/usr/bin/id"
	errManagerStopped  = "terminal manager unavailable"
)

var ErrSessionNotFound = errors.New("terminal session not found")

var (
	lookupOSUser       = osuser.Lookup
	lookupOSUserGroups = func(u *osuser.User) ([]string, error) { return u.GroupIds() }
	lookupNSSUser      = lookupUserWithGetent
	lookupNSSGroupIDs  = lookupGroupIDsWithID
)

type session struct {
	id        string
	cmd       *exec.Cmd
	tty       *os.File
	exited    chan struct{}
	closeOnce sync.Once
	budget    *sessionlimit.Budget
}

type executionIdentity struct {
	credential *syscall.Credential
	username   string
	homeDir    string
}

type Manager struct {
	mu        sync.Mutex
	sessions  map[string]*session
	sendCh    chan<- *pb.AgentMessage
	done      chan struct{}
	closeOnce sync.Once
	budget    *sessionlimit.Budget
}

func NewManager(sendCh chan<- *pb.AgentMessage) *Manager {
	return NewManagerWithBudget(sendCh, sessionlimit.New(maxSessions))
}

func NewManagerWithBudget(sendCh chan<- *pb.AgentMessage, budget *sessionlimit.Budget) *Manager {
	return &Manager{
		sessions: make(map[string]*session),
		sendCh:   sendCh,
		done:     make(chan struct{}),
		budget:   budget,
	}
}

func (m *Manager) Open(sessionID string, cols, rows uint32, cwd, runAsUser string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	if m.isStopped() {
		return fmt.Errorf(errManagerStopped)
	}
	if err := m.validateOpenSlot(sessionID); err != nil {
		return err
	}

	if !m.budget.Acquire() {
		return fmt.Errorf("too many active terminal sessions")
	}
	registered := false
	defer func() {
		if !registered {
			m.budget.Release()
		}
	}()

	shell, err := resolveShell()
	if err != nil {
		return err
	}
	identity, err := executionIdentityForRunAs(runAsUser)
	if err != nil {
		return err
	}

	cmd := exec.Command(shell, "-i")
	cmd.Env = buildTerminalEnv(shell, identity)
	applyExecutionIdentity(cmd, identity, cwd)

	if err := applyWorkingDirectory(cmd, cwd); err != nil {
		return err
	}

	ptmx, err := pty.StartWithSize(cmd, normalizedSize(cols, rows))
	if err != nil {
		return fmt.Errorf("start terminal: %w", err)
	}

	s := &session{
		id:     sessionID,
		cmd:    cmd,
		tty:    ptmx,
		exited: make(chan struct{}),
	}

	if err := m.register(sessionID, s); err != nil {
		m.closeSession(s, true)
		return err
	}

	registered = true
	go m.readLoop(s)
	go m.waitLoop(s)

	return nil
}

func (m *Manager) validateOpenSlot(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isStopped() {
		return fmt.Errorf(errManagerStopped)
	}
	if _, exists := m.sessions[sessionID]; exists {
		return fmt.Errorf("terminal session already exists")
	}
	if len(m.sessions) >= maxSessions {
		return fmt.Errorf("too many active terminal sessions")
	}
	return nil
}

func (m *Manager) register(sessionID string, s *session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isStopped() {
		return fmt.Errorf(errManagerStopped)
	}
	if _, exists := m.sessions[sessionID]; exists {
		return fmt.Errorf("terminal session already exists")
	}
	if len(m.sessions) >= maxSessions {
		return fmt.Errorf("too many active terminal sessions")
	}
	m.sessions[sessionID] = s
	return nil
}

func applyExecutionIdentity(cmd *exec.Cmd, identity *executionIdentity, cwd string) {
	if identity == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: identity.credential}
	if identity.homeDir != "" && cwd == "" {
		cmd.Dir = identity.homeDir
	}
}

func applyWorkingDirectory(cmd *exec.Cmd, cwd string) error {
	if cwd == "" {
		return nil
	}
	cleaned := filepath.Clean(cwd)
	if !filepath.IsAbs(cleaned) {
		return fmt.Errorf("terminal cwd must be absolute")
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		return fmt.Errorf("terminal cwd not available")
	}
	if !info.IsDir() {
		return fmt.Errorf("terminal cwd must be a directory")
	}
	cmd.Dir = cleaned
	return nil
}

func (m *Manager) Input(sessionID string, data []byte) error {
	s, err := m.get(sessionID)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if _, err := s.tty.Write(data); err != nil {
		return fmt.Errorf("write terminal input: %w", err)
	}
	return nil
}

func (m *Manager) Resize(sessionID string, cols, rows uint32) error {
	s, err := m.get(sessionID)
	if err != nil {
		return err
	}
	if err := pty.Setsize(s.tty, normalizedSize(cols, rows)); err != nil {
		return fmt.Errorf("resize terminal: %w", err)
	}
	return nil
}

func (m *Manager) Close(sessionID string) error {
	s, err := m.get(sessionID)
	if err != nil {
		return err
	}
	m.closeSession(s, true)
	return nil
}

func (m *Manager) CloseAll() {
	m.stop()

	m.mu.Lock()
	sessions := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()

	for _, s := range sessions {
		m.closeSession(s, true)
	}
}

func (m *Manager) stop() {
	m.closeOnce.Do(func() {
		close(m.done)
	})
}

func (m *Manager) isStopped() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

func (m *Manager) get(sessionID string) (*session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return s, nil
}

func (m *Manager) readLoop(s *session) {
	buf := make([]byte, terminalBufferSize)
	for {
		n, err := s.tty.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			if !m.Send(&pb.AgentMessage{
				Payload: &pb.AgentMessage_TerminalData{
					TerminalData: &pb.TerminalData{
						SessionId: s.id,
						Data:      data,
					},
				},
			}) {
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				log.Printf("terminal read error for %s: %v", s.id, err)
			}
			return
		}
	}
}

func (m *Manager) waitLoop(s *session) {
	err := s.cmd.Wait()
	close(s.exited)

	exitCode := int32(0)
	exitErr := ""
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = int32(exitError.ExitCode())
		} else {
			exitCode = -1
			exitErr = err.Error()
		}
	}

	_ = m.Send(&pb.AgentMessage{
		Payload: &pb.AgentMessage_TerminalExit{
			TerminalExit: &pb.TerminalExit{
				SessionId: s.id,
				ExitCode:  exitCode,
				Error:     exitErr,
			},
		},
	})

	m.closeSession(s, false)
}

// Send forwards a terminal agent message unless the manager is shutting down.
func (m *Manager) Send(msg *pb.AgentMessage) bool {
	select {
	case m.sendCh <- msg:
		return true
	case <-m.done:
		return false
	}
}

func (m *Manager) closeSession(s *session, signalProcess bool) {
	s.closeOnce.Do(func() {
		m.mu.Lock()
		_, existed := m.sessions[s.id]
		delete(m.sessions, s.id)
		if existed {
			m.budget.Release()
		}
		m.mu.Unlock()

		if signalProcess && s.cmd.Process != nil {
			pid := s.cmd.Process.Pid
			signalProcessGroup(pid, syscall.SIGHUP)
			go func() {
				select {
				case <-s.exited:
					return
				case <-time.After(500 * time.Millisecond):
					signalProcessGroup(pid, syscall.SIGKILL)
				}
			}()
		}

		_ = s.tty.Close()
	})
}

func signalProcessGroup(pid int, signal syscall.Signal) {
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(-pid, signal); err != nil {
		_ = syscall.Kill(pid, signal)
	}
}

func normalizedSize(cols, rows uint32) *pty.Winsize {
	if cols == 0 {
		cols = defaultCols
	}
	if rows == 0 {
		rows = defaultRows
	}
	if cols > maxCols {
		cols = maxCols
	}
	if rows > maxRows {
		rows = maxRows
	}
	return &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	}
}

func resolveShell() (string, error) {
	candidates := []string{
		os.Getenv("SHELL"),
		"/bin/bash",
		"/usr/bin/bash",
		"/bin/sh",
		"/usr/bin/sh",
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no supported shell found on agent")
}

func executionIdentityForRunAs(runAsUser string) (*executionIdentity, error) {
	if runAsUser == "" {
		return nil, nil
	}
	resolver := executionidentity.Resolver{LookupUser: lookupOSUser, LookupGroups: lookupOSUserGroups, LookupNSSUser: lookupNSSUser, LookupNSSGroups: lookupNSSGroupIDs}
	identity, err := resolver.ResolveNamed(runAsUser)
	if err != nil {
		if err.Error() == "invalid execution user" {
			return nil, fmt.Errorf("invalid terminal execution user")
		}
		return nil, fmt.Errorf("terminal %s", err)
	}
	return &executionIdentity{credential: identity.Credential(), username: identity.Username, homeDir: identity.Home}, nil
}

func lookupUserWithGetent(username string) (*osuser.User, error) {
	return executionidentity.LookupUserWithGetent(username)
}
func parseGetentPasswdLine(line string) (*osuser.User, error) {
	return executionidentity.ParsePasswd(line)
}
func lookupGroupIDsWithID(username string) ([]string, error) {
	return executionidentity.LookupGroupIDsWithID(username)
}
func parseGroupIDs(output string) ([]string, error) { return executionidentity.ParseGroups(output) }
func validateRunAsUsername(username string) error {
	if err := executionidentity.ValidateUsername(username); err != nil {
		return fmt.Errorf("invalid terminal execution user")
	}
	return nil
}

func buildTerminalEnv(shell string, identity *executionIdentity) []string {
	env := []string{
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"PATH=" + terminalPath,
		"SHELL=" + shell,
		"LANG=C.UTF-8",
	}
	if identity != nil {
		env = append(env,
			"USER="+identity.username,
			"LOGNAME="+identity.username,
		)
		if identity.homeDir != "" {
			env = append(env, "HOME="+identity.homeDir)
		}
		return env
	}
	if current, err := osuser.Current(); err == nil {
		env = append(env,
			"USER="+current.Username,
			"LOGNAME="+current.Username,
		)
		if current.HomeDir != "" {
			env = append(env, "HOME="+current.HomeDir)
		}
	}
	return env
}
