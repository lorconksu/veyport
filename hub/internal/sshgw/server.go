// Package sshgw implements the Veyport SSH gateway: a hardened SSH listener
// that authenticates operators by short-lived user certificate and bridges an
// interactive PTY to a fleet agent over the existing hub↔agent terminal
// channel. The hub stays on the data path, so every byte remains observable
// and no new agent capability is required (feature 005-ssh-gateway).
//
// The gateway owns no state of its own: TerminalSessions, ConnManager,
// PendingRequests and Store are injected so it shares the exact machinery the
// web terminal uses, and authorization runs through the same
// server.AuthorizeTerminalExecution core.
package sshgw

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
)

const (
	// DefaultHandshakeTimeout bounds how long an unauthenticated connection
	// may occupy the listener before it is dropped (FR-014, SC-009).
	DefaultHandshakeTimeout = 30 * time.Second
	// DefaultMaxConns caps concurrent gateway connections (FR-014).
	DefaultMaxConns = 256
	// DefaultOpenTimeout bounds the wait for the agent's TerminalOpenAck,
	// matching the web terminal's 5s budget in handlers_terminal.go.
	DefaultOpenTimeout = 5 * time.Second

	// serverVersion is the SSH identification string the gateway announces.
	serverVersion = "SSH-2.0-Veyport"
	// maxAuthTries bounds authentication attempts per connection.
	maxAuthTries = 3
	// forceCloseGrace is how long Stop waits after force-closing connections.
	forceCloseGrace = 2 * time.Second

	// usernameSeparator splits <veyport-user>+<server> (FR-016). The split is
	// on the FIRST separator, so a server name may contain '+' but a veyport
	// username may not.
	usernameSeparator = "+"

	// Permissions extensions carrying the authenticated identity from the
	// auth callback to session handling — the idiomatic x/crypto/ssh channel
	// for exactly this.
	extUsername = "veyport-username"
	extTarget   = "veyport-target"
)

// usernameFormatMessage explains the FR-016 addressing form to a client that
// connected without it. It is delivered as an SSH auth banner, which is the
// only way to get prose to a client that never authenticates.
const usernameFormatMessage = "veyport: the SSH username must be <veyport-user>+<server>, " +
	"for example \"alice+web01\". Connect with: ssh -p 2222 alice+web01@<hub-host>, " +
	"or simply: vey ssh web01"

// errUsernameFormat is the internal cause behind usernameFormatMessage.
var errUsernameFormat = errors.New("ssh username is not of the form <veyport-user>+<server>")

// Config is the injected dependency set and effective configuration for the
// gateway. Everything except the sshconfig-derived values is shared with the
// HTTP and gRPC servers (main.go wires the same objects).
type Config struct {
	// Store is the hub datastore, used for live authorization and audit.
	Store *store.Store
	// UserCA is the trust root for user certificates. Nil disables the
	// listener (corrupt-key case, FR-006).
	UserCA *userca.UserCA
	// HostKey is the stable gateway host identity. Nil disables the listener.
	HostKey ssh.Signer
	// Terminals is the shared terminal session registry.
	Terminals *grpcserver.TerminalSessions
	// ConnMgr is the shared agent connection manager.
	ConnMgr *connmgr.ConnManager
	// Pending is the shared request/response correlation registry.
	Pending *grpcserver.PendingRequests

	// Addr is the listen address (sshconfig.Config.Addr).
	Addr string
	// Enabled reports whether the listener should open at all (FR-015).
	Enabled bool

	// HandshakeTimeout bounds the pre-authentication phase.
	// Zero means DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// MaxConns caps concurrent connections. Zero means DefaultMaxConns.
	MaxConns int
	// OpenTimeout bounds the wait for TerminalOpenAck.
	// Zero means DefaultOpenTimeout.
	OpenTimeout time.Duration
}

// Server is the SSH gateway listener. The zero value is not usable; build one
// with New.
type Server struct {
	cfg Config

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	closing  bool

	wg        sync.WaitGroup
	ready     chan struct{}
	readyOnce sync.Once
}

// New builds a gateway from cfg. It performs no I/O; call Start to listen.
func New(cfg Config) *Server {
	return &Server{
		cfg:   cfg,
		conns: make(map[net.Conn]struct{}),
		ready: make(chan struct{}),
	}
}

// Start binds the listener and serves connections until Stop is called. It
// blocks, mirroring grpcserver.Server.Start, so run it in a goroutine.
//
// A disabled gateway, or one whose key material is unusable, returns nil
// without ever opening a port: the hub's REST and gRPC planes keep serving
// (FR-006, FR-015). Only a genuine bind failure is returned as an error.
func (s *Server) Start() error {
	lis, err := s.listen()
	s.markReady()
	if err != nil {
		return err
	}
	if lis == nil {
		return nil
	}
	return s.serve(lis)
}

// listen opens the listener, or reports (nil, nil) when the gateway must not
// listen at all.
func (s *Server) listen() (net.Listener, error) {
	if !s.cfg.Enabled {
		log.Printf("SSH gateway: disabled by configuration; not listening")
		return nil, nil
	}
	if reason := s.unusableKeyMaterial(); reason != "" {
		// Fail loudly but locally: never regenerate the host key, never take
		// the whole hub down (FR-006).
		log.Printf("SSH GATEWAY DISABLED: %s. The SSH port will not be opened; "+
			"restore the stored key or clear it deliberately to re-enable.", reason)
		s.logAudit(model.AuditSSHSessionRefused, model.AuditOutcomeFailure, "", "",
			"gateway_disabled reason="+reason, "")
		return nil, nil
	}

	lis, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("ssh gateway listen on %s: %w", s.cfg.Addr, err)
	}

	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		_ = lis.Close()
		return nil, nil
	}
	s.listener = lis
	s.mu.Unlock()

	log.Printf("Veyport SSH gateway listening on %s (host key %s)",
		lis.Addr(), ssh.FingerprintSHA256(s.cfg.HostKey.PublicKey()))
	return lis, nil
}

// unusableKeyMaterial names the missing trust material, or "" when the gateway
// can serve.
func (s *Server) unusableKeyMaterial() string {
	switch {
	case s.cfg.HostKey == nil:
		return "the SSH gateway host key is missing or unusable"
	case s.cfg.UserCA == nil:
		return "the SSH user certificate authority is missing or unusable"
	default:
		return ""
	}
}

func (s *Server) serve(lis net.Listener) error {
	for {
		conn, err := lis.Accept()
		if err != nil {
			if s.isClosing() {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("ssh gateway accept: %w", err)
		}
		if !s.trackConn(conn) {
			log.Printf("SSH gateway: refusing %s, connection cap (%d) reached",
				conn.RemoteAddr(), s.maxConns())
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrackConn(conn)
			s.handleConn(conn)
		}()
	}
}

// Stop closes the listener and waits for in-flight sessions to finish. When
// ctx expires the remaining connections are force-closed and ctx's error is
// returned, so the hub's shutdown path stays bounded.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	lis := s.listener
	s.mu.Unlock()

	if lis != nil {
		_ = lis.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.closeAllConns()
		select {
		case <-done:
		case <-time.After(forceCloseGrace):
		}
		return ctx.Err()
	}
}

// Addr reports the bound listen address, or "" when the gateway is not
// listening (disabled, unusable key material, or not started).
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) markReady() {
	s.readyOnce.Do(func() { close(s.ready) })
}

func (s *Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

func (s *Server) trackConn(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || len(s.conns) >= s.maxConns() {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) untrackConn(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

func (s *Server) closeAllConns() {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (s *Server) activeConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *Server) maxConns() int {
	if s.cfg.MaxConns > 0 {
		return s.cfg.MaxConns
	}
	return DefaultMaxConns
}

func (s *Server) handshakeTimeout() time.Duration {
	if s.cfg.HandshakeTimeout > 0 {
		return s.cfg.HandshakeTimeout
	}
	return DefaultHandshakeTimeout
}

func (s *Server) openTimeout() time.Duration {
	if s.cfg.OpenTimeout > 0 {
		return s.cfg.OpenTimeout
	}
	return DefaultOpenTimeout
}

// handleConn runs one TCP connection through the SSH handshake and, once
// authenticated, serves its channels.
func (s *Server) handleConn(nConn net.Conn) {
	defer func() { _ = nConn.Close() }()

	// Bound the unauthenticated phase; clear the deadline once the handshake
	// succeeds so an interactive session is never cut off mid-shell.
	_ = nConn.SetDeadline(time.Now().Add(s.handshakeTimeout()))

	state := &connState{}
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, s.serverConfig(state))
	if err != nil {
		s.auditHandshakeFailure(state, nConn.RemoteAddr(), err)
		return
	}
	defer func() { _ = sshConn.Close() }()
	_ = nConn.SetDeadline(time.Time{})

	go rejectGlobalRequests(reqs)
	s.serveChannels(sshConn, chans)
}

// connState carries what the auth callback learned into the failure audit.
// Callbacks run inside the synchronous handshake, but the mutex keeps this
// obviously safe.
type connState struct {
	mu       sync.Mutex
	rawUser  string
	username string
	target   string
}

func (c *connState) record(rawUser, username, target string) {
	c.mu.Lock()
	c.rawUser, c.username, c.target = rawUser, username, target
	c.mu.Unlock()
}

func (c *connState) snapshot() (rawUser, username, target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rawUser, c.username, c.target
}

// serverConfig builds a per-connection ssh.ServerConfig. Per-connection (not
// shared) so the auth callback can close over this connection's state.
//
// Only PublicKeyCallback is set: passwords, keyboard-interactive and
// GSSAPI are therefore unavailable, and NoClientAuth stays false (FR-005).
func (s *Server) serverConfig(state *connState) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion: serverVersion,
		MaxAuthTries:  maxAuthTries,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return s.authenticate(conn, key, state)
		},
	}
	cfg.AddHostKey(s.cfg.HostKey)
	return cfg
}

// principalConn overrides ConnMetadata.User so the certificate principal check
// sees the bare veyport username rather than the raw "<user>+<server>" login
// name.
//
// This is load-bearing: ssh.CertChecker.Authenticate performs its principal
// check as CheckCert(conn.User(), cert), and conn.User() is the raw SSH
// username, which carries the "+<server>" suffix (FR-016). Rather than
// reimplement Authenticate's checks — and thereby risk the R1a trap, where
// CheckCert alone verifies a certificate against its OWN embedded SignatureKey
// and never consults IsUserAuthority — the gateway keeps Authenticate as the
// single verifier and adapts its view of the username.
type principalConn struct {
	ssh.ConnMetadata
	principal string
}

func (p principalConn) User() string { return p.principal }

// authenticate is the PublicKeyCallback. It accepts only a user certificate
// signed by the gateway's user CA whose principal equals the left half of the
// login name, and stashes the resolved identity in ssh.Permissions for the
// session layer.
func (s *Server) authenticate(conn ssh.ConnMetadata, key ssh.PublicKey, state *connState) (*ssh.Permissions, error) {
	username, target, err := splitLoginName(conn.User())
	state.record(conn.User(), username, target)
	if err != nil {
		return nil, &ssh.BannerError{Err: err, Message: usernameFormatMessage}
	}

	// CertChecker.Authenticate — never CheckCert — is what enforces the trust
	// root (IsUserAuthority), CertType == UserCert, and, with UserKeyFallback
	// nil, the rejection of bare public keys (research R1a, FR-005).
	checker := &ssh.CertChecker{IsUserAuthority: s.cfg.UserCA.IsUserAuthority}
	if _, err := checker.Authenticate(principalConn{ConnMetadata: conn, principal: username}, key); err != nil {
		return nil, &ssh.BannerError{
			Err:     fmt.Errorf("ssh gateway: certificate rejected: %w", err),
			Message: "veyport: certificate rejected (" + err.Error() + "). Run: vey ssh-cert",
		}
	}

	// Only the proven identity crosses into session handling. Authorization
	// itself is deliberately NOT decided here: it is re-evaluated against live
	// store state when the shell is requested (FR-007).
	return &ssh.Permissions{
		Extensions: map[string]string{
			extUsername: username,
			extTarget:   target,
		},
	}, nil
}

// splitLoginName parses the FR-016 login name on its FIRST separator: the left
// part is the veyport username (and required certificate principal), the right
// part is the target server name or ID.
func splitLoginName(raw string) (username, target string, err error) {
	idx := strings.Index(raw, usernameSeparator)
	if idx < 0 {
		return "", "", errUsernameFormat
	}
	username, target = raw[:idx], raw[idx+len(usernameSeparator):]
	if username == "" || target == "" {
		return "", "", errUsernameFormat
	}
	return username, target, nil
}

// rejectGlobalRequests refuses every connection-level request, which is how
// remote port forwarding (`ssh -R`, "tcpip-forward") is denied (FR-010).
func rejectGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

// auditHandshakeFailure records a connection that never authenticated. It runs
// once per connection rather than once per auth attempt, so a client that
// probes with a key and then signs does not produce duplicate entries.
func (s *Server) auditHandshakeFailure(state *connState, remote net.Addr, err error) {
	rawUser, _, target := state.snapshot()
	detail := fmt.Sprintf("ssh_user=%q target=%q reason=%v", rawUser, target, err)
	s.logAudit(model.AuditSSHSessionRefused, model.AuditOutcomeFailure, "", "", detail, remoteHost(remote))
}

// logAudit writes an audit entry directly, with an explicit ID and no
// *http.Request — the non-HTTP pattern from expireUnattachedTerminalSession.
func (s *Server) logAudit(action, outcome, userID, target, detail, ip string) {
	entry := model.AuditEntry{
		ID:      newID(),
		Action:  action,
		Outcome: outcome,
	}
	if userID != "" {
		entry.UserID = &userID
	}
	if target != "" {
		entry.Target = &target
	}
	if detail != "" {
		entry.Detail = &detail
	}
	if ip != "" {
		entry.IPAddress = &ip
	}
	if err := s.cfg.Store.LogAudit(entry); err != nil {
		log.Printf("SSH gateway: audit %s: %v", action, err)
	}
}

// remoteHost strips the port from an address for audit purposes.
func remoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
