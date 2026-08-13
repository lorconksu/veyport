package sshgw

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// Listener lifecycle: binding, refusing to bind, and shutting down. FR-006 and
// FR-014 both hinge on the gateway failing locally — a listener problem must
// never take the hub's REST and gRPC planes with it.

// ---------------------------------------------------------------------------
// test doubles
// ---------------------------------------------------------------------------

// namedAddr is a net.Addr with an arbitrary string form, so audit-side address
// handling can be exercised without a real socket.
type namedAddr struct {
	network string
	address string
}

func (a namedAddr) Network() string { return a.network }
func (a namedAddr) String() string  { return a.address }

// timeoutError is a net.Error that reports a timeout, which Accept must treat
// as transient rather than fatal.
type timeoutError struct{}

func (timeoutError) Error() string   { return "accept: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// scriptedListener replays a fixed sequence of Accept errors. Accept failures
// are not reproducible against a real socket, and the distinction between a
// transient and a fatal one is exactly what serve has to get right.
type scriptedListener struct {
	errs []error
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	if len(l.errs) == 0 {
		return nil, errors.New("scripted listener exhausted")
	}
	err := l.errs[0]
	l.errs = l.errs[1:]
	return nil, err
}

func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return namedAddr{network: "tcp", address: "127.0.0.1:0"} }

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// TestStartReportsBindFailure pins that a genuine bind failure — unlike a
// disabled gateway or unusable key material — is reported to the caller.
func TestStartReportsBindFailure(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error: %v", err)
	}
	defer func() { _ = busy.Close() }()

	f := newFixture(t, func(cfg *Config) { cfg.Addr = busy.Addr().String() })

	startErr := f.srv.Start()
	if startErr == nil {
		t.Fatal("Start() succeeded on an address that is already bound")
	}
	if !strings.Contains(startErr.Error(), "listen") {
		t.Errorf("Start() error = %v, want it to name the failed listen", startErr)
	}
	if addr := f.srv.Addr(); addr != "" {
		t.Errorf("Addr() = %q, want no listener after a bind failure", addr)
	}
}

// TestStopBeforeStartNeverServes pins the shutdown race: a gateway told to stop
// before it finished starting must not end up serving on an orphaned listener.
// The second Stop also has to be a no-op.
func TestStopBeforeStartNeverServes(t *testing.T) {
	f := newFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()

	if err := f.srv.Stop(ctx); err != nil {
		t.Fatalf("Stop() before Start() error: %v", err)
	}
	if err := f.srv.Start(); err != nil {
		t.Fatalf("Start() after Stop() error: %v", err)
	}
	if addr := f.srv.Addr(); addr != "" {
		t.Errorf("Addr() = %q, want no listener after Stop preceded Start", addr)
	}
	if err := f.srv.Stop(ctx); err != nil {
		t.Errorf("second Stop() error: %v", err)
	}
}

// TestStopForceClosesConnectionsWhenContextExpires pins the bounded shutdown
// path: connections still in the handshake are force-closed and the context's
// error is surfaced, so the hub's shutdown can never hang on a stalled client.
func TestStopForceClosesConnectionsWhenContextExpires(t *testing.T) {
	f := newFixture(t, nil)
	f.start()

	conn, err := net.Dial("tcp", f.srv.Addr())
	if err != nil {
		t.Fatalf("net.Dial() error: %v", err)
	}
	defer func() { _ = conn.Close() }()
	waitFor(t, "the connection to be tracked", func() bool { return f.srv.activeConns() == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := f.srv.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop() error = %v, want context.DeadlineExceeded", err)
	}
	waitFor(t, "the force-closed connection to be untracked", func() bool { return f.srv.activeConns() == 0 })
}

// TestServeRetriesTimeoutsAndReportsFatalErrors pins Accept error handling: a
// timeout is transient and the loop continues, anything else ends serving with
// an error the hub can log.
func TestServeRetriesTimeoutsAndReportsFatalErrors(t *testing.T) {
	srv := New(Config{})
	lis := &scriptedListener{errs: []error{timeoutError{}, errors.New("listener is broken")}}

	err := srv.serve(lis)
	if err == nil {
		t.Fatal("serve() returned nil on a fatal accept error")
	}
	if !strings.Contains(err.Error(), "listener is broken") {
		t.Errorf("serve() error = %v, want it to carry the fatal accept error", err)
	}
	if len(lis.errs) != 0 {
		t.Errorf("serve() stopped early with %d scripted errors left: a timeout was treated as fatal", len(lis.errs))
	}
}

// TestLogAuditSurvivesAStoreFailure pins that an unwritable audit log degrades
// to a log line instead of taking the session down with it.
func TestLogAuditSurvivesAStoreFailure(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf(fmtStoreNew, err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close() error: %v", err)
	}

	srv := New(Config{Store: st})
	srv.logAudit(model.AuditSSHSessionRefused, model.AuditOutcomeFailure,
		testUserID, testServerID, "detail", "127.0.0.1")
}

// TestSplitLoginNameRejectsMalformedNames pins FR-016: both halves are required.
func TestSplitLoginNameRejectsMalformedNames(t *testing.T) {
	for _, raw := range []string{"", "alice", "+", "+web01", "alice+"} {
		if username, target, err := splitLoginName(raw); err == nil {
			t.Errorf("splitLoginName(%q) = (%q, %q), want an error", raw, username, target)
		}
	}
}

func TestSplitLoginNameSplitsOnTheFirstSeparator(t *testing.T) {
	username, target, err := splitLoginName("alice+edge+case")
	if err != nil {
		t.Fatalf("splitLoginName() error: %v", err)
	}
	if username != "alice" || target != "edge+case" {
		t.Errorf("splitLoginName() = (%q, %q), want (\"alice\", \"edge+case\")", username, target)
	}
}

// TestRemoteHostStripsThePort pins the audit address rendering, including the
// addresses net.SplitHostPort cannot parse.
func TestRemoteHostStripsThePort(t *testing.T) {
	cases := []struct {
		name string
		addr net.Addr
		want string
	}{
		{"nil address", nil, ""},
		{"tcp", namedAddr{network: "tcp", address: "10.0.0.5:2222"}, "10.0.0.5"},
		{"ipv6", namedAddr{network: "tcp", address: "[2001:db8::1]:2222"}, "2001:db8::1"},
		{"no port", namedAddr{network: "unix", address: "/run/veyport.sock"}, "/run/veyport.sock"},
	}
	for _, c := range cases {
		if got := remoteHost(c.addr); got != c.want {
			t.Errorf("remoteHost(%s) = %q, want %q", c.name, got, c.want)
		}
	}
}
