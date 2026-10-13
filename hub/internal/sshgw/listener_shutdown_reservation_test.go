package sshgw

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type shutdownReservationConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *shutdownReservationConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestStopWaitsForConnectionReservedBeforeHandlerLaunch(t *testing.T) {
	s := New(Config{})
	local, remote := net.Pipe()
	conn := &shutdownReservationConn{Conn: local, closed: make(chan struct{})}
	t.Cleanup(func() { _ = conn.Close(); _ = remote.Close() })
	if !s.trackConn(conn) {
		t.Fatal("first accepted connection was refused")
	}

	// Hold the serve loop exactly after admission and before handler launch.
	// Shutdown must join this connection even though no handler has run yet.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- s.Stop(ctx) }()
	waitFor(t, "shutdown to close admission", s.isClosing)
	select {
	case err := <-stopped:
		t.Fatalf("Stop returned before the reserved handler could finish: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Dispatch is delayed until force-close, reproducing a scheduler pause in
	// the accept loop without changing production code or handshake timeouts.
	finished := make(chan struct{})
	go func() {
		<-conn.closed
		s.untrackConn(conn)
		s.wg.Done()
		close(finished)
	}()
	cancel()
	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Stop error = %v, want context cancellation", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("shutdown did not force-close the reserved connection")
	}
	select {
	case <-finished:
	case <-time.After(waitTimeout):
		t.Fatal("reserved handler was not joined during shutdown")
	}
	if got := s.activeConns(); got != 0 {
		t.Fatalf("shutdown left %d tracked connections", got)
	}
}

func TestConnectionCapAndShutdownRefusalsDoNotReserveHandlers(t *testing.T) {
	s := New(Config{MaxConns: 1})
	first, firstPeer := net.Pipe()
	second, secondPeer := net.Pipe()
	t.Cleanup(func() {
		_ = first.Close()
		_ = firstPeer.Close()
		_ = second.Close()
		_ = secondPeer.Close()
	})
	if !s.trackConn(first) {
		t.Fatal("first accepted connection was refused")
	}
	if s.trackConn(second) {
		t.Fatal("connection cap allowed a second handler")
	}
	s.untrackConn(first)
	s.wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("refused connection stranded shutdown: %v", err)
	}
	if s.trackConn(second) {
		t.Fatal("shutdown admitted a new connection")
	}
	drained := make(chan struct{})
	go func() { s.wg.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-ctx.Done():
		t.Fatal("post-shutdown refusal reserved handler work")
	}
	if got := s.activeConns(); got != 0 {
		t.Fatalf("refused connections left %d tracked connections", got)
	}
}
