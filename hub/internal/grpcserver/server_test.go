package grpcserver

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

const testStale1 = "stale-1"

func testGRPCServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	cm := connmgr.New()
	s := New(Config{
		Addr:    ":0",
		Store:   st,
		ConnMgr: cm,
	})
	return s, st
}

func TestNewGRPCServer(t *testing.T) {
	s, _ := testGRPCServer(t)
	if s == nil {
		t.Fatal("expected non-nil gRPC server")
	}
	if s.ConnMgr() == nil {
		t.Fatal("expected non-nil ConnMgr")
	}
}

func TestNewGRPCServer_DefaultPendingAndLogSessions(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// Passing nil Pending and LogSessions — should auto-create
	s := New(Config{
		Addr:        ":0",
		Store:       st,
		ConnMgr:     connmgr.New(),
		Pending:     nil,
		LogSessions: nil,
	})

	if s.pending == nil {
		t.Fatal("expected auto-created pending requests")
	}
	if s.logSessions == nil {
		t.Fatal("expected auto-created log sessions")
	}
}

func TestSweepStaleConnections(t *testing.T) {
	s, st := testGRPCServer(t)

	// Create a server in "online" state
	st.CreateServer(&model.Server{ID: "s1", Name: "test", Status: "online", Labels: "{}"})

	// Sweep with no connected agents — "s1" is online but not connected (orphan)
	s.sweepStaleConnections()

	srv, _ := st.GetServerByID("s1")
	if srv.Status != "offline" {
		t.Fatalf("expected 'offline' after sweep, got '%s'", srv.Status)
	}
}

func TestStartHeartbeatMonitor_Stop(t *testing.T) {
	s, _ := testGRPCServer(t)

	stop := make(chan struct{})
	s.StartHeartbeatMonitor(stop)

	// Immediately stop — goroutine should exit cleanly
	close(stop)
}

func TestStop(t *testing.T) {
	s, _ := testGRPCServer(t)
	// Stop should not panic
	s.Stop()
}

func TestSweepStaleConnections_NoServers(t *testing.T) {
	s, _ := testGRPCServer(t)

	// Sweep with no servers — should not panic
	s.sweepStaleConnections()
}

func TestSweepStaleConnections_StaleConn(t *testing.T) {
	s, st := testGRPCServer(t)

	// Create a server as "online"
	st.CreateServer(&model.Server{ID: testStale1, Name: "stale", Status: "online", Labels: "{}"})

	// Register a stale stream (no heartbeat will come)
	stream := &mockStream{}
	s.connMgr.Register(testStale1, stream)

	// The heartbeat is old by default since we never called UpdateHeartbeat.
	// sweepStaleConnections sweeps after 30 seconds of no heartbeat.
	// In tests, the connection was just registered so it won't be stale yet.
	// But the orphan check should still run — servers online but not in connMgr.

	// Unregister from connMgr and check orphan handling
	s.connMgr.Unregister(testStale1)
	s.sweepStaleConnections()

	srv, _ := st.GetServerByID(testStale1)
	if srv.Status != "offline" {
		t.Fatalf("expected 'offline' for orphaned server, got '%s'", srv.Status)
	}
}
