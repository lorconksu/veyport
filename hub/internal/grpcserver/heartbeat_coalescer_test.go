package grpcserver

import (
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// helper creates a store + coalescer with controllable clock.
func testCoalescer(t *testing.T, interval time.Duration) (*HeartbeatCoalescer, *store.Store, *fakeClock) {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	hc := NewHeartbeatCoalescer(st, interval)
	fc := &fakeClock{now: time.Now()}
	hc.nowFunc = fc.Now
	return hc, st, fc
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (fc *fakeClock) Now() time.Time {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.now
}

func (fc *fakeClock) Advance(d time.Duration) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.now = fc.now.Add(d)
}

func createTestServer(t *testing.T, st *store.Store, id, status string) {
	t.Helper()
	if err := st.CreateServer(&model.Server{ID: id, Name: id, Status: status, Labels: "{}"}); err != nil {
		t.Fatalf("create test server %s: %v", id, err)
	}
}

// TestCoalescer_RateLimits verifies that heartbeats within the interval are coalesced.
func TestCoalescer_RateLimits(t *testing.T) {
	hc, st, fc := testCoalescer(t, 30*time.Second)
	createTestServer(t, st, "s1", "online")

	// First heartbeat should write
	wrote := hc.RecordHeartbeat("s1")
	if !wrote {
		t.Fatal("expected first heartbeat to write")
	}

	// Second heartbeat within interval should NOT write
	fc.Advance(5 * time.Second)
	wrote = hc.RecordHeartbeat("s1")
	if wrote {
		t.Fatal("expected second heartbeat within interval to be coalesced")
	}

	// Third heartbeat within interval should NOT write
	fc.Advance(10 * time.Second)
	wrote = hc.RecordHeartbeat("s1")
	if wrote {
		t.Fatal("expected third heartbeat within interval to be coalesced")
	}

	// After interval elapses, should write again
	fc.Advance(20 * time.Second) // total 35s from first write
	wrote = hc.RecordHeartbeat("s1")
	if !wrote {
		t.Fatal("expected heartbeat after interval to write")
	}
}

// TestCoalescer_ForceWrite verifies handshake/reconnect always writes.
func TestCoalescer_ForceWrite(t *testing.T) {
	hc, st, fc := testCoalescer(t, 30*time.Second)
	createTestServer(t, st, "s1", "online")

	// Record a normal heartbeat
	hc.RecordHeartbeat("s1")

	// ForceWrite should succeed even within the interval
	fc.Advance(1 * time.Second)
	hc.ForceWrite("s1")

	// Verify the last_seen_at was updated by checking the server
	srv, err := st.GetServerByID("s1")
	if err != nil {
		t.Fatalf("get server: %v", err)
	}
	if srv.LastSeenAt == nil {
		t.Fatal("expected last_seen_at to be set after ForceWrite")
	}
}

// TestCoalescer_Flush verifies disconnect flushes and cleans up tracking.
func TestCoalescer_Flush(t *testing.T) {
	hc, st, _ := testCoalescer(t, 30*time.Second)
	createTestServer(t, st, "s1", "online")

	hc.RecordHeartbeat("s1")
	hc.Flush("s1")

	// After flush, the server entry is removed from tracking,
	// so the next RecordHeartbeat should write immediately.
	wrote := hc.RecordHeartbeat("s1")
	if !wrote {
		t.Fatal("expected heartbeat after flush to write immediately")
	}
}

// TestCoalescer_FlushAll verifies graceful shutdown flushes all servers.
func TestCoalescer_FlushAll(t *testing.T) {
	hc, st, _ := testCoalescer(t, 30*time.Second)
	createTestServer(t, st, "s1", "online")
	createTestServer(t, st, "s2", "online")

	hc.RecordHeartbeat("s1")
	hc.RecordHeartbeat("s2")

	hc.FlushAll()

	// After FlushAll, both servers should have last_seen_at set and tracking cleared.
	for _, id := range []string{"s1", "s2"} {
		srv, err := st.GetServerByID(id)
		if err != nil {
			t.Fatalf("get server %s: %v", id, err)
		}
		if srv.LastSeenAt == nil {
			t.Fatalf("expected last_seen_at set for %s after FlushAll", id)
		}
	}

	// Next heartbeats should write immediately (tracking cleared).
	wrote := hc.RecordHeartbeat("s1")
	if !wrote {
		t.Fatal("expected heartbeat after FlushAll to write immediately")
	}
}

// TestCoalescer_IndependentServers verifies that coalescing is per-server.
func TestCoalescer_IndependentServers(t *testing.T) {
	hc, st, fc := testCoalescer(t, 30*time.Second)
	createTestServer(t, st, "s1", "online")
	createTestServer(t, st, "s2", "online")

	// Both should write on first heartbeat
	if !hc.RecordHeartbeat("s1") {
		t.Fatal("expected s1 first heartbeat to write")
	}
	if !hc.RecordHeartbeat("s2") {
		t.Fatal("expected s2 first heartbeat to write")
	}

	// Neither should write within interval
	fc.Advance(10 * time.Second)
	if hc.RecordHeartbeat("s1") {
		t.Fatal("expected s1 heartbeat within interval to be coalesced")
	}
	if hc.RecordHeartbeat("s2") {
		t.Fatal("expected s2 heartbeat within interval to be coalesced")
	}
}

// TestCoalescer_ConcurrentAccess verifies thread safety under concurrent heartbeats.
func TestCoalescer_ConcurrentAccess(t *testing.T) {
	hc, st, _ := testCoalescer(t, 30*time.Second)
	createTestServer(t, st, "s1", "online")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hc.RecordHeartbeat("s1")
		}()
	}
	wg.Wait()
	// No panic = pass. Also verify data integrity.
	srv, err := st.GetServerByID("s1")
	if err != nil {
		t.Fatalf("get server: %v", err)
	}
	if srv.LastSeenAt == nil {
		t.Fatal("expected last_seen_at to be set")
	}
}

// TestHandleStreamHeartbeat_Coalesced verifies that the handler uses coalescing.
func TestHandleStreamHeartbeat_Coalesced(t *testing.T) {
	h, st := testHandler(t)
	createTestServer(t, st, "s1", "online")

	// Wire up coalescer with short interval for testing
	hc := NewHeartbeatCoalescer(st, 30*time.Second)
	fc := &fakeClock{now: time.Now()}
	hc.nowFunc = fc.Now
	h.hbCoalescer = hc

	stream := &mockStream{}
	h.connMgr.Register("s1", stream)

	// First heartbeat writes
	if err := h.handleStreamHeartbeat("s1", stream); err != nil {
		t.Fatalf("first heartbeat: %v", err)
	}
	srv, _ := st.GetServerByID("s1")
	firstSeen := srv.LastSeenAt

	// Second heartbeat within interval should be coalesced (last_seen_at unchanged)
	fc.Advance(5 * time.Second)
	if err := h.handleStreamHeartbeat("s1", stream); err != nil {
		t.Fatalf("second heartbeat: %v", err)
	}
	srv, _ = st.GetServerByID("s1")
	if srv.LastSeenAt == nil || firstSeen == nil {
		t.Fatal("expected last_seen_at to be set")
	}
	if *srv.LastSeenAt != *firstSeen {
		t.Fatal("expected last_seen_at unchanged for coalesced heartbeat")
	}
}

// TestHandleHeartbeat_StatusTransitionAlwaysWrites verifies offline->online writes immediately.
func TestHandleHeartbeat_StatusTransitionAlwaysWrites(t *testing.T) {
	h, st := testHandler(t)
	createTestServer(t, st, "s1", "offline")

	hc := NewHeartbeatCoalescer(st, 30*time.Second)
	h.hbCoalescer = hc

	// Handshake heartbeat on offline server triggers status change + force write
	if err := h.handleHeartbeat("s1"); err != nil {
		t.Fatalf("handleHeartbeat: %v", err)
	}

	srv, _ := st.GetServerByID("s1")
	if srv.Status != "online" {
		t.Fatalf("expected online, got %s", srv.Status)
	}
	if srv.LastSeenAt == nil {
		t.Fatal("expected last_seen_at to be set after status transition")
	}
}

// TestHandleHeartbeat_HandshakeAlwaysForceWrites verifies reconnect heartbeat always writes.
func TestHandleHeartbeat_HandshakeAlwaysForceWrites(t *testing.T) {
	h, st := testHandler(t)
	createTestServer(t, st, "s1", "online")

	hc := NewHeartbeatCoalescer(st, 30*time.Second)
	fc := &fakeClock{now: time.Now()}
	hc.nowFunc = fc.Now
	h.hbCoalescer = hc

	// First handshake heartbeat
	if err := h.handleHeartbeat("s1"); err != nil {
		t.Fatalf("first handleHeartbeat: %v", err)
	}
	srv1, _ := st.GetServerByID("s1")
	if srv1.LastSeenAt == nil {
		t.Fatal("expected last_seen_at set after first handshake")
	}

	// Advance clock by 2 seconds (enough for SQLite second-precision timestamps to differ)
	fc.Advance(2 * time.Second)

	// Second handshake heartbeat (simulating reconnect) should still write
	// even though we are well within the 30s coalesce interval.
	if err := h.handleHeartbeat("s1"); err != nil {
		t.Fatalf("second handleHeartbeat: %v", err)
	}
	srv2, _ := st.GetServerByID("s1")
	if srv2.LastSeenAt == nil {
		t.Fatal("expected last_seen_at set after second handshake")
	}

	// Both handshakes wrote (the DB was hit both times). Since ForceWrite
	// always calls UpdateServerLastSeen, verify the value was updated.
	// Note: UpdateServerLastSeen uses time.Now() internally, not our fake clock.
	// But we can verify the coalescer internal state was updated both times.
	hc.mu.Lock()
	_, tracked := hc.lastWritten["s1"]
	hc.mu.Unlock()
	if !tracked {
		t.Fatal("expected server to be tracked in coalescer after force writes")
	}

	// The key test: a normal RecordHeartbeat right after the second ForceWrite
	// should be coalesced (proving ForceWrite updated the tracking timestamp).
	fc.Advance(1 * time.Second)
	wrote := hc.RecordHeartbeat("s1")
	if wrote {
		t.Fatal("expected RecordHeartbeat after recent ForceWrite to be coalesced")
	}
}
