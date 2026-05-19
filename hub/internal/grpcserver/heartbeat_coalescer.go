package grpcserver

import (
	"sync"
	"time"

	"github.com/wyiu/veyport/hub/internal/store"
)

// HeartbeatCoalescer rate-limits last_seen_at DB writes to at most once per
// coalesceInterval per server. Status transitions and handshake heartbeats
// bypass the rate limit and always write immediately.
type HeartbeatCoalescer struct {
	mu       sync.Mutex
	store    *store.Store
	interval time.Duration

	// lastWritten tracks when we last flushed last_seen_at to the DB per server.
	lastWritten map[string]time.Time

	// nowFunc is injectable for testing.
	nowFunc func() time.Time
}

// NewHeartbeatCoalescer creates a coalescer that writes at most once per interval.
func NewHeartbeatCoalescer(st *store.Store, interval time.Duration) *HeartbeatCoalescer {
	return &HeartbeatCoalescer{
		store:       st,
		interval:    interval,
		lastWritten: make(map[string]time.Time),
		nowFunc:     time.Now,
	}
}

// RecordHeartbeat writes last_seen_at to DB only if the coalesce interval has
// elapsed since the last write for this server. It returns true if a DB write
// was performed.
func (hc *HeartbeatCoalescer) RecordHeartbeat(serverID string) bool {
	hc.mu.Lock()
	now := hc.nowFunc()
	last, ok := hc.lastWritten[serverID]
	if ok && now.Sub(last) < hc.interval {
		hc.mu.Unlock()
		return false // coalesced — skip DB write
	}
	hc.lastWritten[serverID] = now
	hc.mu.Unlock()

	// DB write outside the lock — allows concurrent heartbeats from other agents
	_ = hc.store.UpdateServerLastSeen(serverID, nil)
	return true
}

// ForceWrite bypasses coalescing and writes immediately. Used for handshake
// heartbeats, status transitions, and disconnect flushes.
func (hc *HeartbeatCoalescer) ForceWrite(serverID string) {
	hc.mu.Lock()
	hc.lastWritten[serverID] = hc.nowFunc()
	hc.mu.Unlock()

	_ = hc.store.UpdateServerLastSeen(serverID, nil)
}

// Flush writes last_seen_at for a specific server (used on disconnect).
// It also cleans up the tracking entry.
func (hc *HeartbeatCoalescer) Flush(serverID string) {
	hc.mu.Lock()
	delete(hc.lastWritten, serverID)
	hc.mu.Unlock()

	_ = hc.store.UpdateServerLastSeen(serverID, nil)
}

// FlushAll writes last_seen_at for all tracked servers (used on graceful shutdown).
func (hc *HeartbeatCoalescer) FlushAll() {
	hc.mu.Lock()
	ids := make([]string, 0, len(hc.lastWritten))
	for id := range hc.lastWritten {
		ids = append(ids, id)
	}
	hc.lastWritten = make(map[string]time.Time)
	hc.mu.Unlock()

	for _, id := range ids {
		_ = hc.store.UpdateServerLastSeen(id, nil)
	}
}
