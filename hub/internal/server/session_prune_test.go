package server

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wyiu/veyport/hub/internal/model"
)

// newPruneSession inserts a session row owned by userID with the given
// created/last-seen instant, then (when ended is true) immediately ends it at
// the same instant. It returns the session id.
func newPruneSession(t *testing.T, s *Server, userID string, at time.Time, ended bool) string {
	t.Helper()
	id := uuid.NewString()
	sess := &model.Session{
		ID:         id,
		UserID:     userID,
		Kind:       model.SessionKindWeb,
		IP:         "10.0.0.9",
		UserAgent:  "Mozilla/5.0",
		CreatedAt:  at,
		LastSeenAt: at,
	}
	if err := s.store.CreateSession(sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if ended {
		if _, err := s.store.EndSession(id, model.SessionEndLogout, nil, at); err != nil {
			t.Fatalf("end session: %v", err)
		}
	}
	return id
}

// TestRunSessionPrune verifies a single prune pass deletes only ended rows
// older than the retention cutoff, leaving recently-ended and live rows
// untouched (FR-013).
func TestRunSessionPrune(t *testing.T) {
	s := testServer(t)
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })

	user := newLocalUser(t, s, "prune-owner", "password123456")

	oldEnded := newPruneSession(t, s, user.ID, now.Add(-40*24*time.Hour), true)
	recentEnded := newPruneSession(t, s, user.ID, now.Add(-10*24*time.Hour), true)
	live := newPruneSession(t, s, user.ID, now.Add(-40*24*time.Hour), false)

	n, err := s.runSessionPrune(sessionPruneRetention)
	if err != nil {
		t.Fatalf("run session prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 pruned row, got %d", n)
	}

	if _, err := s.store.GetSession(oldEnded); err == nil {
		t.Fatalf("expected the old ended session %q to be pruned", oldEnded)
	}
	if _, err := s.store.GetSession(recentEnded); err != nil {
		t.Fatalf("expected the recently-ended session to survive: %v", err)
	}
	if _, err := s.store.GetSession(live); err != nil {
		t.Fatalf("expected the live session to survive: %v", err)
	}

	// A second pass finds nothing left to prune.
	n, err = s.runSessionPrune(sessionPruneRetention)
	if err != nil {
		t.Fatalf("run session prune again: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 pruned rows on the second pass, got %d", n)
	}
}

// TestStartSessionPruner_StopsCleanly starts the pruner goroutine with a very
// short interval and stops it, asserting the stop returns promptly without
// leaking the goroutine (a second stop must also be safe, since Shutdown
// paths can be invoked more than once). New already starts the pruner on the
// default 24h cadence, so the default run is stopped first to avoid two
// tickers racing against the same wait group.
func TestStartSessionPruner_StopsCleanly(t *testing.T) {
	s := testServer(t)
	s.stopSessionPruner()

	s.startSessionPruner(5*time.Millisecond, sessionPruneRetention)

	// Let it tick at least once so we exercise the running goroutine, not just
	// the immediate first run.
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		s.stopSessionPruner()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stopSessionPruner did not return in time — pruner goroutine leaked")
	}

	// Calling it again (e.g. a second Shutdown) must not panic or block.
	s.stopSessionPruner()
}

// TestServer_Shutdown_StopsSessionPruner exercises the real integration point:
// New starts the pruner automatically, and Server.Shutdown (the same method
// main's shutdown handler calls) must stop it, even when invoked twice.
func TestServer_Shutdown_StopsSessionPruner(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return in time — session pruner goroutine leaked")
	}

	// A second Shutdown (main's shutdown handler could plausibly be reached
	// twice under overlapping signals) must not panic or block either.
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("second shutdown: %v", err)
	}
}
