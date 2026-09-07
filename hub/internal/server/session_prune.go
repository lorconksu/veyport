package server

import (
	"log"
	"sync"
	"time"
)

// Session prune defaults (FR-013): ended sessions remain visible as history
// for 30 days and are then removed; live sessions are never touched by this
// path however old they are.
const (
	sessionPruneInterval  = 24 * time.Hour
	sessionPruneRetention = 30 * 24 * time.Hour
)

// startSessionPruner launches the background goroutine that periodically
// removes ended session rows older than retention. It runs one prune pass
// immediately (so a long-lived hub doesn't wait a full interval after
// startup before ever pruning), then again on every tick of interval, until
// stopSessionPruner is called. Follows the same ticker-goroutine shape as
// auth.TokenBlacklist.periodicCleanup.
//
// Call at most once without an intervening stopSessionPruner: a second call
// while the previous goroutine is still running would leave it unreachable
// (its stop channel is overwritten here) and stopSessionPruner would then
// hang waiting for it. New calls this once; nothing else should.
func (s *Server) startSessionPruner(interval, retention time.Duration) {
	stop := make(chan struct{})
	s.sessionPruneStop = stop
	s.sessionPruneStopOnce = &sync.Once{}

	s.sessionPruneWG.Add(1)
	go func() {
		defer s.sessionPruneWG.Done()

		s.runAndLogSessionPrune(retention)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.runAndLogSessionPrune(retention)
			case <-stop:
				return
			}
		}
	}()
}

// stopSessionPruner signals the pruner goroutine to exit and waits for it.
// Safe to call multiple times, and safe to call even if the pruner was never
// started (s.sessionPruneStop is nil).
func (s *Server) stopSessionPruner() {
	if s.sessionPruneStop == nil {
		return
	}
	s.sessionPruneStopOnce.Do(func() { close(s.sessionPruneStop) })
	s.sessionPruneWG.Wait()
}

// runAndLogSessionPrune runs one prune pass and logs the outcome: the count
// of rows removed when it deleted anything, or the error when it failed.
// Errors are logged rather than returned since the caller is a ticker loop
// with nothing to propagate them to.
func (s *Server) runAndLogSessionPrune(retention time.Duration) {
	n, err := s.runSessionPrune(retention)
	if err != nil {
		log.Printf("server: prune ended sessions: %v", err)
		return
	}
	if n > 0 {
		log.Printf("server: pruned %d ended session(s) older than %s", n, retention)
	}
}

// runSessionPrune deletes ended session rows that ended more than retention
// ago, relative to the server's clock (s.now, overridable in tests via
// SetClock). It returns the number of rows removed.
func (s *Server) runSessionPrune(retention time.Duration) (int64, error) {
	cutoff := s.now().Add(-retention)
	return s.store.PruneEndedSessions(cutoff)
}
