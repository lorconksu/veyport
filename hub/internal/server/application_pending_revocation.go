package server

import (
	"errors"
	"sync"
	"time"
)

const maxPendingApplicationRevocations = 1024
const applicationRevocationCleanupBatch = 100

type applicationRevocations struct {
	mu         sync.Mutex
	pending    map[string]time.Time
	quarantine bool
	reason     string
	observedAt time.Time
}

func newApplicationRevocations(now time.Time) *applicationRevocations {
	// Memory cannot prove what happened before a crash during a storage outage.
	// Startup must durably retire preexisting sessions and tickets first.
	return &applicationRevocations{pending: make(map[string]time.Time), quarantine: true, reason: "hub_restart", observedAt: now}
}

func (r *applicationRevocations) markLocked(id string, now time.Time) {
	if r.quarantine {
		return
	}
	if _, exists := r.pending[id]; exists {
		return
	}
	if len(r.pending) == maxPendingApplicationRevocations {
		// Never discard evidence of a denied session when the memory bound fills.
		r.quarantine, r.reason, r.observedAt = true, "access_changed", now
		return
	}
	r.pending[id] = now
}

// retryApplicationRevocationQuarantine rejects the triggering admission even
// after successful cleanup; only a subsequent fresh launch may obtain access.
func (s *Server) retryApplicationRevocationQuarantine() (bool, error) {
	r := s.applicationRevocations
	r.mu.Lock()
	if !r.quarantine {
		r.mu.Unlock()
		return false, nil
	}
	s.applicationStreams.closeAll()
	err := s.store.EndAllApplicationSessions(r.reason, r.observedAt)
	if err == nil {
		clear(r.pending)
		r.quarantine = false
	}
	r.mu.Unlock()
	if err == nil {
		err = s.auditApplicationSessionEnds()
	}
	return true, err
}

func (s *Server) checkApplicationPendingRevocation(id string) error {
	if quarantined, err := s.retryApplicationRevocationQuarantine(); quarantined {
		return errors.Join(errApplicationDenied, err)
	}
	r := s.applicationRevocations
	r.mu.Lock()
	if r.quarantine {
		r.mu.Unlock()
		return errApplicationDenied
	}
	if observedAt, pending := r.pending[id]; pending {
		s.applicationStreams.closeSession(id)
		err := s.store.EndApplicationSession(id, "access_changed", observedAt)
		if err == nil {
			delete(r.pending, id)
		}
		r.mu.Unlock()
		if err == nil {
			err = s.auditApplicationSessionEnds()
		}
		return errors.Join(errApplicationDenied, err)
	}
	// A check may hold a snapshot read before another worker durably ended it.
	// Retiring a pending marker must not make that stale snapshot admissible.
	current, err := s.store.ApplicationSessionByID(id)
	r.mu.Unlock()
	if err != nil || current.EndedAt != nil {
		return errors.Join(errApplicationDenied, err)
	}
	return nil
}

func (s *Server) persistApplicationAccessChanged(id string, now time.Time) error {
	r := s.applicationRevocations
	r.mu.Lock()
	r.markLocked(id, now)
	if r.quarantine {
		r.mu.Unlock()
		_, err := s.retryApplicationRevocationQuarantine()
		return err
	}
	observedAt := r.pending[id]
	s.applicationStreams.closeSession(id)
	err := s.store.EndApplicationSession(id, "access_changed", observedAt)
	if err == nil {
		delete(r.pending, id)
	}
	r.mu.Unlock()
	if err == nil {
		err = s.auditApplicationSessionEnds()
	}
	return err
}

// Reuse existing housekeeping; no worker or unbounded retry queue is added.
// Stop on the first storage failure rather than repeat an unavailable write.
func (s *Server) retryPendingApplicationRevocations() error {
	if quarantined, err := s.retryApplicationRevocationQuarantine(); quarantined {
		return err
	}
	r := s.applicationRevocations
	r.mu.Lock()
	count := 0
	var err error
	for id, observedAt := range r.pending {
		err = s.store.EndApplicationSession(id, "access_changed", observedAt)
		if err != nil {
			break
		}
		delete(r.pending, id)
		count++
		if count == applicationRevocationCleanupBatch {
			break
		}
	}
	r.mu.Unlock()
	if err == nil && count != 0 {
		err = s.auditApplicationSessionEnds()
	}
	return err
}
