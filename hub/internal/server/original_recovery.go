package server

import (
	"context"
	"sync"
	"time"

	"github.com/wyiu/veyport/hub/internal/store"
)

type originalRecovery struct {
	wake   chan struct{}
	cancel context.CancelFunc
	once   sync.Once
	wg     sync.WaitGroup
}

func (s *Server) startOriginalRecovery() {
	if s.originalAccess.ResolveArchive == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	worker := &originalRecovery{wake: make(chan struct{}, 1), cancel: cancel}
	s.originalRecovery = worker
	worker.wg.Add(1)
	go func() {
		defer worker.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		s.recoverOriginalEvidence(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.recoverOriginalEvidence(ctx)
			case <-worker.wake:
				s.recoverOriginalEvidence(ctx)
			}
		}
	}()
}
func (s *Server) stopOriginalRecovery() {
	if worker := s.originalRecovery; worker != nil {
		worker.once.Do(worker.cancel)
		worker.wg.Wait()
	}
}
func (s *Server) wakeOriginalRecovery() {
	if worker := s.originalRecovery; worker != nil {
		select {
		case worker.wake <- struct{}{}:
		default:
		}
	}
}

func (s *Server) recoverOriginalEvidence(ctx context.Context) {
	now := s.now()
	stale, err := s.store.SweepOriginalAccess(now)
	if err == nil {
		for _, a := range stale {
			state := "expired"
			if a.State == "started" {
				state = "unconfirmed"
			}
			stamp := a.ExpiresAt
			if a.ConsumedAt != nil {
				stamp = *a.ConsumedAt
			}
			raw, err := originalEnvelope(a, state, "result", stamp)
			policy, pErr := s.store.GetPolicyVersion(a.PolicyVersion)
			if err != nil || pErr != nil {
				_ = s.store.MarkOriginalPermanent(a.ID)
				continue
			}
			if err = s.store.RecordOriginalOutcome(a.ID, state, a.BytesWritten, raw, now.Add(time.Duration(policy.Policy.RetentionHours)*time.Hour), now); err != nil {
				_ = s.store.MarkOriginalPermanent(a.ID)
			}
		}
	}
	events, err := s.store.DueOriginalEvidence(now)
	if err != nil {
		return
	}
	for _, e := range events {
		if ctx.Err() != nil {
			return
		}
		if now.Sub(e.CreatedAt) >= store.OriginalEvidenceMaxAge {
			_ = s.store.RetryOriginalEvidence(e, now)
			continue
		}
		a, err := s.store.GetOriginalAccess(e.AccessID)
		if err != nil {
			continue
		}
		// Pending intent recovery is evidence only, after permit expiry. It
		// never races a live handler or turns a failed request into authority.
		if e.EventID == a.ID+".intent" && now.Before(a.ExpiresAt) {
			continue
		}
		policy, err := s.store.GetPolicyVersion(e.PolicyVersion)
		if err != nil || policy.SHA256 != a.PolicySHA256 {
			_ = s.store.RetryOriginalEvidence(e, now)
			continue
		}
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		archive, err := s.originalAccess.ResolveArchive(attempt, policy)
		if err == nil {
			receipt, pErr := preserveOriginal(attempt, archive, e.Raw, e.MinRetainUntil, s.now(), false)
			err = pErr
			if err == nil {
				err = s.store.ConfirmOriginalEvidence(e.EventID, receipt.Manifest, s.now())
			}
		}
		cancel()
		if err != nil {
			_ = s.store.RetryOriginalEvidence(e, now)
		}
	}
}
