package sshgw

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func lifecycleEnvelope(e *model.Execution) (auditrecord.Envelope, error) {
	version, err := strconv.ParseUint(e.PolicyVersion, 10, 64)
	if err != nil {
		return auditrecord.Envelope{}, err
	}
	i := e.Preparation.Identity
	l := e.Preparation.Limits
	envelope := auditrecord.Envelope{SchemaVersion: 1, EventID: e.ID + ".completion", EventType: auditrecord.ExecutionLifecycle, Actor: auditrecord.Actor{UserID: e.ActorID, PersonID: e.ActorPersonID, Name: e.ActorName, Provider: e.ActorProvider, Subject: e.ActorSubject}, PolicyVersion: version, PolicySHA256: e.PolicySHA256, OccurredAt: e.UpdatedAt.UTC(), Execution: &auditrecord.ExecutionBinding{ExecutionID: e.ID, PreparationID: e.Preparation.PreparationID, BootID: e.Preparation.BootID, NodeID: e.NodeID, NodeName: e.NodeName, Identity: auditrecord.Identity{Username: i.Username, UID: i.UID, GID: i.GID, Groups: i.Groups, GroupsSHA256: i.GroupsSHA256, IdentitySHA256: i.IdentitySHA256, Home: i.Home, Shell: i.Shell, CWD: i.Cwd}, CommandSHA256: e.CommandSHA256, CommandBytes: int64(e.CommandLength), ScriptSHA256: e.ScriptSHA256, ScriptBytes: e.ScriptLength, PreparedUntil: time.UnixMilli(e.Preparation.ExpiresUnixMilli).UTC(), Limits: auditrecord.Limits{MaxFrameBytes: l.MaxFrameBytes, MaxBufferBytes: l.MaxBufferBytes, RuntimeSeconds: l.RuntimeSeconds, TermGraceSeconds: l.TermGraceSeconds, BlockedConsumerSeconds: l.BlockedConsumerSeconds}}, Details: &auditrecord.Details{CorrelationID: e.ID, State: e.State, ExitCode: e.ExitCode}}
	if e.Preparation.PreparationID == "" {
		envelope.EventType = auditrecord.ExecutionDenial
		envelope.Execution = nil
		envelope.Details.Submission = &auditrecord.SubmissionBinding{NodeID: e.NodeID, NodeName: e.NodeName, CommandSHA256: e.CommandSHA256, CommandBytes: int64(e.CommandLength), ScriptSHA256: e.ScriptSHA256, ScriptBytes: e.ScriptLength}
	}
	if e.FinishedAt != nil {
		envelope.OccurredAt = *e.FinishedAt
	}
	return envelope, nil
}
func (s *Server) queueExecutionLifecycle(p execParams) error {
	return s.queueExecutionEvent(p, "completion", "")
}
func (s *Server) queueExecutionEvent(p execParams, suffix, state string) error {
	metadata, err := s.cfg.Store.GetExecution(p.metadata.ID)
	if err != nil {
		return err
	}
	envelope, err := lifecycleEnvelope(metadata)
	if err != nil {
		return err
	}
	envelope.EventID = p.metadata.ID + "." + suffix
	if state != "" {
		envelope.Details.State = state
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	version, err := s.cfg.Store.GetPolicyVersion(p.policy.Version)
	if err != nil {
		return err
	}
	return s.cfg.Store.QueueExecutionEvidence(raw, time.Now().UTC().Add(time.Duration(version.Policy.RetentionHours)*time.Hour))
}
func (s *Server) wakeEvidenceRecovery() {
	select {
	case s.evidenceWake <- struct{}{}:
	default:
	}
}

func (s *Server) startEvidenceRecovery() {
	if s.cfg.ProtectedExecution == nil || s.cfg.ProtectedExecution.ResolveArchive == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	if s.closing || s.evidenceCancel != nil {
		s.mu.Unlock()
		cancel()
		return
	}
	s.evidenceCancel = cancel
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		s.recoverExecutionEvidence(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.recoverExecutionEvidence(ctx)
			case <-s.evidenceWake:
				s.recoverExecutionEvidence(ctx)
			}
		}
	}()
}

// Failed completion preservation never owns or cancels an admitted process.
// Recovery submits exactly the stored redacted envelope with its stable ID;
// lookup is historical evidence only and never renews an admission permit.
func (s *Server) recoverExecutionEvidence(ctx context.Context) {
	missing, missingErr := s.cfg.Store.UnqueuedEnhancedExecutions(32)
	if missingErr == nil {
		for _, execution := range missing {
			envelope, err := lifecycleEnvelope(execution)
			if err != nil {
				_ = s.cfg.Store.MarkExecutionEvidencePermanent(execution.ID)
				continue
			}
			raw, err := json.Marshal(envelope)
			if err != nil {
				continue
			}
			version, err := s.cfg.Store.GetPolicyVersion(envelope.PolicyVersion)
			if err != nil {
				continue
			}
			if err = s.cfg.Store.QueueExecutionEvidence(raw, time.Now().UTC().Add(time.Duration(version.Policy.RetentionHours)*time.Hour)); err != nil {
				_ = s.cfg.Store.MarkExecutionEvidencePermanent(execution.ID)
			}
		}
	}
	events, err := s.cfg.Store.DueExecutionEvidence(time.Now(), 32)
	if err != nil {
		return
	}
	for _, event := range events {
		if ctx.Err() != nil {
			return
		}
		if time.Since(event.CreatedAt) >= store.MaxRecoveryAge {
			_ = s.cfg.Store.RetryExecutionEvidence(event, time.Now())
			continue
		}
		version, versionErr := s.cfg.Store.GetPolicyVersion(event.PolicyVersion)
		if versionErr != nil {
			_ = s.cfg.Store.RetryExecutionEvidence(event, time.Now())
			continue
		}
		gate, resolveErr := s.cfg.ProtectedExecution.ResolveArchive(ctx, version)
		if resolveErr != nil || gate.Preserver == nil || gate.Verifier == nil {
			_ = s.cfg.Store.RetryExecutionEvidence(event, time.Now())
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		receipt, preserveErr := gate.Preserver.Preserve(attemptCtx, event.Envelope, nil)
		if preserveErr != nil {
			if lookup, ok := gate.Preserver.(interface {
				Lookup(context.Context, string, string) (auditrecord.Receipt, error)
			}); ok {
				receipt, preserveErr = lookup.Lookup(attemptCtx, event.EventID, event.RecordSHA256)
			}
		}
		if preserveErr == nil {
			preserveErr = verifyLifecycleReceipt(gate, receipt, event)
		}
		cancel()
		if preserveErr == nil {
			_ = s.cfg.Store.ConfirmExecutionEvidence(event.EventID)
		} else {
			_ = s.cfg.Store.RetryExecutionEvidence(event, time.Now())
		}
	}
}
func verifyLifecycleReceipt(gate auditgate.Gate, receipt auditrecord.Receipt, event store.ExecutionEvidence) error {
	expected, _, err := auditrecord.ExpectedFor(event.Envelope)
	if err != nil {
		return err
	}
	expected.MinRetainUntil = event.MinRetainUntil
	claims, err := gate.Verifier.VerifyHistorical(receipt.Token, expected, time.Now())
	if err != nil || auditrecord.Digest(claims.Manifest) != auditrecord.Digest(receipt.Manifest) {
		return auditgate.ErrReceipt
	}
	return nil
}
