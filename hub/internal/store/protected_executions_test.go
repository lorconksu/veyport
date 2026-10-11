package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func protectedExecution(t *testing.T, s *store.Store, id string) *model.Execution {
	t.Helper()
	e := &model.Execution{ID: id, ActorID: "actor", ActorPersonID: "person", ActorName: "actor", NodeID: "node", NodeName: "node", Enhanced: true, CommandSHA256: auditrecord.Hash([]byte("id")), CommandLength: 2, PolicyVersion: "1", PolicySHA256: auditrecord.Hash([]byte("policy"))}
	if err := s.CreateExecution(e); err != nil {
		t.Fatal(err)
	}
	e.Preparation = model.ExecutionPreparation{PreparationID: id + ".prep", BootID: "boot", ExpiresUnixMilli: time.Now().Add(time.Minute).UnixMilli(), Identity: model.ExecutionIdentity{Username: "root", UID: 0, GID: 0, Groups: []uint32{0}, GroupsSHA256: auditrecord.Hash([]byte("groups")), IdentitySHA256: auditrecord.Hash([]byte("identity")), Home: "/root", Shell: "/bin/sh", Cwd: "/root"}}
	if err := s.PrepareExecution(id, e.Preparation); err != nil {
		t.Fatal(err)
	}
	return e
}
func denialEvidence(t *testing.T, e *model.Execution) []byte {
	t.Helper()
	raw, err := json.Marshal(auditrecord.Envelope{SchemaVersion: 1, EventID: e.ID + ".completion", EventType: auditrecord.ExecutionDenial, Actor: auditrecord.Actor{UserID: e.ActorID, PersonID: e.ActorPersonID, Name: e.ActorName}, PolicyVersion: 1, PolicySHA256: e.PolicySHA256, OccurredAt: time.Now().UTC(), Details: &auditrecord.Details{CorrelationID: e.ID, State: "admission_failed", Submission: &auditrecord.SubmissionBinding{NodeID: e.NodeID, NodeName: e.NodeName, CommandSHA256: e.CommandSHA256, CommandBytes: int64(e.CommandLength)}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProtectedReceiptAndDispatchShareOneDurableClaim(t *testing.T) {
	s := testStore(t)
	e := protectedExecution(t, s, "first")
	hash := auditrecord.Hash([]byte("receipt"))
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.Claim(context.Background(), e.ID, e.Preparation.PreparationID, hash)
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("claims=%d", success)
	}
	got, err := s.GetExecution(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "dispatching" || got.AdmissionDisposition != "consumed_dispatch" {
		t.Fatal("claim and state not atomic")
	}
	second := protectedExecution(t, s, "second")
	if err = s.ClaimExecutionDispatch(second.ID, second.Preparation.PreparationID); err == nil {
		t.Fatal("Standard path bypassed protected admission")
	}
	if err = s.Claim(context.Background(), second.ID, second.Preparation.PreparationID, hash); err == nil {
		t.Fatal("receipt replayed for another execution")
	}
	got, err = s.GetExecution(second.ID)
	if err != nil || got.State != "prepared" {
		t.Fatal("receipt conflict left partial dispatch state")
	}
	if err = s.ClaimExecutionDispatch(e.ID, e.Preparation.PreparationID); err == nil {
		t.Fatal("protected permit was double-claimed by Standard path")
	}
	if err = s.ReconcileExecutions(); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetExecution(e.ID)
	if err != nil || got.State != "outcome_unknown" || got.EvidenceState != "completion_unconfirmed" {
		t.Fatal("restart lost uncertain launch")
	}
}
func TestProtectedExpiredAndWrongPreparationCannotClaim(t *testing.T) {
	s := testStore(t)
	e := protectedExecution(t, s, "expired")
	if err := s.Claim(context.Background(), e.ID, "wrong", auditrecord.Hash([]byte("receipt"))); err == nil {
		t.Fatal("wrong preparation accepted")
	}
	if _, err := s.DB().Exec(`UPDATE executions SET preparation=json_set(preparation,'$.expires_unix_milli',?) WHERE id=?`, time.Now().Add(-time.Second).UnixMilli(), e.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Claim(context.Background(), e.ID, e.Preparation.PreparationID, auditrecord.Hash([]byte("receipt"))); err == nil {
		t.Fatal("expired preparation accepted")
	}
	var count int
	if err := s.DB().QueryRow(`SELECT count(*) FROM execution_dispatches`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied preparation consumed receipt")
	}
}
func TestProtectedCompletionExitSurvivesEvidenceOutageAndBoundedRecovery(t *testing.T) {
	s := testStore(t)
	e := protectedExecution(t, s, "completion")
	code := int32(42)
	if err := s.FinishExecution(e.ID, "exited", &code, "", ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetExecution(e.ID)
	if err != nil || got.State != "exited" || got.ExitCode == nil || *got.ExitCode != 42 || got.EvidenceState != "completion_unconfirmed" {
		t.Fatal("completion evidence changed actual process outcome")
	}
	raw := denialEvidence(t, e)
	minimum := time.Now().Add(24 * time.Hour)
	if err = s.QueueExecutionEvidence(raw, minimum); err != nil {
		t.Fatal(err)
	}
	if err = s.QueueExecutionEvidence(raw, minimum); err != nil {
		t.Fatal("same evidence is not idempotent")
	}
	var envelope auditrecord.Envelope
	_ = json.Unmarshal(raw, &envelope)
	envelope.Details.State = "changed"
	changed, _ := json.Marshal(envelope)
	if err = s.QueueExecutionEvidence(changed, minimum); err == nil {
		t.Fatal("same event accepted different content")
	}
	queued, err := s.DueExecutionEvidence(time.Now().Add(time.Second), 32)
	if err != nil || len(queued) != 1 {
		t.Fatalf("queue=%d err=%v", len(queued), err)
	}
	if !queued[0].MinRetainUntil.Equal(minimum) {
		t.Fatal("recovery shortened the exact required retention deadline")
	}
	if err = s.RetryExecutionEvidence(queued[0], time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmExecutionEvidence(queued[0].EventID); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetExecution(e.ID)
	if err != nil || got.EvidenceState != "confirmed" || *got.ExitCode != 42 {
		t.Fatal("confirmed evidence lost original exit")
	}
	envelope.EventID = e.ID + ".running"
	envelope.Details.State = "running"
	raw, _ = json.Marshal(envelope)
	if err = s.QueueExecutionEvidence(raw, minimum); err != nil {
		t.Fatal(err)
	}
	queued, _ = s.DueExecutionEvidence(time.Now().Add(time.Minute), 32)
	if err = s.RetryExecutionEvidence(queued[0], queued[0].CreatedAt.Add(store.MaxRecoveryAge)); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetExecution(e.ID)
	if got.EvidenceState != "permanently_incomplete" || *got.ExitCode != 42 {
		t.Fatal("retry age lost explicit permanent gap")
	}
}
func TestProtectedRecoveryRejectsRawPayloadAndStopsAtCountLimit(t *testing.T) {
	s := testStore(t)
	e := protectedExecution(t, s, "bounded")
	raw := denialEvidence(t, e)
	var envelope auditrecord.Envelope
	_ = json.Unmarshal(raw, &envelope)
	envelope.Details.Reason = "SYNTHETIC_SECRET_raw-command"
	bad, _ := json.Marshal(envelope)
	if err := s.QueueExecutionEvidence(bad, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("raw diagnostic entered ordinary recovery")
	}
	tx, err := s.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < store.MaxRecoveryEvents; i++ {
		if _, err = tx.Exec(`INSERT INTO execution_evidence_recovery(event_id,execution_id,policy_version,record_sha256,envelope,min_retain_until,created_at,next_attempt_at) VALUES(?,?,?,?,?,?,?,?)`, time.Unix(int64(i), 0).String(), e.ID, 1, auditrecord.Hash(nil), []byte("{}"), "2099-01-01", "2026-01-01", "2099-01-01"); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = s.QueueExecutionEvidence(raw, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetExecution(e.ID)
	if got.EvidenceState != "permanently_incomplete" {
		t.Fatal("queue overflow did not record permanent evidence gap")
	}
}

func TestProtectedEvidenceAcknowledgementsRequireFullDurabilityAndSurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executions.db")
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	s.DB().SetMaxOpenConns(1)
	fullCommit := func(operation func() error) {
		t.Helper()
		if _, err := s.DB().Exec("PRAGMA synchronous=NORMAL"); err != nil {
			t.Fatal(err)
		}
		if err := operation(); err != nil {
			t.Fatal(err)
		}
		var mode int
		if err := s.DB().QueryRow("PRAGMA synchronous").Scan(&mode); err != nil || mode != 2 {
			t.Fatal("protected acknowledgement used WAL NORMAL durability")
		}
	}
	e := protectedExecution(t, s, "durable-confirmation")
	fullCommit(func() error {
		return s.Claim(context.Background(), e.ID, e.Preparation.PreparationID, auditrecord.Hash([]byte("receipt")))
	})
	code := int32(42)
	if err := s.FinishExecution(e.ID, "exited", &code, "", ""); err != nil {
		t.Fatal(err)
	}
	fullCommit(func() error { return s.QueueExecutionEvidence(denialEvidence(t, e), time.Now().Add(time.Hour)) })
	fullCommit(func() error { return s.ConfirmExecutionEvidence(e.ID + ".completion") })
	expired := protectedExecution(t, s, "durable-expiry")
	if err := s.FinishExecution(expired.ID, "admission_failed", nil, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueExecutionEvidence(denialEvidence(t, expired), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	queued, err := s.DueExecutionEvidence(time.Now().Add(time.Second), 32)
	if err != nil || len(queued) != 1 {
		t.Fatal("expiry evidence was not queued")
	}
	fullCommit(func() error {
		return s.RetryExecutionEvidence(queued[0], queued[0].CreatedAt.Add(store.MaxRecoveryAge))
	})
	permanent := protectedExecution(t, s, "durable-permanent")
	fullCommit(func() error { return s.MarkExecutionEvidencePermanent(permanent.ID) })
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetExecution(e.ID)
	if err != nil || got.EvidenceState != "confirmed" || got.ExitCode == nil || *got.ExitCode != 42 {
		t.Fatal("reopen lost confirmed actual process completion")
	}
	for _, id := range []string{expired.ID, permanent.ID} {
		got, err := s.GetExecution(id)
		if err != nil || got.EvidenceState != "permanently_incomplete" {
			t.Fatal("reopen lost permanent evidence gap")
		}
	}
}

func TestProtectedUnusedAdmissionIsRedactedAndMissingCompletionCanRecover(t *testing.T) {
	s := testStore(t)
	e := protectedExecution(t, s, "unused-admission")
	if err := s.SetExecutionSubmission(e.ID, "", 0, e.ID+".admission", auditrecord.Hash([]byte("record"))); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveUnusedExecutionReceipt(e.ID, "synthetic-verified-receipt"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkExecutionAdmissionUnused(e.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetExecution(e.ID)
	if err != nil || got.AdmissionDisposition != "archived_unused" || got.State != "prepared" {
		t.Fatal("archived unused authority became a dispatch claim")
	}
	public, err := json.Marshal(got)
	if err != nil || bytes.Contains(public, []byte("synthetic-verified-receipt")) {
		t.Fatal("receipt authority escaped ordinary execution metadata")
	}
	if err := s.FinishExecution(e.ID, "admission_failed", nil, "", ""); err != nil {
		t.Fatal(err)
	}
	missing, err := s.UnqueuedEnhancedExecutions(0)
	if err != nil || len(missing) != 1 || missing[0].ID != e.ID {
		t.Fatal("durable outcome without queued evidence was not recoverable")
	}
	raw := denialEvidence(t, e)
	if _, err := store.DecodeExecutionEvidence(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DecodeExecutionEvidence([]byte("invalid")); err == nil {
		t.Fatal("invalid recovery payload accepted")
	}
	var envelope auditrecord.Envelope
	_ = json.Unmarshal(raw, &envelope)
	envelope.Details.Reason = "SYNTHETIC_SECRET_command"
	bad, _ := json.Marshal(envelope)
	if _, err := store.DecodeExecutionEvidence(bad); err == nil {
		t.Fatal("raw reason accepted by recovery decoder")
	}
	if err := s.QueueExecutionEvidence(raw, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	missing, err = s.UnqueuedEnhancedExecutions(100)
	if err != nil || len(missing) != 0 {
		t.Fatal("queued completion was reconstructed again")
	}
	if err := s.ConfirmExecutionEvidence(e.ID + ".completion"); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueExecutionEvidence(raw, time.Now().Add(time.Hour)); err != nil {
		t.Fatal("confirmed exact event was not idempotent")
	}
	queued, err := s.DueExecutionEvidence(time.Now().Add(time.Second), 100)
	if err != nil || len(queued) != 0 {
		t.Fatal("confirmed receipt was queued again")
	}
	claimed := protectedExecution(t, s, "consumed-unused")
	if err := s.SetExecutionSubmission(claimed.ID, "", 0, claimed.ID+".admission", auditrecord.Hash([]byte("other-record"))); err != nil {
		t.Fatal(err)
	}
	if err := s.Claim(context.Background(), claimed.ID, claimed.Preparation.PreparationID, auditrecord.Hash([]byte("other-receipt"))); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveExecutionReceipt(claimed.ID, "synthetic-verified-consumed-receipt"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkExecutionAdmissionUnused(claimed.ID); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetExecution(claimed.ID)
	if err != nil || got.AdmissionDisposition != "consumed_unused" {
		t.Fatal("consumed but unused admission lost its disposition")
	}
	for _, token := range []string{"", string(make([]byte, auditrecord.MaxReceiptBytes+1))} {
		if s.SaveExecutionReceipt(claimed.ID, token) == nil || s.SaveUnusedExecutionReceipt(claimed.ID, token) == nil {
			t.Fatal("missing or unbounded receipt persisted")
		}
	}
}

func TestProtectedStorageFailureNeverAcknowledgesAuthorityOrEvidence(t *testing.T) {
	s := testStore(t)
	e := protectedExecution(t, s, "unavailable-storage")
	raw := denialEvidence(t, e)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	operations := map[string]func() error{
		"claim": func() error {
			return s.Claim(context.Background(), e.ID, e.Preparation.PreparationID, auditrecord.Hash([]byte("receipt")))
		},
		"bad-claim":    func() error { return s.Claim(context.Background(), e.ID, e.Preparation.PreparationID, "invalid") },
		"queue":        func() error { return s.QueueExecutionEvidence(raw, time.Now().Add(time.Hour)) },
		"confirmation": func() error { return s.ConfirmExecutionEvidence(e.ID + ".completion") },
		"permanent":    func() error { return s.MarkExecutionEvidencePermanent(e.ID) },
		"expiry": func() error {
			return s.RetryExecutionEvidence(store.ExecutionEvidence{ExecutionID: e.ID, CreatedAt: time.Now().Add(-store.MaxRecoveryAge)}, time.Now())
		},
		"lookup":           func() error { _, err := s.DueExecutionEvidence(time.Now(), 0); return err },
		"missing-outcomes": func() error { _, err := s.UnqueuedEnhancedExecutions(32); return err },
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil {
				t.Fatal("unavailable durable storage falsely acknowledged protected state")
			}
		})
	}
}
