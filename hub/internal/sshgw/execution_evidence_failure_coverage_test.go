package sshgw

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auditruntime"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/testaudit"
)

func evidenceFailureFixture(t *testing.T) (*Server, *testaudit.Fixture, auditgate.Gate, auditgate.OriginalMetadataClient, model.PolicyVersion) {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// The recovery worker uses the production wall clock, so its independent
	// receipt service must follow real time too, including on slow CI workers.
	f := testaudit.New(t, testaudit.NewRealClock())
	credential, _ := json.Marshal(f.Credential)
	runtime, err := auditruntime.Load(f.ConfigFile(t), auditruntime.Options{Store: st, ResolveSecret: func(ref string) (string, string, error) {
		if ref != "secret:evidence-fixture" {
			return "", "", errors.New("wrong fixture credential")
		}
		return "destination", string(credential), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	policy := model.AuditPolicy{Profile: "enhanced", Actors: []string{}, Nodes: []string{"node"}, RuntimeSeconds: 60, RetentionHours: 24, Destination: f.Config.Endpoint, CredentialRef: "secret:evidence-fixture", TrustKeyIDs: []string{"fixture-key"}, QualificationSHA256: f.Config.QualificationSHA256}
	raw, _ := json.Marshal(policy)
	if _, err = st.DB().Exec("INSERT INTO audit_policy_versions(version,payload,digest) VALUES(2,?,?)", raw, auditrecord.Hash(raw)); err != nil {
		t.Fatal(err)
	}
	p, err := st.GetPolicyVersion(2)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := runtime.ResolveArchive(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := runtime.ResolveOriginalArchive(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Store: st, ProtectedExecution: &ProtectedExecutionConfig{ResolveArchive: runtime.ResolveArchive}})
	return s, f, gate, archive.Admin, p
}

func evidenceFailureExecution(t *testing.T, s *Server, id string, policy model.PolicyVersion) *model.Execution {
	t.Helper()
	e := &model.Execution{ID: id, Enhanced: true, ActorID: "synthetic-actor", ActorName: "synthetic-actor", ActorPersonID: "synthetic-person", ActorProvider: "local", ActorSubject: "synthetic-actor", NodeID: "node", NodeName: "synthetic-target", CommandSHA256: auditrecord.Hash([]byte("synthetic private command")), CommandLength: 25, PolicyVersion: "2", PolicySHA256: policy.SHA256}
	if err := s.cfg.Store.CreateExecution(e); err != nil {
		t.Fatal(err)
	}
	if err := s.cfg.Store.FinishExecution(id, "denied", nil, "", "SYNTHETIC_PRIVATE_ERROR_CANARY"); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestExecutionEvidenceRecoveryArchivesUnpreparedDenialWithoutInventingIdentity(t *testing.T) {
	s, f, _, _, p := evidenceFailureFixture(t)
	e := evidenceFailureExecution(t, s, "recovered-denial", p)
	s.recoverExecutionEvidence(context.Background())
	stored, err := s.cfg.Store.GetExecution(e.ID)
	if err != nil || stored.State != "denied" || stored.EvidenceState != "confirmed" {
		t.Fatal("denial recovery changed process outcome or lacked external evidence")
	}
	archived := f.Originals.Envelopes()
	if len(archived) != 1 || archived[0].EventType != auditrecord.ExecutionDenial || archived[0].Execution != nil || archived[0].Details.Submission == nil || archived[0].Details.Submission.NodeID != e.NodeID || archived[0].Details.Submission.CommandSHA256 != e.CommandSHA256 {
		t.Fatal("denial lost redacted target/command binding or fabricated prepared identity")
	}
	raw, _ := json.Marshal(archived[0])
	if strings.Contains(string(raw), "PRIVATE_ERROR_CANARY") || len(archived[0].Command) != 0 || len(archived[0].Attachments) != 0 {
		t.Fatal("durable denial leaked originals/private error")
	}
	s.recoverExecutionEvidence(context.Background())
	if len(f.Originals.Envelopes()) != 1 {
		t.Fatal("recovery duplicated an immutable exact event")
	}
}

func TestExecutionEvidenceRealClockRemainsValidAfterDelayAndRepeatedRecovery(t *testing.T) {
	s, f, _, _, p := evidenceFailureFixture(t)
	fixed := testaudit.NewClock()
	before := fixed.Now()
	// Exceed the former two-second offset while preserving exact retention and
	// the verifier's normal skew. Both later writes use the actual TLS service.
	time.Sleep(2100 * time.Millisecond)
	if !fixed.Now().Equal(before) {
		t.Fatal("the deterministic clock advanced with wall time")
	}
	fixed.Advance(time.Minute)
	if !fixed.Now().Equal(before.Add(time.Minute)) {
		t.Fatal("the deterministic clock lost explicit advancement")
	}
	for _, id := range []string{"delayed-real-clock", "repeated-real-clock"} {
		e := evidenceFailureExecution(t, s, id, p)
		s.recoverExecutionEvidence(context.Background())
		stored, err := s.cfg.Store.GetExecution(e.ID)
		if err != nil || stored.EvidenceState != "confirmed" || stored.State != "denied" {
			t.Fatal("real-time recovery failed after delay or on repeated preservation")
		}
	}
	if len(f.Originals.Envelopes()) != 2 {
		t.Fatal("delayed recovery did not preserve each exact event once")
	}
}

type evidenceReplyFailure struct {
	preserver auditgate.Preserver
	admin     auditgate.OriginalMetadataClient
	mode      string
}

func (f evidenceReplyFailure) Preserve(ctx context.Context, raw []byte, inputs []auditgate.AttachmentInput) (auditrecord.Receipt, error) {
	r, err := f.preserver.Preserve(ctx, raw, inputs)
	if err != nil {
		return r, err
	}
	switch f.mode {
	case "lost-reply":
		return auditrecord.Receipt{}, errors.New("synthetic lost response")
	case "manifest-substitution":
		r.Manifest.VersionID = "unverified-substituted-version"
	case "invalid-token":
		r.Token = "unverified-token"
	}
	return r, nil
}

func (f evidenceReplyFailure) Lookup(ctx context.Context, id, hash string) (auditrecord.Receipt, error) {
	return f.admin.Lookup(ctx, id, hash)
}

func TestExecutionEvidenceReceiptFaultsRecoverExactBytesWithoutProcessRetry(t *testing.T) {
	s, fixture, gate, admin, p := evidenceFailureFixture(t)
	for _, mode := range []string{"lost-reply", "manifest-substitution", "invalid-token"} {
		t.Run(mode, func(t *testing.T) {
			e := evidenceFailureExecution(t, s, "evidence-"+mode, p)
			faulty := gate
			faulty.Preserver = evidenceReplyFailure{preserver: gate.Preserver, admin: admin, mode: mode}
			s.cfg.ProtectedExecution.ResolveArchive = func(context.Context, model.PolicyVersion) (auditgate.Gate, error) { return faulty, nil }
			s.recoverExecutionEvidence(context.Background())
			stored, err := s.cfg.Store.GetExecution(e.ID)
			if err != nil || stored.State != "denied" {
				t.Fatal("evidence transport retried/changed a denied process")
			}
			if mode == "lost-reply" {
				if stored.EvidenceState != "confirmed" {
					t.Fatal("exact authenticated lookup failed to reconcile lost preservation reply")
				}
				return
			}
			if stored.EvidenceState != "completion_unconfirmed" {
				t.Fatal("unverified response falsely confirmed evidence")
			}
			due, err := s.cfg.Store.DueExecutionEvidence(time.Now(), 32)
			if err != nil || len(due) != 0 {
				t.Fatal("failed verification bypassed documented retry backoff")
			}
			// Restore the concrete TLS clients and make only this test event due.
			// Production retry backoff remains untouched.
			s.cfg.ProtectedExecution.ResolveArchive = func(context.Context, model.PolicyVersion) (auditgate.Gate, error) { return gate, nil }
			if _, err := s.cfg.Store.DB().Exec("UPDATE execution_evidence_recovery SET next_attempt_at=? WHERE execution_id=?", time.Now().Add(-time.Second).UTC().Format("2006-01-02 15:04:05"), e.ID); err != nil {
				t.Fatal(err)
			}
			s.recoverExecutionEvidence(context.Background())
			stored, _ = s.cfg.Store.GetExecution(e.ID)
			if stored.State != "denied" || stored.EvidenceState != "confirmed" {
				t.Fatal("restored archive did not confirm exact retained event")
			}
		})
	}
	if len(fixture.Originals.Envelopes()) != 3 {
		t.Fatal("reply recovery created duplicate originals")
	}
}

func TestExecutionEvidenceDamagedOrExpiredRecoveryNeverCreatesAuthority(t *testing.T) {
	s, _, _, _, p := evidenceFailureFixture(t)
	e := evidenceFailureExecution(t, s, "damaged-policy-version", p)
	if _, err := s.cfg.Store.DB().Exec("UPDATE executions SET policy_version='damaged' WHERE id=?", e.ID); err != nil {
		t.Fatal(err)
	}
	s.recoverExecutionEvidence(context.Background())
	stored, _ := s.cfg.Store.GetExecution(e.ID)
	if stored.State != "denied" || stored.EvidenceState != "permanently_incomplete" {
		t.Fatal("damaged metadata fabricated recoverable prepared authority")
	}
	e = evidenceFailureExecution(t, s, "old-recovery-event", p)
	if err := s.queueExecutionLifecycle(execParams{metadata: e, policy: model.ExecutionPolicy{Version: p.Version}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.cfg.Store.DB().Exec("UPDATE execution_evidence_recovery SET created_at=? WHERE execution_id=?", time.Now().Add(-25*time.Hour).UTC().Format("2006-01-02 15:04:05"), e.ID); err != nil {
		t.Fatal(err)
	}
	s.recoverExecutionEvidence(context.Background())
	stored, _ = s.cfg.Store.GetExecution(e.ID)
	if stored.State != "denied" || stored.EvidenceState != "permanently_incomplete" {
		t.Fatal("expired recovery event renewed evidence/dispatch authority")
	}
	if err := s.queueExecutionLifecycle(execParams{metadata: &model.Execution{ID: "missing"}, policy: model.ExecutionPolicy{Version: p.Version}}); err == nil {
		t.Fatal("nonexistent execution manufactured evidence")
	}
	s.cfg.ProtectedExecution.ResolveArchive = nil
	s.startEvidenceRecovery() // unavailable optional runtime starts no worker.
	if s.evidenceCancel != nil {
		t.Fatal("missing resolver started an unbounded recovery worker")
	}
	if err := s.cfg.Store.Close(); err != nil {
		t.Fatal(err)
	}
	s.recoverExecutionEvidence(context.Background()) // closed storage cannot claim success or panic.
}
