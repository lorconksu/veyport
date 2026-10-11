package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestOriginalDatabaseWriteFailuresRollbackProofAndHandleAuthority(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "failed-write", now)
	originalExec(t, s, `CREATE TRIGGER fail_original_queue BEFORE INSERT ON original_read_evidence BEGIN SELECT RAISE(ABORT,'synthetic evidence disk failure'); END`)
	if err := s.CreateOriginalAccess(a, proof, now.Add(24*time.Hour), now, 0); err == nil {
		t.Fatal("unpreserved intent created authority")
	}
	if _, err := s.GetOriginalAccess(a.ID); err == nil {
		t.Fatal("failed intent transaction left an access record")
	}
	var consumed any
	if err := s.DB().QueryRow("SELECT consumed_at FROM stepup_proofs WHERE hash=?", store.SecurityDigest([]byte(proof))).Scan(&consumed); err != nil || consumed != nil {
		t.Fatal("failed durable intent consumed proof")
	}
	originalExec(t, s, "DROP TRIGGER fail_original_queue")
	if err := s.CreateOriginalAccess(a, proof, now.Add(24*time.Hour), now, 0); err != nil {
		t.Fatal("rolled back proof could not be used after repaired storage:", err)
	}
	originalExec(t, s, `CREATE TRIGGER fail_original_confirmation BEFORE INSERT ON original_read_confirmations BEGIN SELECT RAISE(ABORT,'synthetic confirmation disk failure'); END`)
	if err := s.AuthorizeOriginalAccess(a.ID, "verified-token", a.ExpiresAt, a.Object, now, 0); err == nil {
		t.Fatal("failed confirmation authorized a handle")
	}
	stored, err := s.GetOriginalAccess(a.ID)
	if err != nil || stored.State != "pending" || stored.IntentToken != "" {
		t.Fatal("failed confirmation left partial authority")
	}
	if _, err = s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, 0); err == nil {
		t.Fatal("rolled back handle could be consumed")
	}
	originalExec(t, s, "DROP TRIGGER fail_original_confirmation")
	if err = s.AuthorizeOriginalAccess(a.ID, "verified-token", a.ExpiresAt, a.Object, now, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, 0); err != nil {
		t.Fatal(err)
	}
}

func TestOriginalOutcomeConflictsCannotReplaceQueuedOrConfirmedExactEvidence(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "exact-failure", now)
	authorizeOriginal(t, s, a, proof, now)
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, 0); err != nil {
		t.Fatal(err)
	}
	a.BytesWritten = 3
	raw := originalRaw(t, a, "interrupted", "result", now)
	if err := s.RecordOriginalOutcome(a.ID, "interrupted", 3, raw, now.Add(24*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	changed := originalRaw(t, a, "interrupted", "result", now.Add(time.Second))
	if err := s.RecordOriginalOutcome(a.ID, "interrupted", 3, changed, now.Add(24*time.Hour), now); !errors.Is(err, store.ErrOriginalAccess) {
		t.Fatal("queued exact event was replaced")
	}
	if err := s.ConfirmOriginalEvidence(a.ID+".result", a.Object, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordOriginalOutcome(a.ID, "interrupted", 3, changed, now.Add(24*time.Hour), now); !errors.Is(err, store.ErrOriginalAccess) {
		t.Fatal("confirmed exact event was replaced")
	}
	other := a.Object
	other.VersionID = "substituted-version"
	if err := s.ConfirmOriginalEvidence(a.ID+".result", other, now); !errors.Is(err, store.ErrOriginalAccess) {
		t.Fatal("different immutable confirmation version was accepted")
	}
	if err := s.ConfirmOriginalEvidence("absent-event", a.Object, now); err == nil {
		t.Fatal("missing event fabricated a confirmation")
	}
	stored, err := s.GetOriginalAccess(a.ID)
	if err != nil || stored.State != "interrupted" || stored.BytesWritten != 3 || stored.EvidenceState != "confirmed" {
		t.Fatal("refused evidence change downgraded the real outcome")
	}
}

func TestOriginalMalformedMetadataAndBoundaryArgumentsNeverClaim(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "invalid-boundary", now)
	authorizeOriginal(t, s, a, proof, now)
	for _, token := range []string{"", "not-a-hash"} {
		if _, err := s.ConsumeOriginalAccess(token, a.UserID, a.SessionID, now, 0); err == nil {
			t.Fatal("malformed handle claimed an original")
		}
	}
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, "", now, 0); err == nil {
		t.Fatal("sessionless handle was accepted")
	}
	originalExec(t, s, "UPDATE original_access SET object_ref=? WHERE id=?", []byte(`{"private_unknown":"SYNTHETIC_CANARY"}`), a.ID)
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, 0); err == nil {
		t.Fatal("corrupted exact-version metadata claimed an original")
	}
	var consumed any
	if err := s.DB().QueryRow("SELECT consumed_at FROM original_access WHERE id=?", a.ID).Scan(&consumed); err != nil || consumed != nil {
		t.Fatal("metadata rejection left a consumed claim")
	}
	for _, state := range []string{"fabricated", "completed"} {
		if err := s.RecordOriginalOutcome(a.ID, state, auditrecord.MaxAttachmentBytes+1, nil, now.Add(time.Hour), now); err == nil {
			t.Fatal("unbounded/fabricated outcome was accepted")
		}
	}
	if err := s.AuthorizeOriginalAccess(a.ID, "", now.Add(time.Minute), a.Object, now, 0); err == nil {
		t.Fatal("empty admission authorization was accepted")
	}
}

func TestOriginalClosedStorageNeverReportsConfirmationOrPruningSuccess(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "closed-storage", now)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"create":    func() error { return s.CreateOriginalAccess(a, proof, now.Add(time.Hour), now, 0) },
		"authorize": func() error { return s.AuthorizeOriginalAccess(a.ID, "token", a.ExpiresAt, a.Object, now, 0) },
		"claim": func() error {
			_, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, 0)
			return err
		},
		"outcome": func() error {
			return s.RecordOriginalOutcome(a.ID, "interrupted", 0, originalRaw(t, a, "interrupted", "result", now), now.Add(time.Hour), now)
		},
		"confirm": func() error { return s.ConfirmOriginalEvidence(a.ID+".result", a.Object, now) },
		"retry": func() error {
			return s.RetryOriginalEvidence(model.OriginalEvidence{EventID: a.ID + ".result", AccessID: a.ID, CreatedAt: now}, now)
		},
		"permanent": func() error { return s.MarkOriginalPermanent(a.ID) },
		"sweep":     func() error { _, err := s.SweepOriginalAccess(now); return err },
		"due":       func() error { _, err := s.DueOriginalEvidence(now); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("closed durable storage reported success")
			}
		})
	}
}

func TestOriginalOutcomeSchemaAndStateBoundariesPreserveClaim(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "outcome-boundary", now)
	authorizeOriginal(t, s, a, proof, now)
	if err := s.AuthorizeOriginalAccess(a.ID, "token", a.ExpiresAt, a.Object, now, 0); err == nil {
		t.Fatal("authorized permit returned to pending authorization")
	}
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, 0); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"completed", "expired"} {
		raw := originalRaw(t, a, state, "result", now)
		if err := s.RecordOriginalOutcome(a.ID, state, 0, raw, now.Add(time.Hour), now); err == nil {
			t.Fatal("claimed original accepted short completion or unused-permit expiry")
		}
	}
	if err := s.RecordOriginalOutcome(a.ID, "interrupted", 0, []byte("not an audit envelope"), now.Add(time.Hour), now); err == nil {
		t.Fatal("unstructured result became durable evidence")
	}
	if err := s.MarkOriginalPermanent(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordOriginalOutcome(a.ID, "interrupted", 0, originalRaw(t, a, "interrupted", "result", now), now.Add(time.Hour), now); err == nil {
		t.Fatal("permanent evidence gap was silently healed")
	}
	if err := s.ConfirmOriginalEvidence(a.ID+".result", auditrecord.ObjectRef{}, now); err == nil {
		t.Fatal("invalid object reference confirmed a gap")
	}
	stored, err := s.GetOriginalAccess(a.ID)
	if err != nil || stored.State != "started" || stored.ConsumedAt == nil || stored.EvidenceState != "permanently_incomplete" {
		t.Fatal("schema/state refusal lost consumed process state")
	}
}
