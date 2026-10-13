package store_test

import (
	"github.com/wyiu/veyport/hub/internal/lockout"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/store"
)

func TestOriginalConfirmationAndConsumptionWriteFailuresNeverReleasePartialAuthority(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "confirmation-delete-failure", now)
	if err := s.CreateOriginalAccess(a, proof, now.Add(24*time.Hour), now, lockout.Policy{}); err != nil {
		t.Fatal(err)
	}
	originalExec(t, s, `CREATE TRIGGER evidence_delete_fault BEFORE DELETE ON original_read_evidence BEGIN SELECT RAISE(ABORT,'synthetic durable delete failure'); END`)
	if err := s.AuthorizeOriginalAccess(a.ID, "verified-intent", a.ExpiresAt, a.Object, now, lockout.Policy{}); err == nil {
		t.Fatal("partial confirmation created download authority")
	}
	got, err := s.GetOriginalAccess(a.ID)
	if err != nil || got.State != "pending" || got.IntentToken != "" || got.ConsumedAt != nil {
		t.Fatal("failed queue deletion left partial authorization")
	}
	var count int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM original_read_confirmations WHERE access_id=?", a.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed authorization retained a false confirmation")
	}
	originalExec(t, s, "DROP TRIGGER evidence_delete_fault")
	if err := s.AuthorizeOriginalAccess(a.ID, "verified-intent", a.ExpiresAt, a.Object, now, lockout.Policy{}); err != nil {
		t.Fatal(err)
	}
	originalExec(t, s, `CREATE TRIGGER handle_claim_fault BEFORE UPDATE ON original_access WHEN NEW.state='started' BEGIN SELECT RAISE(ABORT,'synthetic claim write failure'); END`)
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, lockout.Policy{}); err == nil {
		t.Fatal("failed claim returned original-read authority")
	}
	got, err = s.GetOriginalAccess(a.ID)
	if err != nil || got.State != "authorized" || got.ConsumedAt != nil {
		t.Fatal("failed claim lost the atomic one-use boundary")
	}
	originalExec(t, s, "DROP TRIGGER handle_claim_fault")
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, lockout.Policy{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, lockout.Policy{}); err == nil {
		t.Fatal("repair recreated a consumed permit")
	}
}

func TestOriginalResultAndPermanentGapPersistenceFailuresKeepExactRecoverableEvidence(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "result-update-failure", now)
	authorizeOriginal(t, s, a, proof, now)
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, lockout.Policy{}); err != nil {
		t.Fatal(err)
	}
	a.BytesWritten = 3
	raw := originalRaw(t, a, "interrupted", "result", now)
	originalExec(t, s, `CREATE TRIGGER result_update_fault BEFORE UPDATE ON original_access WHEN NEW.state='interrupted' BEGIN SELECT RAISE(ABORT,'synthetic result write failure'); END`)
	if err := s.RecordOriginalOutcome(a.ID, "interrupted", 3, raw, now.Add(24*time.Hour), now); err == nil {
		t.Fatal("failed outcome write was reported recorded")
	}
	got, err := s.GetOriginalAccess(a.ID)
	if err != nil || got.State != "started" || got.BytesWritten != 0 || got.ConsumedAt == nil {
		t.Fatal("failed outcome changed durable consumption or claimed delivered bytes")
	}
	events, err := s.DueOriginalEvidence(now)
	if err != nil || len(events) != 0 {
		t.Fatal("failed result transaction retained a mismatched queue entry")
	}
	originalExec(t, s, "DROP TRIGGER result_update_fault")
	if err := s.RecordOriginalOutcome(a.ID, "interrupted", 3, raw, now.Add(24*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []struct{ name, sql string }{
		{"permanent_update_fault", `CREATE TRIGGER permanent_update_fault BEFORE UPDATE ON original_access WHEN NEW.evidence_state='permanently_incomplete' BEGIN SELECT RAISE(ABORT,'synthetic gap write failure'); END`},
		{"permanent_delete_fault", `CREATE TRIGGER permanent_delete_fault BEFORE DELETE ON original_read_evidence BEGIN SELECT RAISE(ABORT,'synthetic gap cleanup failure'); END`},
	} {
		originalExec(t, s, fault.sql)
		if err := s.MarkOriginalPermanent(a.ID); err == nil {
			t.Fatal("failed permanent-gap transaction was reported durable")
		}
		got, err = s.GetOriginalAccess(a.ID)
		events, queueErr := s.DueOriginalEvidence(now)
		if err != nil || got.State != "interrupted" || got.EvidenceState != "unconfirmed" || queueErr != nil || len(events) != 1 || string(events[0].Raw) != string(raw) {
			t.Fatal("gap write failure destroyed exact recoverable evidence")
		}
		originalExec(t, s, "DROP TRIGGER "+fault.name)
	}
	if err := s.MarkOriginalPermanent(a.ID); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetOriginalAccess(a.ID)
	if err != nil || got.State != "interrupted" || got.BytesWritten != 3 || got.EvidenceState != "permanently_incomplete" {
		t.Fatal("permanent gap changed known delivery outcome")
	}
}

func TestOriginalMetadataCorruptionBlocksRecoveryAndPruningRemainsAtomic(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "corrupt-retention", now)
	if err := s.CreateOriginalAccess(a, proof, now.Add(24*time.Hour), now, lockout.Policy{}); err != nil {
		t.Fatal(err)
	}
	originalExec(t, s, "UPDATE original_read_evidence SET min_retain_until='corrupt timestamp' WHERE access_id=?", a.ID)
	if events, err := s.DueOriginalEvidence(now); err == nil || events != nil {
		t.Fatal("malformed retention became an archive-preservation requirement")
	}
	originalExec(t, s, "UPDATE original_access SET actor='not JSON' WHERE id=?", a.ID)
	if stale, err := s.SweepOriginalAccess(now.Add(time.Minute)); err == nil || stale != nil {
		t.Fatal("corrupt actor attribution became a valid recovery operation")
	}
	// Pruning old completed/permanent metadata is one transaction. A failed
	// final deletion must retain both attribution and its exact confirmation.
	b, proof := originalFixture(t, s, "prune-failure", now)
	authorizeOriginal(t, s, b, proof, now)
	if err := s.MarkOriginalPermanent(b.ID); err != nil {
		t.Fatal(err)
	}
	originalExec(t, s, "UPDATE original_access SET created_at=? WHERE id=?", now.Add(-31*24*time.Hour).UnixMilli(), b.ID)
	originalExec(t, s, `CREATE TRIGGER prune_confirm_fault BEFORE DELETE ON original_read_confirmations BEGIN SELECT RAISE(ABORT,'synthetic confirmation prune failure'); END`)
	if _, err := s.SweepOriginalAccess(now); err == nil {
		t.Fatal("failed confirmation prune was reported complete")
	}
	originalExec(t, s, "DROP TRIGGER prune_confirm_fault")
	originalExec(t, s, `CREATE TRIGGER prune_access_fault BEFORE DELETE ON original_access BEGIN SELECT RAISE(ABORT,'synthetic metadata prune failure'); END`)
	if _, err := s.SweepOriginalAccess(now); err == nil {
		t.Fatal("failed metadata prune was reported complete")
	}
	var count int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM original_read_confirmations WHERE access_id=?", b.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("failed final deletion lost durable confirmation attribution")
	}
	originalExec(t, s, "DROP TRIGGER prune_access_fault")
	if _, err := s.SweepOriginalAccess(now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetOriginalAccess(b.ID); err == nil {
		t.Fatal("bounded old permanent metadata was never pruned")
	}
}

func TestOriginalMissingEvidenceTablesDoNotConsumeFreshOperationProof(t *testing.T) {
	for _, table := range []string{"original_read_evidence", "original_read_confirmations"} {
		t.Run(table, func(t *testing.T) {
			s := testStore(t)
			now := time.Now().UTC()
			a, proof := originalFixture(t, s, "unavailable-evidence", now)
			originalExec(t, s, "DROP TABLE "+table)
			if err := s.CreateOriginalAccess(a, proof, now.Add(24*time.Hour), now, lockout.Policy{}); err == nil {
				t.Fatal("missing durable evidence storage created original authority")
			}
			if _, err := s.GetOriginalAccess(a.ID); err == nil {
				t.Fatal("missing evidence table left partial access metadata")
			}
			var consumed any
			if err := s.DB().QueryRow("SELECT consumed_at FROM stepup_proofs WHERE hash=?", store.SecurityDigest([]byte(proof))).Scan(&consumed); err != nil || consumed != nil {
				t.Fatal("missing evidence storage burned a proof in a rolled-back operation")
			}
		})
	}
}
