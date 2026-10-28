package store_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func originalExec(t *testing.T, s *store.Store, query string, args ...any) {
	t.Helper()
	if _, err := s.DB().Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func originalFixture(t *testing.T, s *store.Store, id string, now time.Time) (model.OriginalAccess, string) {
	t.Helper()
	u := &model.User{ID: id + ".user", Username: id + ".user", Email: id + "@test.invalid", Role: model.RoleViewer, TOTPEnabled: true}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec("INSERT INTO user_roles(user_id,role) VALUES(?,'original-reader')", u.ID); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	person, err := s.PersonForUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	sid := id + ".session"
	if err := s.CreateSession(&model.Session{ID: sid, UserID: u.ID, Kind: "web", CreatedAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	a := model.OriginalAccess{ID: id, ExecutionID: "execution", UserID: u.ID, PersonID: person, SessionID: sid, SecurityRevision: u.SecurityRevision, PolicyVersion: 1, PolicySHA256: auditrecord.Hash([]byte("policy")), Digest: auditrecord.Hash([]byte("digest")), Purpose: "Incident investigation", Kind: "envelope", Object: auditrecord.ObjectRef{Bucket: "archive", Key: "envelopes/execution", VersionID: "exact-version", SHA256: auditrecord.Hash([]byte("original")), Bytes: 8, RetainUntil: now.Add(48 * time.Hour)}, Actor: auditrecord.Actor{UserID: u.ID, PersonID: person, Name: u.Username}, HandleSHA256: auditrecord.Hash([]byte(id + ".handle")), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	a.Intent = originalRaw(t, a, "authorized", "intent", now)
	proof, err := s.IssueStepup(a.UserID, a.SessionID, model.OriginalReadAction, a.Digest, now)
	if err != nil {
		t.Fatal(err)
	}
	return a, proof
}

func originalRaw(t *testing.T, a model.OriginalAccess, state, suffix string, now time.Time) []byte {
	t.Helper()
	typ := auditrecord.OriginalReadIntent
	details := &auditrecord.Details{CorrelationID: a.ID, RequestID: a.ExecutionID, RequestSHA256: a.Digest, SessionSHA256: auditrecord.Hash([]byte(a.SessionID)), Reason: a.Purpose, State: state, Originals: []auditrecord.ObjectRef{a.Object}}
	if suffix != "intent" {
		typ = auditrecord.OriginalReadResult
		details.Delivery = &auditrecord.OriginalDelivery{BytesWritten: &a.BytesWritten, Scope: "hub_response"}
	}
	raw, err := json.Marshal(auditrecord.Envelope{SchemaVersion: 1, EventID: a.ID + "." + suffix, EventType: typ, Actor: a.Actor, PolicyVersion: a.PolicyVersion, PolicySHA256: a.PolicySHA256, OccurredAt: now, Details: details})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func authorizeOriginal(t *testing.T, s *store.Store, a model.OriginalAccess, proof string, now time.Time) {
	t.Helper()
	if err := s.CreateOriginalAccess(a, proof, now.Add(24*time.Hour), now, lockout.Policy{SessionIdle: 15 * time.Minute, CLISessionIdle: 15 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	manifest := a.Object
	manifest.Key = a.ID + ".intent.manifest"
	if err := s.AuthorizeOriginalAccess(a.ID, "verified-intent-token", a.ExpiresAt, manifest, now, lockout.Policy{SessionIdle: 15 * time.Minute, CLISessionIdle: 15 * time.Minute}); err != nil {
		t.Fatal(err)
	}
}

func TestOriginalAccessRejectsProofFromPriorCredentialGeneration(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "legacy-proof", now)
	originalExec(t, s, "UPDATE stepup_proofs SET token_generation=-1 WHERE hash=?", store.SecurityDigest([]byte(proof)))
	policy := lockout.Policy{SessionIdle: 15 * time.Minute, CLISessionIdle: 15 * time.Minute}
	if err := s.CreateOriginalAccess(a, proof, now.Add(24*time.Hour), now, policy); !errors.Is(err, store.ErrStepup) {
		t.Fatalf("legacy credential-generation proof was not rejected: %v", err)
	}
	if _, err := s.GetOriginalAccess(a.ID); err == nil {
		t.Fatal("rejected proof created original-access state")
	}
	var consumed any
	if err := s.DB().QueryRow("SELECT consumed_at FROM stepup_proofs WHERE hash=?", store.SecurityDigest([]byte(proof))).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed != nil {
		t.Fatal("rejected proof was consumed")
	}
}

func TestOriginalHandleOneUseFullDurabilityAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "single", now)
	authorizeOriginal(t, s, a, proof, now)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, lockout.Policy{SessionIdle: 15 * time.Minute, CLISessionIdle: 15 * time.Minute})
			results <- err
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
		t.Fatalf("successful claims=%d", success)
	}
	var mode int
	if err := s.DB().QueryRow("PRAGMA synchronous").Scan(&mode); err != nil || mode != 2 {
		t.Fatalf("one-use durability mode=%d err=%v", mode, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, lockout.Policy{SessionIdle: 15 * time.Minute, CLISessionIdle: 15 * time.Minute}); err == nil {
		t.Fatal("consumed handle replayed after reopen")
	}
	stored, err := s.GetOriginalAccess(a.ID)
	if err != nil || stored.ConsumedAt == nil || stored.State != "started" {
		t.Fatalf("lost durable consumption:%+v %v", stored, err)
	}
}

func TestOriginalHandleLiveAuthoritySessionAndExpiry(t *testing.T) {
	for _, mutation := range []string{"role", "revision", "person", "disabled", "session", "absolute", "idle", "handle-expiry", "wrong-user", "wrong-session"} {
		t.Run(mutation, func(t *testing.T) {
			s := testStore(t)
			now := time.Now().UTC()
			a, proof := originalFixture(t, s, mutation, now)
			authorizeOriginal(t, s, a, proof, now)
			user, sid := a.UserID, a.SessionID
			switch mutation {
			case "role":
				originalExec(t, s, "DELETE FROM user_roles WHERE user_id=? AND role='original-reader'", user)
			case "revision":
				originalExec(t, s, "UPDATE users SET security_revision=security_revision+1 WHERE id=?", user)
			case "person":
				originalExec(t, s, "INSERT INTO security_persons(id) VALUES('other-person')")
				originalExec(t, s, "UPDATE security_identity_links SET person_id='other-person' WHERE user_id=?", user)
			case "disabled":
				originalExec(t, s, "UPDATE users SET disabled_at=datetime('now') WHERE id=?", user)
			case "session":
				if _, err := s.EndSession(sid, model.SessionEndRevokedSelf, nil, now); err != nil {
					t.Fatal(err)
				}
			case "absolute":
				originalExec(t, s, "UPDATE sessions SET expires_at='2000-01-01 00:00:00' WHERE id=?", sid)
			case "idle":
				originalExec(t, s, "UPDATE sessions SET last_seen_at='2000-01-01 00:00:00' WHERE id=?", sid)
			case "handle-expiry":
				now = now.Add(time.Minute)
			case "wrong-user":
				user = "another-user"
			case "wrong-session":
				sid = "another-session"
			}
			if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, user, sid, now, lockout.Policy{SessionIdle: 15 * time.Minute, CLISessionIdle: 15 * time.Minute}); err == nil {
				t.Fatal("stale authority consumed handle")
			}
		})
	}
}

func TestOriginalProofAndIntentAreAtomicBounded(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "atomic", now)
	bad := a
	bad.Digest = auditrecord.Hash([]byte("changed-purpose"))
	if err := s.CreateOriginalAccess(bad, proof, now.Add(time.Hour), now, lockout.Policy{}); err == nil {
		t.Fatal("changed digest consumed proof")
	}
	if _, err := s.GetOriginalAccess(a.ID); err == nil {
		t.Fatal("failed proof persisted access")
	}
	if err := s.CreateOriginalAccess(a, proof, now.Add(time.Hour), now, lockout.Policy{}); err != nil {
		t.Fatal(err)
	}
	other := a
	other.ID = "replay"
	other.HandleSHA256 = auditrecord.Hash([]byte("new-handle"))
	other.Intent = originalRaw(t, other, "authorized", "intent", now)
	if err := s.CreateOriginalAccess(other, proof, now.Add(time.Hour), now, lockout.Policy{}); err == nil {
		t.Fatal("MFA proof reused")
	}
	events, err := s.DueOriginalEvidence(now)
	if err != nil || len(events) != 1 || string(events[0].Raw) != string(a.Intent) {
		t.Fatalf("intent queue:%+v %v", events, err)
	}
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, lockout.Policy{}); err == nil {
		t.Fatal("pending intent became usable")
	}
	if err := s.CreateOriginalAccess(other, "bad", now.Add(time.Hour), now, lockout.Policy{}); err == nil {
		t.Fatal("unbounded/malformed proof")
	}
}

func TestOriginalEvidencePreservesExactResultsAndPermanentGaps(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "results", now)
	authorizeOriginal(t, s, a, proof, now)
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, lockout.Policy{}); err != nil {
		t.Fatal(err)
	}
	a.BytesWritten = 3
	raw := originalRaw(t, a, "interrupted", "result", now)
	if err := s.RecordOriginalOutcome(a.ID, "interrupted", 3, raw, now.Add(24*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	events, err := s.DueOriginalEvidence(now)
	if err != nil || len(events) != 1 {
		t.Fatal(err)
	}
	if err := s.RetryOriginalEvidence(events[0], now); err != nil {
		t.Fatal(err)
	}
	due, err := s.DueOriginalEvidence(now)
	if err != nil || len(due) != 0 {
		t.Fatal("retry ignored bounded backoff")
	}
	manifest := a.Object
	manifest.Key = "result-manifest"
	if err := s.ConfirmOriginalEvidence(a.ID+".result", manifest, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmOriginalEvidence(a.ID+".result", manifest, now); err != nil {
		t.Fatal("confirmation not idempotent:", err)
	}
	stored, err := s.GetOriginalAccess(a.ID)
	if err != nil || stored.State != "interrupted" || stored.BytesWritten != 3 || stored.EvidenceState != "confirmed" {
		t.Fatalf("outcome:%+v %v", stored, err)
	}
	if err := s.RecordOriginalOutcome(a.ID, "interrupted", 3, raw, now.Add(24*time.Hour), now); err != nil {
		t.Fatal("exact confirmed result replay failed:", err)
	}
	stored, _ = s.GetOriginalAccess(a.ID)
	if stored.EvidenceState != "confirmed" {
		t.Fatal("exact replay downgraded confirmed evidence")
	}
	a.BytesWritten = 0
	if err := s.RecordOriginalOutcome(a.ID, "started", 0, originalRaw(t, a, "started", "started", now), now.Add(24*time.Hour), now); err == nil {
		t.Fatal("terminal result returned to started")
	}
	if err := s.MarkOriginalPermanent(a.ID); err != nil {
		t.Fatal(err)
	}
	stored, _ = s.GetOriginalAccess(a.ID)
	if stored.EvidenceState != "permanently_incomplete" {
		t.Fatal("lost permanent gap")
	}
	// Expired recovery entries become a durable permanent gap, not renewed authority.
	b, proof := originalFixture(t, s, "expired-evidence", now)
	if err := s.CreateOriginalAccess(b, proof, now.Add(time.Hour), now, lockout.Policy{}); err != nil {
		t.Fatal(err)
	}
	events, _ = s.DueOriginalEvidence(now)
	if len(events) != 1 {
		t.Fatal("missing expired recovery")
	}
	if err := s.RetryOriginalEvidence(events[0], now.Add(store.OriginalEvidenceMaxAge)); err != nil {
		t.Fatal(err)
	}
	stored, _ = s.GetOriginalAccess(b.ID)
	if stored.EvidenceState != "permanently_incomplete" {
		t.Fatal("expiry did not preserve gap")
	}
}

func TestOriginalCapacityFailureRollsBackProofAndIntent(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "capacity-source", now)
	if err := s.CreateOriginalAccess(a, proof, now.Add(time.Hour), now, lockout.Policy{}); err != nil {
		t.Fatal(err)
	}
	// Existing metadata occupies the actual table; no runtime limit is bypassed.
	if _, err := s.DB().Exec(`WITH RECURSIVE slots(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM slots WHERE n<?)
 INSERT INTO original_access(id,execution_id,user_id,person_id,session_id,security_revision,policy_version,policy_sha256,digest,purpose,kind,object_ref,actor,intent,handle_sha256,created_at,expires_at,state)
 SELECT 'metadata-slot-'||n,execution_id,user_id,person_id,session_id,security_revision,policy_version,policy_sha256,digest,purpose,kind,object_ref,actor,intent,printf('%064x',n),created_at,expires_at,state FROM original_access CROSS JOIN slots WHERE id=?`, store.MaxOriginalAccess-1, a.ID); err != nil {
		t.Fatal(err)
	}
	b, proof := originalFixture(t, s, "capacity-next", now)
	if err := s.CreateOriginalAccess(b, proof, now.Add(time.Hour), now, lockout.Policy{}); err == nil {
		t.Fatal("metadata capacity admitted another handle")
	}
	if _, err := s.GetOriginalAccess(b.ID); err == nil {
		t.Fatal("metadata refusal created an access")
	}
	if _, err := s.DB().Exec("DELETE FROM original_access WHERE id LIKE 'metadata-slot-%'"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOriginalAccess(b, proof, now.Add(time.Hour), now, lockout.Policy{}); err != nil {
		t.Fatal("capacity refusal consumed its proof:", err)
	}
	if _, err := s.DB().Exec(`WITH RECURSIVE slots(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM slots WHERE n<?)
 INSERT INTO original_read_evidence(event_id,access_id,policy_version,exact_record,min_retain_until,created_at,next_attempt_at)
 SELECT 'evidence-slot-'||n,access_id,policy_version,exact_record,min_retain_until,created_at,next_attempt_at FROM original_read_evidence CROSS JOIN slots WHERE event_id=?`, store.MaxOriginalEvidence-2, b.ID+".intent"); err != nil {
		t.Fatal(err)
	}
	c, proof := originalFixture(t, s, "capacity-evidence", now)
	if err := s.CreateOriginalAccess(c, proof, now.Add(time.Hour), now, lockout.Policy{}); err == nil {
		t.Fatal("full evidence queue admitted another handle")
	}
	if _, err := s.GetOriginalAccess(c.ID); err == nil {
		t.Fatal("queue refusal left an access without its intent")
	}
	if _, err := s.DB().Exec("DELETE FROM original_read_evidence WHERE event_id LIKE 'evidence-slot-%'"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOriginalAccess(c, proof, now.Add(time.Hour), now, lockout.Policy{}); err != nil {
		t.Fatal("queue refusal consumed its proof:", err)
	}
}

func TestOriginalExpirySweepAndHistoryPruningNeverRevivesPermit(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	a, proof := originalFixture(t, s, "sweep", now)
	authorizeOriginal(t, s, a, proof, now)
	stale, err := s.SweepOriginalAccess(now.Add(time.Minute))
	if err != nil || len(stale) != 1 || stale[0].ID != a.ID {
		t.Fatalf("expired authorized metadata not recovered: %+v %v", stale, err)
	}
	stamp := now.Add(time.Minute)
	raw := originalRaw(t, a, "expired", "result", stamp)
	if err := s.RecordOriginalOutcome(a.ID, "expired", 0, raw, now.Add(24*time.Hour), stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, lockout.Policy{}); err == nil {
		t.Fatal("expired result revived handle under clock rollback")
	}
	if _, err := s.SweepOriginalAccess(now.Add(31 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetOriginalAccess(a.ID); err != nil {
		t.Fatal("unconfirmed evidence was pruned")
	}
	if err := s.ConfirmOriginalEvidence(a.ID+".result", a.Object, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepOriginalAccess(now.Add(31 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetOriginalAccess(a.ID); err == nil {
		t.Fatal("confirmed metadata exceeded thirty-day local history")
	}
}

func TestOriginalIndependentFileWALClaimsAndOutcomes(t *testing.T) {
	s, err := store.New(filepath.Join(t.TempDir(), "concurrent-originals.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	const count = 16
	accesses := make([]model.OriginalAccess, count)
	for i := range accesses {
		a, proof := originalFixture(t, s, fmt.Sprintf("independent-%d", i), now)
		authorizeOriginal(t, s, a, proof, now)
		accesses[i] = a
	}
	begin := make(chan struct{})
	results := make(chan error, count)
	for _, a := range accesses {
		// Prebuild records on the test goroutine so worker errors return through
		// the channel and never abandon an active transaction via Fatal.
		start := originalRaw(t, a, "started", "started", now)
		a.BytesWritten = a.Object.Bytes
		result := originalRaw(t, a, "completed", "result", now)
		go func(a model.OriginalAccess, start, result []byte) {
			<-begin
			if _, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, lockout.Policy{}); err != nil {
				results <- fmt.Errorf("claim %s: %w", a.ID, err)
				return
			}
			if err := s.RecordOriginalOutcome(a.ID, "started", 0, start, now.Add(24*time.Hour), now); err != nil {
				results <- fmt.Errorf("start %s: %w", a.ID, err)
				return
			}
			if err := s.ConfirmOriginalEvidence(a.ID+".started", a.Object, now); err != nil {
				results <- fmt.Errorf("confirm start %s: %w", a.ID, err)
				return
			}
			if err := s.RecordOriginalOutcome(a.ID, "completed", a.Object.Bytes, result, now.Add(24*time.Hour), now); err != nil {
				results <- fmt.Errorf("result %s: %w", a.ID, err)
				return
			}
			results <- s.ConfirmOriginalEvidence(a.ID+".result", a.Object, now)
		}(a, start, result)
	}
	close(begin)
	for range count {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	for _, a := range accesses {
		stored, err := s.GetOriginalAccess(a.ID)
		if err != nil || stored.State != "completed" || stored.EvidenceState != "confirmed" || stored.BytesWritten != a.Object.Bytes || stored.ConsumedAt == nil {
			t.Errorf("independent valid operation lost its result: id=%s state=%s evidence=%s err=%v", a.ID, stored.State, stored.EvidenceState, err)
		}
	}
}
