package auditingest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func (a *memoryArchive) ListKeys(_ context.Context, prefix string) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var keys []string
	for key := range a.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func policyRecord(now time.Time, version uint64, eventID string) []byte {
	e := auditrecord.Envelope{SchemaVersion: 1, EventID: eventID, EventType: auditrecord.PolicyAnchor, Actor: auditrecord.Actor{UserID: "user", PersonID: "person", Name: "owner"}, PolicyVersion: version, PolicySHA256: auditrecord.Hash([]byte(eventID)), OccurredAt: now, Details: &auditrecord.Details{InstallationID: "installation", CorrelationID: "installation", RequestID: eventID, RequestSHA256: auditrecord.Hash([]byte("approved")), ExpectedPolicyVersion: version - 1, NewPolicyVersion: version}}
	b, _ := json.Marshal(e)
	return b
}

func TestLatestAnchorAndHistoricalLookup(t *testing.T) {
	s, _, _, now := testService(t)
	ctx := context.Background()
	if _, err := s.Anchor(ctx, "installation", auditrecord.Hash([]byte("nonce"))); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing anchor not reported")
	}
	raw := policyRecord(now, 2, "change-2")
	r, err := s.Preserve(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.config.Now = func() time.Time { return now.Add(2 * time.Minute) }
	again, err := s.Lookup(ctx, "change-2", auditrecord.Hash(raw))
	if err != nil || again.Manifest.VersionID != r.Manifest.VersionID {
		t.Fatal("historical policy cannot reconcile")
	}
	if _, err = s.Lookup(ctx, "change-2", auditrecord.Hash(nil)); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong event hash reconciled")
	}
	newer := policyRecord(now.Add(2*time.Minute), 3, "change-3")
	if _, err = s.Preserve(ctx, newer, nil); err != nil {
		t.Fatal(err)
	}
	response, err := s.Anchor(ctx, "installation", auditrecord.Hash([]byte("nonce")))
	if err != nil || !strings.Contains(string(response.Record), `"policy_version":3`) {
		t.Fatal("latest anchor incorrect")
	}
	conflict := policyRecord(now, 2, "different-change")
	if _, err = s.Preserve(ctx, conflict, nil); err == nil {
		t.Fatal("anchor rewritten")
	}
	future := policyRecord(now, 5, "change-5")
	if _, err = s.Preserve(ctx, future, nil); err == nil {
		t.Fatal("anchor sequence bypassed")
	}
}

func TestHistoricalLookupDoesNotReviveAdmission(t *testing.T) {
	s, _, _, now := testService(t)
	raw, _ := testRecord(t, now, nil)
	if _, err := s.Preserve(context.Background(), raw, nil); err != nil {
		t.Fatal(err)
	}
	s.config.Now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := s.Lookup(context.Background(), "event-1", auditrecord.Hash(raw)); err == nil {
		t.Fatal("expired admission revived")
	}
}
