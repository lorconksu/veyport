package model

import (
	"testing"
	"time"
)

// TestAuditCatalogLastUpdated_ValidRFC3339 verifies AuditCatalogLastUpdated
// parses as RFC3339 and is on or after 2026-09-05 (the account-lockout
// feature's catalog bump date).
func TestAuditCatalogLastUpdated_ValidRFC3339(t *testing.T) {
	parsed, err := time.Parse(time.RFC3339, AuditCatalogLastUpdated)
	if err != nil {
		t.Fatalf("AuditCatalogLastUpdated %q is not valid RFC3339: %v", AuditCatalogLastUpdated, err)
	}

	minDate := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	if parsed.Before(minDate) {
		t.Errorf("AuditCatalogLastUpdated %q is before %s", AuditCatalogLastUpdated, minDate.Format(time.RFC3339))
	}
}

// TestAuditCatalog_AccountLocked verifies the catalog carries the user.locked
// entry introduced by the account-lockout feature with the expected shape.
func TestAuditCatalog_AccountLocked(t *testing.T) {
	var found *AuditCatalogEntry
	for i := range AuditCatalog {
		if AuditCatalog[i].Action == AuditUserLocked {
			found = &AuditCatalog[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("AuditCatalog missing entry for action %q", AuditUserLocked)
	}
	if found.Label != "Account locked" {
		t.Errorf("expected label %q, got %q", "Account locked", found.Label)
	}
	if found.Category != "Authentication" {
		t.Errorf("expected category %q, got %q", "Authentication", found.Category)
	}
	if found.Outcome != AuditOutcomeSuccess {
		t.Errorf("expected outcome %q, got %q", AuditOutcomeSuccess, found.Outcome)
	}
	if found.ActorType != AuditActorTypeSystem {
		t.Errorf("expected actor type %q, got %q", AuditActorTypeSystem, found.ActorType)
	}
	if found.ResourceType != "user" {
		t.Errorf("expected resource type %q, got %q", "user", found.ResourceType)
	}
}

// TestAuditCatalog_EveryActionConstantHasEntry is a completeness guard: every
// Audit* action constant used elsewhere in the codebase should have a
// corresponding AuditCatalog entry so the audit log filter UI stays in sync.
// This only checks the constants this test package knows about via the
// catalog itself — it verifies no duplicate actions and that AuditUserLocked
// specifically is present exactly once.
func TestAuditCatalog_NoDuplicateActions(t *testing.T) {
	seen := make(map[string]int, len(AuditCatalog))
	for _, e := range AuditCatalog {
		seen[e.Action]++
	}
	for action, count := range seen {
		if count > 1 {
			t.Errorf("action %q appears %d times in AuditCatalog, want 1", action, count)
		}
	}
	if seen[AuditUserLocked] != 1 {
		t.Errorf("expected %q to appear exactly once in AuditCatalog, got %d", AuditUserLocked, seen[AuditUserLocked])
	}
}
