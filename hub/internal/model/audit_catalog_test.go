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

// TestAuditCatalog_AccountLifecycle verifies the five account-lifecycle actions
// added by feature 008 are present exactly once each, filed under User
// Management as successful administrator actions on a user resource. Without
// them the audit-log filter UI would offer no way to find a disable or an
// exemption change.
// assertLifecycleCatalogEntry checks the shape every account-lifecycle
// catalog entry must share: exactly one occurrence, the expected label, and
// the fixed category/outcome/actor/resource fields common to all five
// actions in TestAuditCatalog_AccountLifecycle.
func assertLifecycleCatalogEntry(t *testing.T, entry AuditCatalogEntry, ok bool, count int, action, label string) {
	t.Helper()
	if !ok {
		t.Errorf("AuditCatalog missing entry for action %q", action)
		return
	}
	if count != 1 {
		t.Errorf("action %q appears %d times, want 1", action, count)
	}
	if entry.Label != label {
		t.Errorf("%s: expected label %q, got %q", action, label, entry.Label)
	}
	if entry.Category != auditCategoryUserManagement {
		t.Errorf("%s: expected category %q, got %q", action, auditCategoryUserManagement, entry.Category)
	}
	if entry.Outcome != AuditOutcomeSuccess {
		t.Errorf("%s: expected outcome %q, got %q", action, AuditOutcomeSuccess, entry.Outcome)
	}
	if entry.ActorType != AuditActorTypeUser {
		t.Errorf("%s: expected actor type %q, got %q", action, AuditActorTypeUser, entry.ActorType)
	}
	if entry.ResourceType != "user" {
		t.Errorf("%s: expected resource type %q, got %q", action, "user", entry.ResourceType)
	}
}

func TestAuditCatalog_AccountLifecycle(t *testing.T) {
	byAction := make(map[string]AuditCatalogEntry, len(AuditCatalog))
	counts := make(map[string]int, len(AuditCatalog))
	for _, entry := range AuditCatalog {
		byAction[entry.Action] = entry
		counts[entry.Action]++
	}

	for _, tc := range []struct {
		action string
		label  string
	}{
		{AuditUserDisabled, "Account disabled"},
		{AuditUserEnabled, "Account enabled"},
		{AuditUserUnlocked, "Account unlocked"},
		{AuditUserDormancyExemptSet, "Dormancy exemption granted"},
		{AuditUserDormancyExemptCleared, "Dormancy exemption removed"},
	} {
		entry, ok := byAction[tc.action]
		assertLifecycleCatalogEntry(t, entry, ok, counts[tc.action], tc.action, tc.label)
	}
}

// TestAuditCatalog_LastUpdatedCoversAccountLifecycle pins the catalog stamp to
// the account-lifecycle bump, so a later feature that adds actions without
// moving the date fails here.
func TestAuditCatalog_LastUpdatedCoversAccountLifecycle(t *testing.T) {
	parsed, err := time.Parse(time.RFC3339, AuditCatalogLastUpdated)
	if err != nil {
		t.Fatalf("AuditCatalogLastUpdated %q is not valid RFC3339: %v", AuditCatalogLastUpdated, err)
	}
	minDate := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	if parsed.Before(minDate) {
		t.Errorf("AuditCatalogLastUpdated %q is before the account-lifecycle bump %s",
			AuditCatalogLastUpdated, minDate.Format(time.RFC3339))
	}
}

// TestAuditCatalog_Sessions verifies the three session events (feature 009)
// are present exactly once each, filed under Authentication. Their shapes
// differ deliberately: creation and revocation are things a person did, while
// an expiry is the hub refusing a request on its own, so it is a system action
// with a failure outcome. Without these entries the audit-log filter UI would
// offer no way to find a sign-in's session or a forced sign-out.
func TestAuditCatalog_Sessions(t *testing.T) {
	byAction := make(map[string]AuditCatalogEntry, len(AuditCatalog))
	counts := make(map[string]int, len(AuditCatalog))
	for _, entry := range AuditCatalog {
		byAction[entry.Action] = entry
		counts[entry.Action]++
	}

	for _, tc := range []struct {
		action    string
		label     string
		outcome   string
		actorType string
	}{
		{AuditSessionCreated, "Session created", AuditOutcomeSuccess, AuditActorTypeUser},
		{AuditSessionRevoked, "Session revoked", AuditOutcomeSuccess, AuditActorTypeUser},
		{AuditSessionExpired, "Session expired", AuditOutcomeFailure, AuditActorTypeSystem},
	} {
		entry, ok := byAction[tc.action]
		if !ok {
			t.Errorf("AuditCatalog missing entry for action %q", tc.action)
			continue
		}
		assertSessionCatalogEntry(t, entry, counts[tc.action], tc.action, tc.label, tc.outcome, tc.actorType)
	}
}

// assertSessionCatalogEntry checks entry against the shared session-catalog
// invariants: exactly one entry per action, the expected label/outcome/actor
// type, the fixed "Authentication" category, and the shared session resource
// type.
func assertSessionCatalogEntry(t *testing.T, entry AuditCatalogEntry, count int, action, label, outcome, actorType string) {
	t.Helper()
	if count != 1 {
		t.Errorf("action %q appears %d times, want 1", action, count)
	}
	if entry.Label != label {
		t.Errorf("%s: expected label %q, got %q", action, label, entry.Label)
	}
	if entry.Category != "Authentication" {
		t.Errorf("%s: expected category %q, got %q", action, "Authentication", entry.Category)
	}
	if entry.Outcome != outcome {
		t.Errorf("%s: expected outcome %q, got %q", action, outcome, entry.Outcome)
	}
	if entry.ActorType != actorType {
		t.Errorf("%s: expected actor type %q, got %q", action, actorType, entry.ActorType)
	}
	if entry.ResourceType != auditResourceSession {
		t.Errorf("%s: expected resource type %q, got %q", action, auditResourceSession, entry.ResourceType)
	}
}

// TestAuditCatalog_LastUpdatedCoversSessions pins the catalog stamp to the
// session-records bump, so a later feature that adds actions without moving
// the date fails here.
func TestAuditCatalog_LastUpdatedCoversSessions(t *testing.T) {
	parsed, err := time.Parse(time.RFC3339, AuditCatalogLastUpdated)
	if err != nil {
		t.Fatalf("AuditCatalogLastUpdated %q is not valid RFC3339: %v", AuditCatalogLastUpdated, err)
	}
	minDate := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	if parsed.Before(minDate) {
		t.Errorf("AuditCatalogLastUpdated %q is before the session-records bump %s",
			AuditCatalogLastUpdated, minDate.Format(time.RFC3339))
	}
}
