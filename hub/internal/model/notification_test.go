package model

import "testing"

// TestAllNotifyEvents_AccountLocked verifies the account-lockout feature's
// notification event type is registered with the expected label, category,
// and default-on state.
func TestAllNotifyEvents_AccountLocked(t *testing.T) {
	var found *NotifyEventDef
	for i := range AllNotifyEvents {
		if AllNotifyEvents[i].Type == NotifyAccountLocked {
			found = &AllNotifyEvents[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("AllNotifyEvents missing entry for type %q", NotifyAccountLocked)
	}
	if found.Label != "Account locked after repeated failures" {
		t.Errorf("expected label %q, got %q", "Account locked after repeated failures", found.Label)
	}
	if found.Category != "Security" {
		t.Errorf("expected category %q, got %q", "Security", found.Category)
	}
	if !found.DefaultOn {
		t.Error("expected DefaultOn to be true")
	}
}

// TestNotifyAccountLocked_Value pins the exact event-type string so a typo'd
// constant renamed elsewhere doesn't silently drift the DB/preferences key.
func TestNotifyAccountLocked_Value(t *testing.T) {
	if NotifyAccountLocked != "security.account_locked" {
		t.Errorf("expected NotifyAccountLocked = %q, got %q", "security.account_locked", NotifyAccountLocked)
	}
}
