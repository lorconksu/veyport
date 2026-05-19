package store_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

const testGetRecipientsFmt = "get recipients: %v"

func createTestUser(t *testing.T, st interface {
	CreateUser(*model.User) error
}, id string) {
	t.Helper()
	err := st.CreateUser(&model.User{
		ID:           id,
		Username:     id,
		Email:        id + "@test.com",
		PasswordHash: "$2a$12$dummy",
		Role:         model.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("create test user %s: %v", id, err)
	}
}

func TestGetNotificationPreferences_Defaults(t *testing.T) {
	s := testStore(t)
	createTestUser(t, s, "u1")

	prefs, err := s.GetNotificationPreferences("u1")
	if err != nil {
		t.Fatalf("get preferences: %v", err)
	}

	if len(prefs) != len(model.AllNotifyEvents) {
		t.Fatalf("expected %d preferences, got %d", len(model.AllNotifyEvents), len(prefs))
	}

	// Build a map of type -> pref for easy lookup
	prefMap := make(map[string]model.NotificationPreference)
	for _, p := range prefs {
		prefMap[p.EventType] = p
	}

	// Verify defaults match AllNotifyEvents
	for _, def := range model.AllNotifyEvents {
		p, ok := prefMap[def.Type]
		if !ok {
			t.Fatalf("missing preference for event type %s", def.Type)
		}
		if p.Enabled != def.DefaultOn {
			t.Errorf("event %s: expected enabled=%v (default), got %v", def.Type, def.DefaultOn, p.Enabled)
		}
		if p.Label != def.Label {
			t.Errorf("event %s: expected label %q, got %q", def.Type, def.Label, p.Label)
		}
		if p.Category != def.Category {
			t.Errorf("event %s: expected category %q, got %q", def.Type, def.Category, p.Category)
		}
	}
}

func TestSetNotificationPreference_OverridesDefault(t *testing.T) {
	s := testStore(t)
	createTestUser(t, s, "u1")

	// agent.offline is default-on; disable it
	err := s.SetNotificationPreference("u1", model.NotifyAgentOffline, false)
	if err != nil {
		t.Fatalf("set preference: %v", err)
	}

	prefs, err := s.GetNotificationPreferences("u1")
	if err != nil {
		t.Fatalf("get preferences: %v", err)
	}

	for _, p := range prefs {
		if p.EventType == model.NotifyAgentOffline {
			if p.Enabled {
				t.Fatalf("expected agent.offline to be disabled after override")
			}
			return
		}
	}
	t.Fatal("agent.offline preference not found")
}

func TestSetNotificationPreference_Upsert(t *testing.T) {
	s := testStore(t)
	createTestUser(t, s, "u1")

	// Set twice — second call should overwrite
	if err := s.SetNotificationPreference("u1", model.NotifyAgentOffline, false); err != nil {
		t.Fatalf("first set: %v", err)
	}
	if err := s.SetNotificationPreference("u1", model.NotifyAgentOffline, true); err != nil {
		t.Fatalf("second set: %v", err)
	}

	prefs, _ := s.GetNotificationPreferences("u1")
	for _, p := range prefs {
		if p.EventType == model.NotifyAgentOffline && !p.Enabled {
			t.Fatal("expected agent.offline to be re-enabled after upsert")
		}
	}
}

func TestGetEnabledRecipients_DefaultOn(t *testing.T) {
	s := testStore(t)
	createTestUser(t, s, "u1")
	createTestUser(t, s, "u2")
	createTestUser(t, s, "u3")

	// agent.offline is default-on — u2 disables it
	s.SetNotificationPreference("u2", model.NotifyAgentOffline, false)

	recipients, err := s.GetEnabledRecipients(model.NotifyAgentOffline)
	if err != nil {
		t.Fatalf(testGetRecipientsFmt, err)
	}

	// Should return u1 and u3 (not u2)
	if len(recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(recipients))
	}
	for _, u := range recipients {
		if u.ID == "u2" {
			t.Fatal("u2 should be excluded (disabled agent.offline)")
		}
	}
}

func TestGetEnabledRecipients_DefaultOff(t *testing.T) {
	s := testStore(t)
	createTestUser(t, s, "u1")
	createTestUser(t, s, "u2")
	createTestUser(t, s, "u3")

	// agent.online is default-off — only u2 enables it
	s.SetNotificationPreference("u2", model.NotifyAgentOnline, true)

	recipients, err := s.GetEnabledRecipients(model.NotifyAgentOnline)
	if err != nil {
		t.Fatalf(testGetRecipientsFmt, err)
	}

	// Should return only u2
	if len(recipients) != 1 {
		t.Fatalf("expected 1 recipient, got %d", len(recipients))
	}
	if recipients[0].ID != "u2" {
		t.Fatalf("expected u2 as the only recipient, got %s", recipients[0].ID)
	}
}

func TestGetEnabledRecipients_DefaultOff_NoOverrides(t *testing.T) {
	s := testStore(t)
	createTestUser(t, s, "u1")
	createTestUser(t, s, "u2")

	// agent.online is default-off, no one has enabled it
	recipients, err := s.GetEnabledRecipients(model.NotifyAgentOnline)
	if err != nil {
		t.Fatalf(testGetRecipientsFmt, err)
	}
	if len(recipients) != 0 {
		t.Fatalf("expected 0 recipients, got %d", len(recipients))
	}
}

func TestLogNotification_Roundtrip(t *testing.T) {
	s := testStore(t)
	createTestUser(t, s, "u1")

	errMsg := "connection refused"
	err := s.LogNotification("log-id-1", "u1", model.NotifyAgentOffline, "Agent went offline", "failed", &errMsg)
	if err != nil {
		t.Fatalf("log notification: %v", err)
	}

	entries, total, err := s.ListNotificationLog(10, 0)
	if err != nil {
		t.Fatalf("list notification log: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected total=1, got %d", total)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.ID != "log-id-1" {
		t.Errorf("expected id 'log-id-1', got %s", e.ID)
	}
	if e.UserID != "u1" {
		t.Errorf("expected user_id 'u1', got %s", e.UserID)
	}
	if e.Username != "u1" {
		t.Errorf("expected username 'u1', got %s", e.Username)
	}
	if e.EventType != model.NotifyAgentOffline {
		t.Errorf("expected event_type %s, got %s", model.NotifyAgentOffline, e.EventType)
	}
	if e.Subject != "Agent went offline" {
		t.Errorf("expected subject 'Agent went offline', got %s", e.Subject)
	}
	if e.Status != "failed" {
		t.Errorf("expected status 'failed', got %s", e.Status)
	}
	if e.Error == nil || *e.Error != "connection refused" {
		t.Errorf("expected error 'connection refused', got %v", e.Error)
	}
}

func TestLogNotification_NilError(t *testing.T) {
	s := testStore(t)
	createTestUser(t, s, "u1")

	err := s.LogNotification("log-id-2", "u1", model.NotifyAgentOffline, "Agent offline", "sent", nil)
	if err != nil {
		t.Fatalf("log notification: %v", err)
	}

	entries, _, err := s.ListNotificationLog(10, 0)
	if err != nil {
		t.Fatalf("list log: %v", err)
	}
	if entries[0].Error != nil {
		t.Fatalf("expected nil error field, got %v", entries[0].Error)
	}
}

func TestListNotificationLog_Pagination(t *testing.T) {
	s := testStore(t)
	createTestUser(t, s, "u1")

	// Insert 5 entries
	for i := 0; i < 5; i++ {
		id := "log-id-" + string(rune('a'+i))
		s.LogNotification(id, "u1", model.NotifyAgentOffline, "subject", "sent", nil)
	}

	// Page 1: limit 2, offset 0
	page1, total, err := s.ListNotificationLog(2, 0)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if total != 5 {
		t.Fatalf("expected total=5, got %d", total)
	}
	if len(page1) != 2 {
		t.Fatalf("expected 2 entries on page 1, got %d", len(page1))
	}

	// Page 2: limit 2, offset 2
	page2, total2, err := s.ListNotificationLog(2, 2)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if total2 != 5 {
		t.Fatalf("expected total=5 on page 2, got %d", total2)
	}
	if len(page2) != 2 {
		t.Fatalf("expected 2 entries on page 2, got %d", len(page2))
	}

	// Page 3: limit 2, offset 4
	page3, _, err := s.ListNotificationLog(2, 4)
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if len(page3) != 1 {
		t.Fatalf("expected 1 entry on page 3, got %d", len(page3))
	}
}

func TestListNotificationLog_Empty(t *testing.T) {
	s := testStore(t)

	entries, total, err := s.ListNotificationLog(10, 0)
	if err != nil {
		t.Fatalf("list empty log: %v", err)
	}
	if total != 0 {
		t.Fatalf("expected total=0, got %d", total)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}
