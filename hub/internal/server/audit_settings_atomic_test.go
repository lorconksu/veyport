package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

const auditSettingsPath = "/api/audit-logs/settings"

func putAuditSettings(t *testing.T, s *Server, token string, settings model.AuditSettings, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, auditSettingsPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	req.Header.Set(testContentType, "application/json")
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}

func TestAuditSettingsPUTIsAtomicWithAudit(t *testing.T) {
	newFixture := func(t *testing.T) (*Server, string, model.AuditSettings, model.AuditSettings) {
		t.Helper()
		s := testServer(t)
		token := registerAndGetAdminToken(t, s)
		old := s.store.GetAuditSettings()
		changed := old
		changed.RetentionDays++
		changed.Thresholds.PrivilegedActionsPerHour++
		return s, token, old, changed
	}

	t.Run("audit insert failure leaves settings unchanged and returns failure", func(t *testing.T) {
		s, token, old, changed := newFixture(t)
		_, err := s.store.DB().Exec(`CREATE TRIGGER reject_audit_settings_audit BEFORE INSERT ON audit_logs WHEN NEW.action='audit.retention_updated' BEGIN SELECT RAISE(ABORT, 'test rejects audit event'); END`)
		if err != nil {
			t.Fatal(err)
		}
		defer s.store.DB().Exec("DROP TRIGGER reject_audit_settings_audit")
		rec := putAuditSettings(t, s, token, changed, "audit-settings-audit-failure")
		assertAuditSettingsStorageFailure(t, rec, "test rejects audit event")
		if got := s.store.GetAuditSettings(); got != old {
			t.Fatalf("settings changed despite rejected audit insert: got %+v want %+v", got, old)
		}
		if count := countAuditSettingsEvents(t, s); count != 0 {
			t.Fatalf("recorded %d success events after rejected audit insert", count)
		}
	})

	t.Run("settings write failure leaves settings unchanged and emits no success event", func(t *testing.T) {
		s, token, old, changed := newFixture(t)
		_, err := s.store.DB().Exec(`CREATE TRIGGER reject_audit_settings_config BEFORE INSERT ON _config WHEN NEW.key='audit.retention_days' BEGIN SELECT RAISE(ABORT, 'test rejects settings write'); END`)
		if err != nil {
			t.Fatal(err)
		}
		defer s.store.DB().Exec("DROP TRIGGER reject_audit_settings_config")
		rec := putAuditSettings(t, s, token, changed, "audit-settings-config-failure")
		assertAuditSettingsStorageFailure(t, rec, "test rejects settings write")
		if got := s.store.GetAuditSettings(); got != old {
			t.Fatalf("settings changed despite rejected config write: got %+v want %+v", got, old)
		}
		if count := countAuditSettingsEvents(t, s); count != 0 {
			t.Fatalf("recorded %d success events after rejected config write", count)
		}
	})

	t.Run("successful update records exactly one actor-correlated before-after event", func(t *testing.T) {
		s, token, old, changed := newFixture(t)
		const requestID = "audit-settings-success"
		rec := putAuditSettings(t, s, token, changed, requestID)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if got := s.store.GetAuditSettings(); got != changed {
			t.Fatalf("settings mismatch: got %+v want %+v", got, changed)
		}
		entries := auditSettingsEvents(t, s)
		if len(entries) != 1 {
			t.Fatalf("expected exactly one success event, got %d", len(entries))
		}
		admin, err := s.store.GetUserByUsername("admin")
		if err != nil {
			t.Fatal(err)
		}
		entry := entries[0]
		if entry.UserID == nil || *entry.UserID != admin.ID {
			t.Fatalf("audit actor mismatch: %+v", entry.UserID)
		}
		if entry.CorrelationID == nil || *entry.CorrelationID != requestID {
			t.Fatalf("correlation ID mismatch: %+v", entry.CorrelationID)
		}
		var detail struct {
			Before model.AuditSettings `json:"before"`
			After  model.AuditSettings `json:"after"`
		}
		if entry.Detail == nil || json.Unmarshal([]byte(*entry.Detail), &detail) != nil || detail.Before != old || detail.After != changed {
			t.Fatalf("audit event before/after settings mismatch: %+v", entry.Detail)
		}
	})

	t.Run("nonadmin and invalid settings are blocked", func(t *testing.T) {
		s, token, old, changed := newFixture(t)
		viewerToken := createViewerAndGetToken(t, s, token)
		if rec := putAuditSettings(t, s, viewerToken, changed, "audit-settings-viewer"); rec.Code != http.StatusForbidden {
			t.Fatalf("viewer PUT: expected 403, got %d", rec.Code)
		}
		if rec := putAuditSettings(t, s, token, model.AuditSettings{}, "audit-settings-invalid"); rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid PUT: expected 400, got %d", rec.Code)
		}
		if got := s.store.GetAuditSettings(); got != old {
			t.Fatalf("blocked request changed settings: got %+v want %+v", got, old)
		}
		if count := countAuditSettingsEvents(t, s); count != 0 {
			t.Fatalf("blocked requests emitted success events: got %d want 0", count)
		}
	})

	t.Run("admin API token remains authorized", func(t *testing.T) {
		s, _, _, changed := newFixture(t)
		token := createAdminAPIToken(t, s)
		rec := putAuditSettings(t, s, token, changed, "audit-settings-api-token")
		if rec.Code != http.StatusOK {
			t.Fatalf("admin API token PUT: expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if got := s.store.GetAuditSettings(); got != changed {
			t.Fatalf("API token update did not persist settings: got %+v want %+v", got, changed)
		}
		entries := auditSettingsEvents(t, s)
		admin, err := s.store.GetUserByUsername("admin")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].UserID == nil || *entries[0].UserID != admin.ID {
			t.Fatalf("API token update audit actor mismatch: %+v", entries)
		}
	})
}

func auditSettingsEvents(t *testing.T, s *Server) []model.AuditEntry {
	t.Helper()
	action := model.AuditAuditRetentionUpdated
	entries, _, err := s.store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func countAuditSettingsEvents(t *testing.T, s *Server) int { return len(auditSettingsEvents(t, s)) }

func assertAuditSettingsStorageFailure(t *testing.T, rec *httptest.ResponseRecorder, triggerDetail string) {
	t.Helper()
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 for storage failure, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body["error"] != "audit settings update failed" {
		t.Fatalf("unexpected storage error message: %q", body["error"])
	}
	if strings.Contains(rec.Body.String(), triggerDetail) {
		t.Fatalf("storage detail leaked to API response: %s", rec.Body.String())
	}
}
