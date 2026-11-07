package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestAuditHealthReportsDefaultsDegradationAndRecovery(t *testing.T) {
	s := testServer(t)

	publicHealth := func() (int, map[string]string) {
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode public health: %v; body=%s", err, rec.Body.String())
		}
		return rec.Code, body
	}
	auditHealth := func() (int, model.AuditHealth, string) {
		rec := httptest.NewRecorder()
		// Invoke the handler directly so authentication storage reads cannot mask
		// failures in the audit-health store read itself.
		s.handleAuditHealth(rec, httptest.NewRequest(http.MethodGet, "/api/audit-logs/health", nil))
		var body model.AuditHealth
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body, rec.Body.String()
	}

	if code, body := publicHealth(); code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("default public health = (%d, %v), want 200/ok", code, body)
	}
	if code, body, _ := auditHealth(); code != http.StatusOK || body.Degraded || body.FailureCount != 0 {
		t.Fatalf("default audit health = (%d, %+v), want healthy defaults", code, body)
	}

	if _, err := s.store.DB().Exec(`CREATE TRIGGER reject_audit_health_test BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.store.LogAudit(model.AuditEntry{Action: "test.audit_health_failure"}); err == nil {
		t.Fatal("synthetic audit failure was not triggered")
	}
	if code, body := publicHealth(); code != http.StatusOK || body["status"] != "degraded" {
		t.Fatalf("degraded public health = (%d, %v), want 200/degraded", code, body)
	}
	if code, body, _ := auditHealth(); code != http.StatusOK || !body.Degraded || body.FailureCount < 1 {
		t.Fatalf("degraded audit health = (%d, %+v), want a recorded failure", code, body)
	}
	if _, err := s.store.DB().Exec(`DROP TRIGGER reject_audit_health_test`); err != nil {
		t.Fatal(err)
	}
	if err := s.store.LogAudit(model.AuditEntry{Action: "test.audit_health_recovery"}); err != nil {
		t.Fatalf("record recovery event: %v", err)
	}
	if code, body := publicHealth(); code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("recovered public health = (%d, %v), want 200/ok", code, body)
	}
	if code, body, _ := auditHealth(); code != http.StatusOK || body.Degraded || body.FailureCount < 1 || body.LastRecoveredAt == nil {
		t.Fatalf("recovered audit health = (%d, %+v), want recovery details", code, body)
	}
}

func TestAuditHealthStorageFailuresAreUnavailableAndRecoverable(t *testing.T) {
	s := testServer(t)
	if _, err := s.store.DB().Exec(`ALTER TABLE _config RENAME TO audit_health_config_saved`); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() error {
		if restored {
			return nil
		}
		_, err := s.store.DB().Exec(`ALTER TABLE audit_health_config_saved RENAME TO _config`)
		if err == nil {
			restored = true
		}
		return err
	}
	t.Cleanup(func() {
		if err := restore(); err != nil {
			t.Errorf("restore config table: %v", err)
		}
	})

	public := httptest.NewRecorder()
	s.routes().ServeHTTP(public, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if public.Code != http.StatusInternalServerError || strings.Contains(public.Body.String(), "no such table") || strings.Contains(public.Body.String(), "audit_health_config_saved") {
		t.Fatalf("public health leaked or hid config failure: status=%d body=%q", public.Code, public.Body.String())
	}
	audit := httptest.NewRecorder()
	s.handleAuditHealth(audit, httptest.NewRequest(http.MethodGet, "/api/audit-logs/health", nil))
	if audit.Code != http.StatusInternalServerError || strings.Contains(audit.Body.String(), "no such table") || strings.Contains(audit.Body.String(), "audit_health_config_saved") {
		t.Fatalf("authenticated health leaked or hid config failure: status=%d body=%q", audit.Code, audit.Body.String())
	}

	if err := restore(); err != nil {
		t.Fatalf("restore config table: %v", err)
	}
	if rec := httptest.NewRecorder(); func() int {
		s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
		return rec.Code
	}() != http.StatusOK {
		t.Fatalf("public health did not recover after config restoration: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAuditHealthClosedDatabaseNeverReportsOK(t *testing.T) {
	s := testServer(t)
	if err := s.store.DB().Close(); err != nil {
		t.Fatal(err)
	}

	public := httptest.NewRecorder()
	s.routes().ServeHTTP(public, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if public.Code == http.StatusOK {
		var body map[string]string
		_ = json.Unmarshal(public.Body.Bytes(), &body)
		if body["status"] == "ok" {
			t.Fatalf("closed database reported healthy: %s", public.Body.String())
		}
	}
	if public.Code != http.StatusInternalServerError {
		t.Fatalf("closed database public health status=%d body=%q, want generic 500", public.Code, public.Body.String())
	}

	audit := httptest.NewRecorder()
	s.handleAuditHealth(audit, httptest.NewRequest(http.MethodGet, "/api/audit-logs/health", nil))
	if audit.Code != http.StatusInternalServerError || strings.Contains(audit.Body.String(), "database is closed") {
		t.Fatalf("closed database audit health status=%d body=%q, want generic 500", audit.Code, audit.Body.String())
	}
}
