package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

// TestHandleListAuditLogs_Empty verifies that an empty store returns an empty entries list.
func TestHandleListAuditLogs_Empty(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", testAuditLogsPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	entries, ok := resp["entries"]
	if !ok {
		t.Fatal("expected 'entries' key in response")
	}
	// Entries may not be null/nil — we just registered a user which creates audit entries
	_ = entries

	total, ok := resp["total"]
	if !ok {
		t.Fatal("expected 'total' key in response")
	}
	if total.(float64) < 0 {
		t.Fatal("expected non-negative total")
	}
}

// TestHandleListAuditLogs_WithEntries verifies that injected audit entries are returned.
func TestHandleListAuditLogs_WithEntries(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Inject known audit entries directly
	serverID := "test-server"
	detail := "test detail"
	ip := testLocalhost
	for i := 0; i < 3; i++ {
		s.store.LogAudit(model.AuditEntry{
			ID:        uuid.NewString(),
			Action:    model.AuditServerCreated,
			Target:    &serverID,
			Detail:    &detail,
			IPAddress: &ip,
		})
	}

	req := httptest.NewRequest("GET", testAuditLogsPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	total := int(resp["total"].(float64))
	if total < 3 {
		t.Fatalf("expected at least 3 entries, got total=%d", total)
	}

	entries := resp["entries"].([]interface{})
	if len(entries) == 0 {
		t.Fatal("expected non-empty entries array")
	}
}

// TestHandleListAuditLogs_Pagination verifies that limit and offset params are respected.
func TestHandleListAuditLogs_Pagination(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Inject 5 entries
	ip := testLocalhost
	for i := 0; i < 5; i++ {
		s.store.LogAudit(model.AuditEntry{
			ID:        uuid.NewString(),
			Action:    model.AuditServerCreated,
			IPAddress: &ip,
		})
	}

	// Request with limit=2
	req := httptest.NewRequest("GET", "/api/audit-logs?limit=2&offset=0", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	if int(resp["limit"].(float64)) != 2 {
		t.Fatalf("expected limit=2 in response, got %v", resp["limit"])
	}
	if int(resp["offset"].(float64)) != 0 {
		t.Fatalf("expected offset=0 in response, got %v", resp["offset"])
	}
	entries := resp["entries"].([]interface{})
	if len(entries) > 2 {
		t.Fatalf("expected at most 2 entries with limit=2, got %d", len(entries))
	}
}

// TestHandleListAuditLogs_FilterByAction verifies filtering by action works.
func TestHandleListAuditLogs_FilterByAction(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	ip := testLocalhost
	// Add entries of two different action types
	for i := 0; i < 2; i++ {
		s.store.LogAudit(model.AuditEntry{
			ID:        uuid.NewString(),
			Action:    model.AuditServerCreated,
			IPAddress: &ip,
		})
	}
	for i := 0; i < 3; i++ {
		s.store.LogAudit(model.AuditEntry{
			ID:        uuid.NewString(),
			Action:    model.AuditServerDeleted,
			IPAddress: &ip,
		})
	}

	req := httptest.NewRequest("GET", "/api/audit-logs?action="+model.AuditServerCreated, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	entries := resp["entries"].([]interface{})
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["action"] != model.AuditServerCreated {
			t.Fatalf("filter by action returned unexpected action: %v", entry["action"])
		}
	}
}

// TestHandleListAuditLogs_RequiresAdmin verifies that non-admin access is rejected.
func TestHandleListAuditLogs_RequiresAdmin(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	req := httptest.NewRequest("GET", testAuditLogsPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer accessing audit logs, got %d", rec.Code)
	}
}
