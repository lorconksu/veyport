package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

func auditCloseoutServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	if err := s.store.CreateUser(&model.User{ID: "reviewer", Username: "reviewer", Email: "reviewer@test", PasswordHash: "fixture", Role: model.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	return s
}
func auditCloseoutRequest(handler http.HandlerFunc, body, id string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/audit-logs?action=user.login&outcome=success&actor_type=user&correlation_id=source&resource_type=user&user_id=reviewer&from=2000&to=2099&limit=20&offset=1", strings.NewReader(body))
	r.SetPathValue("id", id)
	ctx := context.WithValue(r.Context(), ctxUserID, "reviewer")
	ctx = context.WithValue(ctx, ctxRequestID, "audit-closeout")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}
func TestAuditWorkflowHTTPPersistsArtifactsAndCorrelatedAudits(t *testing.T) {
	s := auditCloseoutServer(t)
	for _, step := range []struct {
		handler http.HandlerFunc
		body    string
		status  int
	}{
		{s.handleCreateAuditReview, `{"filters_json":"{}","notes":"reviewed","from":"2000","to":"2099"}`, 201},
		{s.handleCreateAuditSavedFilter, `{"name":"Saved","filters_json":"{}"}`, 201},
		{s.handleCreateAuditFlag, `{"note":"investigate"}`, 201},
	} {
		w := auditCloseoutRequest(step.handler, step.body, "")
		if w.Code != step.status {
			t.Fatalf("create: %d %s", w.Code, w.Body.String())
		}
	}
	filters, err := s.store.ListAuditSavedFilters()
	if err != nil || len(filters) != 1 {
		t.Fatalf("saved filters: %+v %v", filters, err)
	}
	if w := auditCloseoutRequest(s.handleDeleteAuditSavedFilter, "", filters[0].ID); w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	for _, handler := range []http.HandlerFunc{s.handleListAuditReviews, s.handleListAuditSavedFilters, s.handleListAuditFlags, s.handleListAuditExports, s.handleAuditCatalog, s.handleAuditHealth, s.handleGetAuditSettings, s.handleListAuditUsers, s.handleAuditDetections, s.handleExportAuditLogs, s.handleRunAuditRetention} {
		if w := auditCloseoutRequest(handler, "", ""); w.Code != 200 {
			t.Fatalf("read or run: %d %s", w.Code, w.Body.String())
		}
	}
	correlation := "audit-closeout"
	entries, total, err := s.store.ListAuditLogs(model.AuditFilter{CorrelationID: &correlation})
	if err != nil || total != 6 {
		t.Fatalf("audit count: %d %+v %v", total, entries, err)
	}
	for _, entry := range entries {
		if entry.UserID == nil || *entry.UserID != "reviewer" || entry.Outcome != model.AuditOutcomeSuccess {
			t.Fatalf("lost actor or success: %+v", entry)
		}
	}
}

func TestAuditWorkflowHTTPRejectsMalformedInput(t *testing.T) {
	s := auditCloseoutServer(t)
	for _, tc := range []struct {
		name     string
		handler  http.HandlerFunc
		body, id string
		status   int
	}{
		{"review-json", s.handleCreateAuditReview, "{", "", 400}, {"review-filter", s.handleCreateAuditReview, `{"filters_json":"{"}`, "", 400},
		{"filter-json", s.handleCreateAuditSavedFilter, "{", "", 400}, {"filter-name", s.handleCreateAuditSavedFilter, `{"name":" ","filters_json":"{}"}`, "", 400}, {"filter-filter", s.handleCreateAuditSavedFilter, `{"name":"n","filters_json":"{"}`, "", 400},
		{"flag-json", s.handleCreateAuditFlag, "{", "", 400}, {"flag-note", s.handleCreateAuditFlag, `{"note":" "}`, "", 400}, {"flag-filter", s.handleCreateAuditFlag, `{"note":"n","filters_json":"{"}`, "", 400},
		{"delete-id", s.handleDeleteAuditSavedFilter, "", "", 400}, {"delete-missing", s.handleDeleteAuditSavedFilter, "", "missing", 404},
		{"oversized", s.handleCreateAuditReview, `{"filters_json":"` + strings.Repeat(" ", 16385) + `"}`, "", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := auditCloseoutRequest(tc.handler, tc.body, tc.id)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
	_, total, err := s.store.ListAuditLogs(model.AuditFilter{})
	if err != nil || total != 0 {
		t.Fatalf("rejected request emitted success: %d %v", total, err)
	}
}

func TestAuditWorkflowHTTPStorageFailuresReturnFailure(t *testing.T) {
	for _, tc := range []struct {
		name, table string
		handler     func(*Server) http.HandlerFunc
		body        string
	}{
		{"list-logs", "audit_logs", func(s *Server) http.HandlerFunc { return s.handleListAuditLogs }, ""},
		{"export", "audit_logs", func(s *Server) http.HandlerFunc { return s.handleExportAuditLogs }, ""},
		{"export-history", "audit_logs", func(s *Server) http.HandlerFunc { return s.handleListAuditExports }, ""},
		{"list-reviews", "audit_reviews", func(s *Server) http.HandlerFunc { return s.handleListAuditReviews }, ""},
		{"create-review", "audit_reviews", func(s *Server) http.HandlerFunc { return s.handleCreateAuditReview }, `{"filters_json":"{}","notes":"n"}`},
		{"list-filters", "audit_saved_filters", func(s *Server) http.HandlerFunc { return s.handleListAuditSavedFilters }, ""},
		{"create-filter", "audit_saved_filters", func(s *Server) http.HandlerFunc { return s.handleCreateAuditSavedFilter }, `{"name":"n","filters_json":"{}"}`},
		{"list-flags", "audit_flags", func(s *Server) http.HandlerFunc { return s.handleListAuditFlags }, ""},
		{"create-flag", "audit_flags", func(s *Server) http.HandlerFunc { return s.handleCreateAuditFlag }, `{"note":"n"}`},
		{"users", "users", func(s *Server) http.HandlerFunc { return s.handleListAuditUsers }, ""},
		{"health", "_config", func(s *Server) http.HandlerFunc { return s.handleAuditHealth }, ""},
		{"public-health", "_config", func(s *Server) http.HandlerFunc { return s.handleHealth }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := auditCloseoutServer(t)
			if _, err := s.store.DB().Exec("ALTER TABLE " + tc.table + " RENAME TO failed_storage"); err != nil {
				t.Fatal(err)
			}
			w := auditCloseoutRequest(tc.handler(s), tc.body, "")
			if w.Code != 500 {
				t.Fatalf("storage failure status %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAuditRetentionHTTPFailureRecordsFailureWithoutDeletion(t *testing.T) {
	s := auditCloseoutServer(t)
	if _, err := s.store.DB().Exec("INSERT INTO audit_logs(id,action,created_at) VALUES('old','user.login','2000-01-01 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.DB().Exec(`CREATE TRIGGER reject_retention BEFORE DELETE ON audit_logs BEGIN SELECT RAISE(ABORT,'retention failure'); END`); err != nil {
		t.Fatal(err)
	}
	w := auditCloseoutRequest(s.handleRunAuditRetention, "", "")
	if w.Code != 500 {
		t.Fatalf("retention status %d: %s", w.Code, w.Body.String())
	}
	action := model.AuditAuditRetentionExecuted
	entries, n, err := s.store.ListAuditLogs(model.AuditFilter{Action: &action})
	if err != nil || n != 1 || entries[0].Outcome != model.AuditOutcomeFailure {
		t.Fatalf("lost failure record: %+v %v", entries, err)
	}
	var old int
	if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM audit_logs WHERE id='old'").Scan(&old); err != nil || old != 1 {
		t.Fatalf("failed retention lost data: %d %v", old, err)
	}
}

func TestAuditDetectionsThresholdsAndReviewAging(t *testing.T) {
	s := auditCloseoutServer(t)
	settings := s.store.GetAuditSettings()
	settings.Thresholds = model.AuditThresholds{LoginFailuresPerHour: 1, RegistrationFailuresPerHour: 1, PrivilegedActionsPerHour: 1}
	if err := s.store.UpdateAuditSettings(settings); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{model.AuditUserLoginFailed, model.AuditServerRegistrationFailed, model.AuditUserRoleUpdated} {
		if err := s.store.LogAudit(model.AuditEntry{Action: action}); err != nil {
			t.Fatal(err)
		}
	}
	w := auditCloseoutRequest(s.handleAuditDetections, "", "")
	var response model.AuditDetectionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Detections) != 4 {
		t.Fatalf("threshold detections: %+v %v", response, err)
	}
	review, err := s.store.CreateAuditReview("reviewer", "{}", "reviewed", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.reviewOverdueDetection(settings); got.ID != "" {
		t.Fatalf("fresh review overdue: %+v", got)
	}
	for _, stamp := range []string{time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339), "2000-01-01 00:00:00"} {
		if _, err := s.store.DB().Exec("UPDATE audit_reviews SET completed_at=? WHERE id=?", stamp, review.ID); err != nil {
			t.Fatal(err)
		}
		if got := s.reviewOverdueDetection(settings); got.ID != "review-overdue" {
			t.Fatalf("old review not detected: %+v", got)
		}
	}
	if _, err := s.store.DB().Exec("UPDATE audit_reviews SET completed_at='corrupt'"); err != nil {
		t.Fatal(err)
	}
	if got := s.reviewOverdueDetection(settings); got.ID != "" {
		t.Fatalf("invalid review time accepted: %+v", got)
	}
}

func TestAuditRequestHelperPreservesExplicitMetadataAndSignalsStorageFailure(t *testing.T) {
	s := auditCloseoutServer(t)
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxRequestID, "replacement"))
	correlation := "original"
	s.auditLogRequest(r, model.AuditEntry{ID: "explicit", Action: model.AuditUserLogin, CorrelationID: &correlation})
	entries, total, err := s.store.ListAuditLogs(model.AuditFilter{})
	if err != nil || total != 1 || entries[0].ID != "explicit" || *entries[0].CorrelationID != "original" {
		t.Fatalf("overwrote metadata: %+v %v", entries, err)
	}
	s.auditLogRequest(httptest.NewRequest("GET", "/", nil), model.AuditEntry{ID: "explicit", Action: model.AuditUserLogin})
	h, err := s.store.GetAuditHealth()
	if err != nil || !h.Degraded || h.FailureCount != 1 {
		t.Fatalf("helper swallowed health signal: %+v %v", h, err)
	}
}
