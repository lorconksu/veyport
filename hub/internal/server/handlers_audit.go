package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

const errAuditFilterJSONInvalid = "filters_json must be valid JSON and at most 16KB"

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health, err := s.store.GetAuditHealth()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load health state")
		return
	}
	status := "ok"
	if health.Degraded {
		status = "degraded"
	}
	// Only expose status to unauthenticated callers; detailed audit health
	// is available via the authenticated /api/audit-logs/health endpoint.
	respondJSON(w, http.StatusOK, map[string]string{
		"status": status,
	})
}

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	filter := auditFilterFromRequest(r)
	entries, total, err := s.store.ListAuditLogs(filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}

	respondJSON(w, http.StatusOK, model.AuditListResponse{
		Entries: entries,
		Total:   total,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
	})
}

func (s *Server) handleAuditCatalog(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, model.AuditCatalogResponse{
		Entries:       model.AuditCatalog,
		LastUpdatedAt: model.AuditCatalogLastUpdated,
	})
}

func (s *Server) handleAuditHealth(w http.ResponseWriter, r *http.Request) {
	health, err := s.store.GetAuditHealth()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load audit health")
		return
	}
	respondJSON(w, http.StatusOK, health)
}

func (s *Server) handleGetAuditSettings(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.store.GetAuditSettings())
}

func (s *Server) handleUpdateAuditSettings(w http.ResponseWriter, r *http.Request) {
	var settings model.AuditSettings
	if err := decodeJSON(r, &settings); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if err := store.ValidateAuditSettings(settings); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdateAuditSettings(settings); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update audit settings")
		return
	}

	userID := UserIDFromContext(r.Context())
	detail := fmt.Sprintf(
		"retention_days=%d review_reminder_days=%d password_history_count=%d temporary_password_ttl_hours=%d login_failures_per_hour=%d registration_failures_per_hour=%d privileged_actions_per_hour=%d",
		settings.RetentionDays, settings.ReviewReminderDays, settings.PasswordHistoryCount, settings.TemporaryPasswordTTLHours,
		settings.Thresholds.LoginFailuresPerHour, settings.Thresholds.RegistrationFailuresPerHour,
		settings.Thresholds.PrivilegedActionsPerHour,
	)
	resourceType := "audit"
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &userID,
		Action:       model.AuditAuditRetentionUpdated,
		Detail:       &detail,
		ResourceType: &resourceType,
	})

	respondJSON(w, http.StatusOK, settings)
}

func (s *Server) handleExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	filter := auditFilterFromRequest(r)
	filter.Limit = 0
	filter.Offset = 0

	entries, total, err := s.store.ListAuditLogs(filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to export audit logs")
		return
	}

	manifest := model.AuditManifest{
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		GeneratedBy:    UserIDFromContext(r.Context()),
		RecordCount:    total,
		AppliedFilters: auditFilterSummary(filter),
	}
	if len(entries) > 0 {
		first := entries[len(entries)-1].CreatedAt.UTC().Format(time.RFC3339)
		last := entries[0].CreatedAt.UTC().Format(time.RFC3339)
		manifest.FirstCreatedAt = first
		manifest.LastCreatedAt = last
	}

	resourceType := "audit"
	detail := fmt.Sprintf("record_count=%d %s", total, manifest.AppliedFilters)
	userID := UserIDFromContext(r.Context())
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &userID,
		Action:       model.AuditAuditExported,
		Detail:       &detail,
		ResourceType: &resourceType,
	})

	respondJSON(w, http.StatusOK, model.AuditExportResponse{
		Manifest: manifest,
		Entries:  entries,
	})
}

func (s *Server) handleListAuditExports(w http.ResponseWriter, r *http.Request) {
	action := model.AuditAuditExported
	filter := model.AuditFilter{
		Action: &action,
		Limit:  20,
	}
	entries, _, err := s.store.ListAuditLogs(filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list audit exports")
		return
	}
	respondJSON(w, http.StatusOK, model.AuditExportHistoryResponse{Entries: entries})
}

func (s *Server) handleRunAuditRetention(w http.ResponseWriter, r *http.Request) {
	settings := s.store.GetAuditSettings()
	cutoff := time.Now().UTC().Add(-time.Duration(settings.RetentionDays) * 24 * time.Hour).Format(time.RFC3339)
	deletedCount, err := s.store.DeleteAuditLogsBefore(cutoff)
	if err != nil {
		detail := fmt.Sprintf("cutoff=%s error=%s", cutoff, err.Error())
		resourceType := "audit"
		userID := UserIDFromContext(r.Context())
		s.auditLogRequest(r, model.AuditEntry{
			UserID:       &userID,
			Action:       model.AuditAuditRetentionExecuted,
			Detail:       &detail,
			Outcome:      model.AuditOutcomeFailure,
			ResourceType: &resourceType,
		})
		respondError(w, http.StatusInternalServerError, "failed to execute audit retention")
		return
	}
	detail := fmt.Sprintf("cutoff=%s deleted_count=%d", cutoff, deletedCount)
	resourceType := "audit"
	userID := UserIDFromContext(r.Context())
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &userID,
		Action:       model.AuditAuditRetentionExecuted,
		Detail:       &detail,
		ResourceType: &resourceType,
	})
	respondJSON(w, http.StatusOK, model.AuditRetentionRunResponse{
		DeletedCount: deletedCount,
		Cutoff:       cutoff,
	})
}

func (s *Server) handleListAuditReviews(w http.ResponseWriter, r *http.Request) {
	limit, _ := parsePagination(r.URL.Query(), 20)
	reviews, err := s.store.ListAuditReviews(limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list audit reviews")
		return
	}
	respondJSON(w, http.StatusOK, model.AuditReviewsResponse{Reviews: reviews})
}

func (s *Server) handleCreateAuditReview(w http.ResponseWriter, r *http.Request) {
	var req model.CreateAuditReviewRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if err := validateJSONBlob(req.FiltersJSON, 16<<10); err != nil {
		respondError(w, http.StatusBadRequest, errAuditFilterJSONInvalid)
		return
	}
	reviewerID := UserIDFromContext(r.Context())
	review, err := s.store.CreateAuditReview(reviewerID, req.FiltersJSON, req.Notes, req.From, req.To)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create audit review")
		return
	}
	resourceType := "audit"
	detail := fmt.Sprintf("review_id=%s", review.ID)
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &reviewerID,
		Action:       model.AuditAuditReviewCompleted,
		Detail:       &detail,
		ResourceType: &resourceType,
	})
	respondJSON(w, http.StatusCreated, review)
}

func (s *Server) handleListAuditSavedFilters(w http.ResponseWriter, r *http.Request) {
	filters, err := s.store.ListAuditSavedFilters()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list audit filters")
		return
	}
	respondJSON(w, http.StatusOK, model.AuditSavedFiltersResponse{Filters: filters})
}

func (s *Server) handleCreateAuditSavedFilter(w http.ResponseWriter, r *http.Request) {
	var req model.CreateAuditSavedFilterRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := validateJSONBlob(req.FiltersJSON, 16<<10); err != nil {
		respondError(w, http.StatusBadRequest, errAuditFilterJSONInvalid)
		return
	}
	userID := UserIDFromContext(r.Context())
	filter, err := s.store.CreateAuditSavedFilter(userID, req.Name, req.FiltersJSON)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to save audit filter")
		return
	}
	resourceType := "audit"
	detail := fmt.Sprintf("filter_id=%s name=%s", filter.ID, filter.Name)
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &userID,
		Action:       model.AuditAuditFilterSaved,
		Detail:       &detail,
		ResourceType: &resourceType,
	})
	respondJSON(w, http.StatusCreated, filter)
}

func (s *Server) handleDeleteAuditSavedFilter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing filter id")
		return
	}
	if err := s.store.DeleteAuditSavedFilter(id); err != nil {
		respondError(w, http.StatusNotFound, "audit filter not found")
		return
	}
	userID := UserIDFromContext(r.Context())
	resourceType := "audit"
	detail := "filter_id=" + id
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &userID,
		Action:       model.AuditAuditFilterDeleted,
		Detail:       &detail,
		ResourceType: &resourceType,
	})
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListAuditFlags(w http.ResponseWriter, r *http.Request) {
	flags, err := s.store.ListAuditFlags(20)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list audit flags")
		return
	}
	respondJSON(w, http.StatusOK, model.AuditFlagsResponse{Flags: flags})
}

func (s *Server) handleCreateAuditFlag(w http.ResponseWriter, r *http.Request) {
	var req model.CreateAuditFlagRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if strings.TrimSpace(req.Note) == "" {
		respondError(w, http.StatusBadRequest, "note is required")
		return
	}
	if req.FiltersJSON == "" {
		req.FiltersJSON = "{}"
	}
	if err := validateJSONBlob(req.FiltersJSON, 16<<10); err != nil {
		respondError(w, http.StatusBadRequest, errAuditFilterJSONInvalid)
		return
	}
	userID := UserIDFromContext(r.Context())
	flag, err := s.store.CreateAuditFlag(userID, req.EntryID, req.FiltersJSON, req.Note)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create audit flag")
		return
	}
	resourceType := "audit"
	detail := fmt.Sprintf("flag_id=%s entry_id=%v", flag.ID, flag.EntryID)
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &userID,
		Action:       model.AuditAuditFlagCreated,
		Detail:       &detail,
		ResourceType: &resourceType,
	})
	respondJSON(w, http.StatusCreated, flag)
}

func (s *Server) handleAuditDetections(w http.ResponseWriter, r *http.Request) {
	settings := s.store.GetAuditSettings()
	from := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	detections := []model.AuditDetection{
		s.loginFailureDetection(from, settings),
		s.registrationFailureDetection(from, settings),
		s.privilegedActionDetection(from, settings),
		s.reviewOverdueDetection(settings),
	}
	respondJSON(w, http.StatusOK, model.AuditDetectionsResponse{Detections: compactDetections(detections)})
}

func compactDetections(detections []model.AuditDetection) []model.AuditDetection {
	out := make([]model.AuditDetection, 0, len(detections))
	for _, detection := range detections {
		if detection.ID != "" {
			out = append(out, detection)
		}
	}
	return out
}

func (s *Server) loginFailureDetection(from string, settings model.AuditSettings) model.AuditDetection {
	total, err := s.auditCountSince(model.AuditFilter{
		Action: stringPtr(model.AuditUserLoginFailed),
		From:   stringPtr(from),
		Limit:  5,
	})
	if err != nil || total < settings.Thresholds.LoginFailuresPerHour {
		return model.AuditDetection{}
	}
	return model.AuditDetection{
		ID:          "login-failures",
		Type:        "login_failures",
		Severity:    "medium",
		Title:       "Repeated failed logins",
		Description: fmt.Sprintf("%d failed logins in the last hour (threshold %d)", total, settings.Thresholds.LoginFailuresPerHour),
	}
}

func (s *Server) registrationFailureDetection(from string, settings model.AuditSettings) model.AuditDetection {
	total, err := s.auditCountSince(model.AuditFilter{
		Action: stringPtr(model.AuditServerRegistrationFailed),
		From:   stringPtr(from),
		Limit:  5,
	})
	if err != nil || total < settings.Thresholds.RegistrationFailuresPerHour {
		return model.AuditDetection{}
	}
	return model.AuditDetection{
		ID:          "registration-failures",
		Type:        "registration_failures",
		Severity:    "high",
		Title:       "Repeated failed agent registrations",
		Description: fmt.Sprintf("%d failed registration attempts in the last hour (threshold %d)", total, settings.Thresholds.RegistrationFailuresPerHour),
	}
}

func (s *Server) privilegedActionDetection(from string, settings model.AuditSettings) model.AuditDetection {
	actions := []string{
		model.AuditUserRoleUpdated,
		model.AuditUserDeleted,
		model.AuditServerDeleted,
		model.AuditServerBatchDeleted,
		model.AuditAuditExported,
	}
	total := 0
	for _, action := range actions {
		actionTotal, err := s.auditCountSince(model.AuditFilter{
			Action: stringPtr(action),
			From:   stringPtr(from),
			Limit:  5,
		})
		if err != nil {
			return model.AuditDetection{}
		}
		total += actionTotal
	}
	if total < settings.Thresholds.PrivilegedActionsPerHour {
		return model.AuditDetection{}
	}
	return model.AuditDetection{
		ID:          "privileged-action-burst",
		Type:        "privileged_action_burst",
		Severity:    "medium",
		Title:       "Burst of privileged actions",
		Description: fmt.Sprintf("%d privileged actions in the last hour (threshold %d)", total, settings.Thresholds.PrivilegedActionsPerHour),
	}
}

func (s *Server) reviewOverdueDetection(settings model.AuditSettings) model.AuditDetection {
	reviews, err := s.store.ListAuditReviews(1)
	if err != nil {
		return model.AuditDetection{}
	}
	if len(reviews) == 0 {
		return model.AuditDetection{
			ID:          "review-overdue-none",
			Type:        "review_overdue",
			Severity:    "medium",
			Title:       "No audit review completed",
			Description: "No recorded audit reviews exist yet",
		}
	}
	completedAt, err := time.Parse(sqliteAuditTimeFormat(reviews[0].CompletedAt), reviews[0].CompletedAt)
	if err != nil || time.Since(completedAt) <= time.Duration(settings.ReviewReminderDays)*24*time.Hour {
		return model.AuditDetection{}
	}
	return model.AuditDetection{
		ID:          "review-overdue",
		Type:        "review_overdue",
		Severity:    "medium",
		Title:       "Audit review overdue",
		Description: fmt.Sprintf("Last review completed at %s", completedAt.UTC().Format(time.RFC3339)),
	}
}

func (s *Server) auditCountSince(filter model.AuditFilter) (int, error) {
	_, total, err := s.store.ListAuditLogs(filter)
	return total, err
}

func stringPtr(value string) *string {
	return &value
}

func (s *Server) handleListAuditUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	respondJSON(w, http.StatusOK, model.UserListResponse{Users: users})
}

func auditFilterFromRequest(r *http.Request) model.AuditFilter {
	q := r.URL.Query()
	filter := model.AuditFilter{}
	filter.Limit, filter.Offset = parsePagination(q, 50)

	if v := q.Get("action"); v != "" {
		filter.Action = &v
	}
	if v := q.Get("user_id"); v != "" {
		filter.UserID = &v
	}
	if v := q.Get("outcome"); v != "" {
		filter.Outcome = &v
	}
	if v := q.Get("actor_type"); v != "" {
		filter.ActorType = &v
	}
	if v := q.Get("correlation_id"); v != "" {
		filter.CorrelationID = &v
	}
	if v := q.Get("resource_type"); v != "" {
		filter.ResourceType = &v
	}
	if v := q.Get("from"); v != "" {
		filter.From = &v
	}
	if v := q.Get("to"); v != "" {
		filter.To = &v
	}
	return filter
}

func auditFilterSummary(filter model.AuditFilter) string {
	values := map[string]*string{
		"action":         filter.Action,
		"user_id":        filter.UserID,
		"outcome":        filter.Outcome,
		"actor_type":     filter.ActorType,
		"correlation_id": filter.CorrelationID,
		"resource_type":  filter.ResourceType,
		"from":           filter.From,
		"to":             filter.To,
	}
	var parts []string
	for key, value := range values {
		if value != nil && *value != "" {
			parts = append(parts, key+"="+*value)
		}
	}
	if len(parts) == 0 {
		return "filters=none"
	}
	return "filters=" + strings.Join(parts, ",")
}

func validateJSONBlob(data string, maxBytes int64) error {
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("json blob too large")
	}
	var decoded interface{}
	return json.Unmarshal([]byte(data), &decoded)
}

func sqliteAuditTimeFormat(value string) string {
	if strings.Contains(value, "T") {
		return time.RFC3339
	}
	return "2006-01-02 15:04:05"
}
