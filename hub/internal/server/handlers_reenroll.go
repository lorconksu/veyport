package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

// reEnrollApproveRequest is the body for POST /api/servers/{id}/reenroll/approve.
type reEnrollApproveRequest struct {
	RequestID string `json:"request_id"`
	TOTPCode  string `json:"totp_code"`
}

// reEnrollDenyRequest is the body for POST /api/servers/{id}/reenroll/deny.
type reEnrollDenyRequest struct {
	RequestID string `json:"request_id"`
}

// handleReEnrollApprove handles POST /api/servers/{id}/reenroll/approve.
// It verifies the approving admin's TOTP code (step-up auth), then calls
// ReleaseKEK on the gRPC handler to deliver the KEK+challenge to the waiting
// agent stream and await the proof result.
func (s *Server) handleReEnrollApprove(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	if serverID == "" {
		respondError(w, http.StatusBadRequest, "missing server id")
		return
	}

	var req reEnrollApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if req.TOTPCode == "" {
		respondError(w, http.StatusBadRequest, "totp_code is required")
		return
	}

	adminID := UserIDFromContext(r.Context())

	// Step-up: verify the approving admin's own TOTP code.
	admin, err := s.store.GetUserByID(adminID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load admin user")
		return
	}

	adminTOTPSecret := admin.TOTPSecret
	if adminTOTPSecret != nil && strings.HasPrefix(*adminTOTPSecret, "enc:") {
		decrypted, err := s.decryptTOTPSecret(*adminTOTPSecret)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to decrypt admin TOTP secret")
			return
		}
		adminTOTPSecret = &decrypted
	}

	if adminTOTPSecret == nil || !auth.ValidateTOTPWithReplay(s.totpCache, adminID, *adminTOTPSecret, req.TOTPCode) {
		respondError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	// Validate request_id: it must be provided and must match the current pending
	// request for this server to prevent approving a stale or superseded request.
	if req.RequestID == "" {
		respondError(w, http.StatusBadRequest, "request_id is required")
		return
	}
	pendingList, err := s.store.ListPendingReEnroll()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list pending re-enrollments")
		return
	}
	var currentPendingID string
	for _, pr := range pendingList {
		if pr.ServerID == serverID {
			currentPendingID = pr.ID
			break
		}
	}
	if currentPendingID == "" {
		respondError(w, http.StatusNotFound, "no pending re-enrollment for this server")
		return
	}
	if req.RequestID != currentPendingID {
		respondError(w, http.StatusConflict, "request_id does not match the current pending request; it may have been superseded")
		return
	}

	// TOTP verified and request_id confirmed — call the gRPC handler to release the KEK to the agent.
	if s.reEnrollReleaser == nil {
		respondError(w, http.StatusServiceUnavailable, "re-enroll releaser not configured")
		return
	}

	if err := s.reEnrollReleaser.ReleaseKEK(serverID, adminID); err != nil {
		// Map common errors to appropriate HTTP status codes.
		switch {
		case err.Error() == "no pending re-enroll for server":
			respondError(w, http.StatusNotFound, "no pending re-enrollment for this server")
		case strings.Contains(err.Error(), "timed out"):
			respondError(w, http.StatusGatewayTimeout, "timed out waiting for agent proof")
		default:
			respondError(w, http.StatusConflict, err.Error())
		}
		return
	}

	// Audit the approval.
	ip := clientIP(r)
	s.store.LogAudit(model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &adminID,
		Action:    model.AuditReEnrollApproved,
		Target:    &serverID,
		IPAddress: &ip,
		ActorType: model.AuditActorTypeUser,
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

// handleReEnrollDeny handles POST /api/servers/{id}/reenroll/deny.
// It records the denial and emits an audit entry.
func (s *Server) handleReEnrollDeny(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	if serverID == "" {
		respondError(w, http.StatusBadRequest, "missing server id")
		return
	}

	var req reEnrollDenyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if req.RequestID == "" {
		respondError(w, http.StatusBadRequest, "request_id is required")
		return
	}

	adminID := UserIDFromContext(r.Context())

	// Validate that request_id corresponds to the current pending re-enroll request
	// for this server — mirrors the approve handler to prevent denying a stale or
	// superseded request.
	pendingList, err := s.store.ListPendingReEnroll()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list pending re-enrollments")
		return
	}
	var currentPendingID string
	for _, pr := range pendingList {
		if pr.ServerID == serverID {
			currentPendingID = pr.ID
			break
		}
	}
	if currentPendingID == "" {
		respondError(w, http.StatusNotFound, "no pending re-enrollment for this server")
		return
	}
	if req.RequestID != currentPendingID {
		respondError(w, http.StatusConflict, "request_id does not match the current pending request; it may have been superseded")
		return
	}

	if err := s.store.UpdateReEnrollStatus(req.RequestID, "denied", adminID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update re-enroll status")
		return
	}

	ip := clientIP(r)
	s.store.LogAudit(model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &adminID,
		Action:    model.AuditReEnrollDenied,
		Target:    &serverID,
		IPAddress: &ip,
		ActorType: model.AuditActorTypeUser,
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "denied"})
}

// handleListPendingReEnroll handles GET /api/servers/reenroll/pending.
func (s *Server) handleListPendingReEnroll(w http.ResponseWriter, r *http.Request) {
	reqs, err := s.store.ListPendingReEnroll()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list pending re-enrollments")
		return
	}
	if reqs == nil {
		reqs = []model.ReEnrollRequest{}
	}
	respondJSON(w, http.StatusOK, reqs)
}
