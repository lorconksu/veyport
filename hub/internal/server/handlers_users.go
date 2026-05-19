package server

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	respondJSON(w, http.StatusOK, model.UserListResponse{Users: users})
}

func (s *Server) handleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	if targetID == "" {
		respondError(w, http.StatusBadRequest, "missing user id")
		return
	}

	var req model.UpdateRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !model.IsValidRole(req.Role) {
		respondError(w, http.StatusBadRequest, "role must be 'admin', 'auditor', or 'viewer'")
		return
	}

	adminID := UserIDFromContext(r.Context())
	if adminID == targetID {
		respondError(w, http.StatusBadRequest, "cannot change your own role")
		return
	}

	if err := s.store.UpdateUserRole(targetID, req.Role); err != nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	// Force re-authentication so the new role takes effect immediately instead
	// of waiting up to 15 minutes for the existing access token to expire.
	// Access tokens read the role from JWT claims, not the DB, so without this
	// a demoted admin keeps admin authority until token expiry.
	if _, err := s.store.IncrementTokenGeneration(targetID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to invalidate sessions")
		return
	}

	user, err := s.store.GetUserByID(targetID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to fetch updated user")
		return
	}

	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &adminID,
		Action:    model.AuditUserRoleUpdated,
		Target:    &targetID,
		IPAddress: &ip,
	})

	respondJSON(w, http.StatusOK, model.UserResponse{User: user})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	if targetID == "" {
		respondError(w, http.StatusBadRequest, "missing user id")
		return
	}

	adminID := UserIDFromContext(r.Context())
	if adminID == targetID {
		respondError(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}

	// Check if user has exclusive access to any servers (no other user has access)
	force := r.URL.Query().Get("force") == "true"
	if !force {
		exclusiveServers, err := s.store.GetExclusiveServerAccess(targetID)
		if err == nil && len(exclusiveServers) > 0 {
			respondJSON(w, http.StatusConflict, map[string]interface{}{
				"error":             "user has exclusive access to servers — add ?force=true to confirm",
				"exclusive_servers": exclusiveServers,
			})
			return
		}
	}

	if err := s.store.DeleteUser(targetID); err != nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &adminID,
		Action:    model.AuditUserDeleted,
		Target:    &targetID,
		IPAddress: &ip,
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "user deleted"})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req model.CreateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validateUsername(req.Username); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !model.IsValidRole(req.Role) {
		respondError(w, http.StatusBadRequest, "role must be 'admin', 'auditor', or 'viewer'")
		return
	}

	tempPassword := auth.GenerateTemporaryPassword()
	hash, err := auth.HashPassword(tempPassword)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user := &model.User{
		ID:                 uuid.NewString(),
		Username:           req.Username,
		Email:              req.Email,
		PasswordHash:       hash,
		Role:               req.Role,
		MustChangePassword: true,
	}
	settings := s.store.GetAuditSettings()
	tempExpiresAt := time.Now().UTC().Add(time.Duration(settings.TemporaryPasswordTTLHours) * time.Hour)
	user.TempPasswordExpiresAt = &tempExpiresAt

	if err := s.store.CreateUser(user); err != nil {
		respondError(w, http.StatusConflict, "user already exists")
		return
	}
	_ = s.store.AddPasswordHistory(user.ID, hash)
	_ = s.store.TrimPasswordHistory(user.ID, settings.PasswordHistoryCount)

	adminID := UserIDFromContext(r.Context())
	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &adminID,
		Action:    model.AuditUserCreated,
		Target:    &user.ID,
		IPAddress: &ip,
	})
	if s.notifier != nil {
		s.notifier.Notify(model.NotifyUserCreated, map[string]string{
			"username":  req.Username,
			"timestamp": time.Now().UTC().Format(model.NotifyTimestampFormat),
		})
	}

	respondJSON(w, http.StatusCreated, model.CreateUserResponse{
		User:              *user,
		TemporaryPassword: tempPassword,
	})
}
