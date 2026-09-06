package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	// Status is derived rather than stored (research R7), so it is computed
	// here against the live policy and clock. An administrator therefore sees
	// an account turn dormant the moment the window closes, with no background
	// job and no stale column to reconcile.
	for i := range users {
		users[i].Status = string(s.accountStatus(&users[i]))
	}
	respondJSON(w, http.StatusOK, model.UserListResponse{Users: users})
}

func (s *Server) handleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	if targetID == "" {
		respondError(w, http.StatusBadRequest, errMissingUserID)
		return
	}

	var req model.UpdateRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
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

	// Read the target before the write so the exemption side effect below can
	// tell a real admin → non-admin demotion from a no-op role change.
	previous, err := s.store.GetUserByID(targetID)
	if err != nil {
		respondError(w, http.StatusNotFound, userNotFoundMessage)
		return
	}

	if err := s.store.UpdateUserRole(targetID, req.Role); err != nil {
		respondError(w, http.StatusNotFound, userNotFoundMessage)
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

	// The store clears the dormancy exemption as part of the role UPDATE
	// (research R6), because an exemption only makes sense on an
	// administrator. The audit trail must still show it happened and why,
	// otherwise the flag would appear to vanish on its own.
	if previous.DormancyExempt && req.Role != model.RoleAdmin {
		s.auditDormancyExemption(r, adminID, targetID, false, stringPtr(detailRoleChanged))
	}

	user.Status = string(s.accountStatus(user))
	respondJSON(w, http.StatusOK, model.UserResponse{User: user})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	if targetID == "" {
		respondError(w, http.StatusBadRequest, errMissingUserID)
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
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
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

// ---------------------------------------------------------------------------
// Account lifecycle (feature 008)
// ---------------------------------------------------------------------------
//
// The three handlers below are the only way an account's access is changed by
// hand. They share one shape: resolve the target, call a single atomic store
// operation, audit the outcome against the acting administrator, then answer
// with the target's freshly derived status — the same derivation the sign-in,
// middleware and SSH paths use, so the administrator's table and the
// enforcement decision can never disagree.

const (
	userNotFoundMessage       = "user not found"
	selfDisableMessage        = "cannot disable your own account"
	lastAdminMessage          = "cannot disable the last enabled administrator"
	dormancyExemptRoleMessage = "dormancy exemption applies to administrator accounts only"
	detailRoleChanged         = "role changed"
	resourceTypeUser          = "user"
)

// userNotFound reports whether a store error means the row was missing. The
// store signals that with a message rather than a sentinel, so the mapping to
// 404 lives here instead of turning every storage fault into a 404 the way an
// unconditional mapping would.
func userNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), userNotFoundMessage)
}

// lifecycleAuditDetail renders an audit detail payload as JSON. A marshalling
// failure degrades to a plain-text rendering rather than dropping the entry:
// an imperfect record of an access change beats no record.
func lifecycleAuditDetail(payload interface{}) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf("%v", payload)
	}
	return string(encoded)
}

// auditLifecycle writes one administrator-attributed lifecycle event.
func (s *Server) auditLifecycle(r *http.Request, adminID, targetID, action string, detail *string) {
	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &adminID,
		Action:       action,
		Target:       &targetID,
		Detail:       detail,
		IPAddress:    &ip,
		Outcome:      model.AuditOutcomeSuccess,
		ActorType:    model.AuditActorTypeUser,
		ResourceType: stringPtr(resourceTypeUser),
	})
}

// auditDormancyExemption records a change to the exemption flag, choosing the
// set or cleared action so the two directions can be filtered apart.
func (s *Server) auditDormancyExemption(r *http.Request, adminID, targetID string, exempt bool, detail *string) {
	action := model.AuditUserDormancyExemptCleared
	if exempt {
		action = model.AuditUserDormancyExemptSet
	}
	s.auditLifecycle(r, adminID, targetID, action, detail)
}

// respondUserWithStatus reloads the target and answers 200 with its derived
// status attached, so a client never has to recompute the label itself.
func (s *Server) respondUserWithStatus(w http.ResponseWriter, userID string) {
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to fetch updated user")
		return
	}
	user.Status = string(s.accountStatus(user))
	respondJSON(w, http.StatusOK, model.UserResponse{User: user})
}

// handleUpdateUserStatus serves PUT /api/users/{id}/status, the disable and
// enable switch (FR-002, FR-003, FR-004).
func (s *Server) handleUpdateUserStatus(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	if targetID == "" {
		respondError(w, http.StatusBadRequest, errMissingUserID)
		return
	}

	// The field is required rather than defaulted. Reading a missing
	// "disabled" as false would turn a malformed disable request into a
	// silent enable — the opposite of what the caller asked for.
	var req struct {
		Disabled *bool `json:"disabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if req.Disabled == nil {
		respondError(w, http.StatusBadRequest, "disabled is required")
		return
	}

	adminID := UserIDFromContext(r.Context())
	if *req.Disabled {
		s.disableAccount(w, r, adminID, targetID)
		return
	}
	s.enableAccount(w, r, adminID, targetID)
}

// disableAccount applies the disable transaction and its two guards.
//
// The self guard is here rather than in the store because it is about the
// request, not the data: an administrator disabling themselves would revoke
// their own session mid-request. The last-admin guard is the store's, checked
// inside the write transaction, so it holds under concurrent disables.
func (s *Server) disableAccount(w http.ResponseWriter, r *http.Request, adminID, targetID string) {
	if adminID == targetID {
		respondError(w, http.StatusBadRequest, selfDisableMessage)
		return
	}

	revoked, err := s.store.DisableUser(targetID, adminID, s.now())
	switch {
	case errors.Is(err, store.ErrAlreadyDisabled):
		// Idempotent: nothing was written, but the attempt is still audited so
		// a retried request leaves the same trail as the original.
	case errors.Is(err, store.ErrLastAdmin):
		respondError(w, http.StatusConflict, lastAdminMessage)
		return
	case userNotFound(err):
		respondError(w, http.StatusNotFound, userNotFoundMessage)
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "failed to disable user")
		return
	}

	detail := lifecycleAuditDetail(struct {
		RevokedAPITokens int `json:"revoked_api_tokens"`
	}{RevokedAPITokens: revoked})
	s.auditLifecycle(r, adminID, targetID, model.AuditUserDisabled, &detail)

	s.respondUserWithStatus(w, targetID)
}

// enableAccount re-enables an account, clearing any lock and failure count with
// it. Enabling one's own account is allowed: it can only widen access, and an
// administrator whose account was disabled by a peer has no session to protect.
func (s *Server) enableAccount(w http.ResponseWriter, r *http.Request, adminID, targetID string) {
	wasDisabled, err := s.store.EnableUser(targetID, s.now())
	switch {
	case userNotFound(err):
		respondError(w, http.StatusNotFound, userNotFoundMessage)
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "failed to enable user")
		return
	}

	detail := lifecycleAuditDetail(struct {
		WasDisabled bool `json:"was_disabled"`
	}{WasDisabled: wasDisabled})
	s.auditLifecycle(r, adminID, targetID, model.AuditUserEnabled, &detail)

	s.respondUserWithStatus(w, targetID)
}

// handleUnlockUser serves POST /api/users/{id}/unlock: an administrator ends a
// lockout before its expiry (FR-005). Unlocking an account that is not locked
// succeeds and is audited, but the was_locked detail records that nothing
// changed — and the store leaves the activity clock alone in that case, so the
// action cannot be used to postpone dormancy.
func (s *Server) handleUnlockUser(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	if targetID == "" {
		respondError(w, http.StatusBadRequest, errMissingUserID)
		return
	}

	wasLocked, err := s.store.UnlockUser(targetID, s.now())
	switch {
	case userNotFound(err):
		respondError(w, http.StatusNotFound, userNotFoundMessage)
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "failed to unlock user")
		return
	}

	adminID := UserIDFromContext(r.Context())
	detail := lifecycleAuditDetail(struct {
		WasLocked bool `json:"was_locked"`
	}{WasLocked: wasLocked})
	s.auditLifecycle(r, adminID, targetID, model.AuditUserUnlocked, &detail)

	s.respondUserWithStatus(w, targetID)
}

// handleSetDormancyExempt serves PUT /api/users/{id}/dormancy-exemption
// (FR-017). The exemption exists so a hub always retains an administrative
// recovery path, which is why the store refuses it on anything but an
// administrator — including when a concurrent demotion lands first.
func (s *Server) handleSetDormancyExempt(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	if targetID == "" {
		respondError(w, http.StatusBadRequest, errMissingUserID)
		return
	}

	var req struct {
		Exempt *bool `json:"exempt"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if req.Exempt == nil {
		respondError(w, http.StatusBadRequest, "exempt is required")
		return
	}

	err := s.store.SetDormancyExempt(targetID, *req.Exempt)
	switch {
	case errors.Is(err, store.ErrNotAdmin):
		respondError(w, http.StatusBadRequest, dormancyExemptRoleMessage)
		return
	case userNotFound(err):
		respondError(w, http.StatusNotFound, userNotFoundMessage)
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "failed to update dormancy exemption")
		return
	}

	adminID := UserIDFromContext(r.Context())
	s.auditDormancyExemption(r, adminID, targetID, *req.Exempt, nil)

	s.respondUserWithStatus(w, targetID)
}
