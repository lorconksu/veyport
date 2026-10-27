package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

var errPasswordChangeRequired = errors.New("password change required; complete password recovery in the browser")

func (s *Server) accountManagementAudit(r *http.Request, actor, target, action string) model.AuditEntry {
	ip := clientIP(r)
	correlation := RequestIDFromContext(r.Context())
	return model.AuditEntry{UserID: &actor, Target: &target, Action: action, IPAddress: &ip, CorrelationID: &correlation, Outcome: model.AuditOutcomeSuccess, ActorType: model.AuditActorTypeUser}
}

func (s *Server) accountManagementError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrAccountManagementActor):
		respondError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, store.ErrProtectedChange):
		securityError(w, err)
	case errors.Is(err, store.ErrSecurityConflict), errors.Is(err, store.ErrAccountDisabled):
		respondError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrTemporaryPasswordExpired):
		respondError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, store.ErrLocalPasswordOnly):
		respondError(w, http.StatusBadRequest, err.Error())
	case userNotFound(err):
		respondError(w, http.StatusNotFound, userNotFoundMessage)
	default:
		respondError(w, http.StatusInternalServerError, "account update failed")
	}
}

func (s *Server) handleReactivateUser(w http.ResponseWriter, r *http.Request) {
	actor, target := UserIDFromContext(r.Context()), r.PathValue("id")
	user, changed, err := s.store.ReactivateUser(target, s.now(), s.lockoutPolicy().DormantDays, s.accountManagementAudit(r, actor, target, model.AuditUserReactivated), s.accountManagementActor(r))
	if err != nil {
		s.auditAccountManagementRefusal(r, actor, target, model.AuditUserReactivated, err)
		s.accountManagementError(w, err)
		return
	}
	user.Status = string(s.accountStatus(user))
	respondJSON(w, http.StatusOK, map[string]any{"user": user, "changed": changed})
}

func (s *Server) auditAccountManagementRefusal(r *http.Request, actor, target, action string, err error) {
	entry := s.accountManagementAudit(r, actor, target, action)
	entry.Outcome = model.AuditOutcomeFailure
	// Never include generated credentials, request bodies or SQL errors.
	detail := "account update refused"
	if errors.Is(err, store.ErrSecurityConflict) {
		detail = "stale account revision"
	}
	entry.Detail = &detail
	s.auditLogRequest(r, entry)
}

func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, target := UserIDFromContext(r.Context()), r.PathValue("id")
	if actor == target {
		respondError(w, http.StatusBadRequest, "use the self-service password change for your own account")
		return
	}
	var req struct {
		Expected *int `json:"expected_revision"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Expected == nil || *req.Expected < 0 {
		respondError(w, http.StatusBadRequest, "expected_revision is required")
		return
	}
	// Cheap refusals precede bcrypt. The transaction repeats all live guards.
	if err := s.securityService().GuardMutation(target); err != nil {
		securityError(w, err)
		return
	}
	current, err := s.store.GetUserByID(target)
	if err != nil {
		s.accountManagementError(w, err)
		return
	}
	if current.AuthProvider != model.AuthProviderLocal {
		s.accountManagementError(w, store.ErrLocalPasswordOnly)
		return
	}
	if current.TokenGeneration != *req.Expected {
		s.accountManagementError(w, store.ErrSecurityConflict)
		return
	}
	authority := s.accountManagementActor(r)
	password := auth.GenerateTemporaryPassword()
	hash, err := auth.HashPassword(password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, errFailedToHashPassword)
		return
	}
	settings := s.store.GetAuditSettings()
	now := s.now().UTC()
	expires := now.Add(time.Duration(settings.TemporaryPasswordTTLHours) * time.Hour).Truncate(time.Second)
	user, err := s.store.ResetLocalPassword(target, *req.Expected, hash, expires, now, settings.PasswordHistoryCount, s.accountManagementAudit(r, actor, target, model.AuditUserPasswordReset), authority)
	if err != nil {
		s.auditAccountManagementRefusal(r, actor, target, model.AuditUserPasswordReset, err)
		s.accountManagementError(w, err)
		return
	}
	// Durable revocation is already committed. Streams use established registry
	// closure plus periodic durable application authorization (bounded at 5s).
	s.endShellsByUser(target, "Authentication credentials changed; sign in again.")
	s.auditApplicationSessionEnds()
	user.Status = string(s.accountStatus(user))
	respondJSON(w, http.StatusOK, map[string]any{"user": user, "temporary_password": password, "expires_at": expires})
}

func temporaryCredentialExpired(user *model.User, now time.Time) bool {
	return user.MustChangePassword && (user.TempPasswordExpiresAt == nil || !now.Before(*user.TempPasswordExpiresAt))
}

func (s *Server) respondPasswordRecovery(w http.ResponseWriter, user *model.User) {
	now := s.now()
	if temporaryCredentialExpired(user, now) {
		respondError(w, http.StatusUnauthorized, "temporary password expired — contact your administrator")
		return
	}
	ttl := auth.SetupTokenExpiry
	if remaining := user.TempPasswordExpiresAt.Sub(now); remaining < ttl {
		ttl = remaining
	}
	token, err := auth.GenerateTokenWithExpiry(s.jwtSecret, user.ID, string(user.Role), auth.TokenTypePasswordRecovery, ttl, user.TokenGeneration)
	if err != nil {
		respondError(w, http.StatusInternalServerError, errFailedToGenerateTokens)
		return
	}
	claims, _ := auth.ValidateToken(s.jwtSecret, token)
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, map[string]any{"must_change_password": true, "recovery_token": token, "expires_at": claims.ExpiresAt.Time})
}

func (s *Server) handleCompletePasswordRecovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// Recovery authority is explicitly supplied in memory by the sign-in flow.
	// Browser cookies can still contain the revoked pre-reset access token and
	// must neither mask this bearer nor authorize recovery on their own.
	token, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), bearerPrefix)
	claims, err := auth.ValidateToken(s.jwtSecret, token)
	if !hasBearer || err != nil || claims.TokenType != auth.TokenTypePasswordRecovery {
		respondError(w, http.StatusUnauthorized, "invalid recovery token")
		return
	}
	if claims.ID != "" && s.tokenBlacklist != nil && s.tokenBlacklist.IsBlacklisted(claims.ID) {
		respondError(w, http.StatusUnauthorized, "invalid recovery token")
		return
	}
	user, err := s.store.GetUserByID(claims.Subject)
	if err != nil || user.TokenGeneration != claims.TokenGeneration || !user.TOTPEnabled || !user.MustChangePassword || temporaryCredentialExpired(user, s.now()) {
		respondError(w, http.StatusUnauthorized, "recovery credential expired or revoked")
		return
	}
	if err := s.accountAccessError(user); err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	if err := auth.ValidatePasswordPolicy(req.NewPassword); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	settings := s.store.GetAuditSettings()
	matches, err := s.store.PasswordMatchesRecent(user.ID, req.NewPassword, settings.PasswordHistoryCount)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to validate password history")
		return
	}
	if matches || auth.ComparePassword(user.PasswordHash, req.NewPassword) {
		respondError(w, http.StatusBadRequest, "new password must not match a recent password")
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		respondError(w, http.StatusInternalServerError, errFailedToHashPassword)
		return
	}
	protected, err := s.store.IsProtectedUser(user.ID)
	if err != nil {
		s.accountManagementError(w, err)
		return
	}
	if protected {
		_, err = s.store.CompleteApprovedPasswordRecoveryAudited(user.ID, user.PasswordHash, user.SecurityRevision, hash, s.now(), settings.PasswordHistoryCount, s.accountManagementAudit(r, user.ID, user.ID, model.AuditUserPasswordChanged), user.TokenGeneration)
	} else {
		_, err = s.store.ChangeLocalPassword(user, hash, s.now(), settings.PasswordHistoryCount, true, s.accountManagementAudit(r, user.ID, user.ID, model.AuditUserPasswordChanged))
	}
	if err != nil {
		s.accountManagementError(w, err)
		return
	}
	s.endShellsByUser(user.ID, "Authentication credentials changed; sign in again.")
	s.auditApplicationSessionEnds()
	clearAuthCookies(w)
	respondJSON(w, http.StatusOK, map[string]any{"status": "password updated", "requires_login": true})
}

func (s *Server) accountManagementActor(r *http.Request) store.AccountManagementActor {
	claims, err := auth.ValidateToken(s.jwtSecret, readAccessToken(r))
	if err != nil {
		return store.AccountManagementActor{}
	}
	user, err := s.store.GetUserByID(claims.Subject)
	if err != nil {
		return store.AccountManagementActor{}
	}
	return store.AccountManagementActor{UserID: claims.Subject, SessionID: claims.SessionID, Generation: claims.TokenGeneration, SecurityRevision: user.SecurityRevision}
}
