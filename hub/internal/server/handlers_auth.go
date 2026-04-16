package server

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
)

const errFailedToHashPassword = "failed to hash password"

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	count, err := s.store.InitializedUserCount()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to check user count")
		return
	}
	resp := model.AuthStatusResponse{Initialized: count > 0}

	// Only include version for authenticated users
	if tokenStr := readAccessToken(r); tokenStr != "" {
		if claims, err := auth.ValidateToken(s.jwtSecret, tokenStr); err == nil && claims.TokenType == auth.TokenTypeAccess {
			resp.Version = Version
		}
	}

	respondJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Only allowed when no fully-initialized users exist
	count, err := s.store.InitializedUserCount()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to check user count")
		return
	}
	if count > 0 {
		respondError(w, http.StatusForbidden, "registration disabled — use admin to create users")
		return
	}

	// Clean up any users from incomplete setup attempts
	if err := s.store.DeleteIncompleteUsers(); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to clean up incomplete setup")
		return
	}

	var req model.RegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	if err := validateUsername(req.Username); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := auth.ValidatePasswordPolicy(req.Password); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, errFailedToHashPassword)
		return
	}

	user := &model.User{
		ID:           uuid.NewString(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hash,
		Role:         model.RoleAdmin,
	}

	if err := s.store.CreateUser(user); err != nil {
		// Unique constraint violation = another request won the race
		respondError(w, http.StatusConflict, "setup already completed")
		return
	}
	settings := s.store.GetAuditSettings()
	_ = s.store.AddPasswordHistory(user.ID, hash)
	_ = s.store.TrimPasswordHistory(user.ID, settings.PasswordHistoryCount)

	// Recheck: if another registration won the race with a different username, roll back
	count, _ = s.store.UserCount()
	if count > 1 {
		s.store.DeleteUser(user.ID)
		respondError(w, http.StatusConflict, "setup already completed")
		return
	}

	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &user.ID,
		Action:    model.AuditUserRegistered,
		IPAddress: &ip,
	})

	setupToken, err := auth.GenerateSetupToken(s.jwtSecret, user.ID, string(user.Role))
	if err != nil {
		respondError(w, http.StatusInternalServerError, errFailedToGenerateToken)
		return
	}

	respondJSON(w, http.StatusOK, model.SetupResponse{
		SetupToken: setupToken,
		User:       user,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	user, err := s.store.GetUserByUsername(req.Username)
	if err != nil {
		// Dummy bcrypt compare to prevent username enumeration via timing
		auth.ComparePassword("$2a$12$000000000000000000000000000000000000000000000000000000", "dummy")
		ip := clientIP(r)
		s.auditLogRequest(r, model.AuditEntry{
			ID:        uuid.NewString(),
			Action:    model.AuditUserLoginFailed,
			IPAddress: &ip,
			ActorType: model.AuditActorTypeAnonymous,
		})
		if s.notifier != nil {
			s.notifier.Notify(model.NotifyLoginFailed, map[string]string{
				"username": req.Username, "ip": ip,
				"timestamp": time.Now().UTC().Format(model.NotifyTimestampFormat),
			})
		}
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if !auth.ComparePassword(user.PasswordHash, req.Password) {
		ip := clientIP(r)
		s.auditLogRequest(r, model.AuditEntry{
			ID:        uuid.NewString(),
			UserID:    &user.ID,
			Action:    model.AuditUserLoginFailed,
			IPAddress: &ip,
		})
		if s.notifier != nil {
			s.notifier.Notify(model.NotifyLoginFailed, map[string]string{
				"username": req.Username, "ip": ip,
				"timestamp": time.Now().UTC().Format(model.NotifyTimestampFormat),
			})
		}
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if user.MustChangePassword && user.TempPasswordExpiresAt != nil && time.Now().UTC().After(*user.TempPasswordExpiresAt) {
		ip := clientIP(r)
		detail := "temporary password expired"
		s.auditLogRequest(r, model.AuditEntry{
			ID:        uuid.NewString(),
			UserID:    &user.ID,
			Action:    model.AuditUserLoginFailed,
			Detail:    &detail,
			IPAddress: &ip,
			Outcome:   model.AuditOutcomeFailure,
		})
		respondError(w, http.StatusUnauthorized, "temporary password expired — contact an administrator")
		return
	}

	// If TOTP not set up yet, return setup token
	if !user.TOTPEnabled {
		setupToken, err := auth.GenerateSetupToken(s.jwtSecret, user.ID, string(user.Role))
		if err != nil {
			respondError(w, http.StatusInternalServerError, errFailedToGenerateToken)
			return
		}
		respondJSON(w, http.StatusOK, model.LoginResponse{
			SetupToken:         setupToken,
			RequiresTOTPSetup:  true,
			MustChangePassword: user.MustChangePassword,
		})
		return
	}

	// TOTP is enabled — require TOTP code
	totpToken, err := auth.GenerateTOTPToken(s.jwtSecret, user.ID, string(user.Role))
	if err != nil {
		respondError(w, http.StatusInternalServerError, errFailedToGenerateToken)
		return
	}

	respondJSON(w, http.StatusAccepted, model.LoginResponse{
		TOTPToken: totpToken,
	})
}

func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	var req model.LoginTOTPRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	// Validate the TOTP token (proves password was already verified)
	claims, err := auth.ValidateToken(s.jwtSecret, req.TOTPToken)
	if err != nil || claims.TokenType != auth.TokenTypeTOTP {
		respondError(w, http.StatusUnauthorized, "invalid or expired TOTP token")
		return
	}

	user, err := s.store.GetUserByID(claims.Subject)
	if err != nil {
		respondError(w, http.StatusUnauthorized, errUserNotFound)
		return
	}

	// Decrypt TOTP secret if encrypted
	totpSecret := user.TOTPSecret
	if totpSecret != nil && strings.HasPrefix(*totpSecret, "enc:") {
		decrypted, err := s.decryptTOTPSecret(*totpSecret)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to decrypt TOTP secret")
			return
		}
		totpSecret = &decrypted
	}

	if totpSecret == nil || !auth.ValidateTOTPWithReplay(s.totpCache, user.ID, *totpSecret, req.Code) {
		ip := clientIP(r)
		s.auditLogRequest(r, model.AuditEntry{
			ID:        uuid.NewString(),
			UserID:    &user.ID,
			Action:    model.AuditUserLoginTOTPFailed,
			IPAddress: &ip,
		})
		respondError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	accessToken, refreshToken, err := auth.GenerateTokenPair(s.jwtSecret, user.ID, string(user.Role), user.TokenGeneration)
	if err != nil {
		respondError(w, http.StatusInternalServerError, errFailedToGenerateTokens)
		return
	}

	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &user.ID,
		Action:    model.AuditUserLogin,
		IPAddress: &ip,
	})

	setAuthCookies(w, accessToken, refreshToken)
	respondJSON(w, http.StatusOK, model.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         *user,
	})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	// Read refresh token from cookie first, fall back to request body
	refreshTokenStr := ""
	if c, err := r.Cookie(cookieRefresh); err == nil {
		refreshTokenStr = c.Value
	}
	if refreshTokenStr == "" {
		var req model.RefreshRequest
		if err := decodeJSON(r, &req); err != nil {
			respondError(w, http.StatusBadRequest, errInvalidRequestBody)
			return
		}
		refreshTokenStr = req.RefreshToken
	}

	claims, err := auth.ValidateToken(s.jwtSecret, refreshTokenStr)
	if err != nil || claims.TokenType != auth.TokenTypeRefresh {
		respondError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	// Verify user still exists and use current role from DB
	user, err := s.store.GetUserByID(claims.Subject)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "user no longer exists")
		return
	}

	// Validate token generation matches DB (detect revoked/outdated refresh tokens)
	if claims.TokenGeneration != user.TokenGeneration {
		respondError(w, http.StatusUnauthorized, "token has been revoked")
		return
	}

	// Increment token generation to prevent reuse of this refresh token
	newGen, err := s.store.IncrementTokenGeneration(user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to rotate token generation")
		return
	}

	// Use user.Role from DB, not claims.Role from the old token
	accessToken, refreshToken, err := auth.GenerateTokenPair(s.jwtSecret, user.ID, string(user.Role), newGen)
	if err != nil {
		respondError(w, http.StatusInternalServerError, errFailedToGenerateTokens)
		return
	}

	setAuthCookies(w, accessToken, refreshToken)
	respondJSON(w, http.StatusOK, model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Blacklist the access token if present
	if tokenStr := readAccessToken(r); tokenStr != "" {
		if claims, err := auth.ValidateToken(s.jwtSecret, tokenStr); err == nil && claims.ID != "" {
			s.tokenBlacklist.Add(claims.ID, claims.ExpiresAt.Time)
		}
	}
	clearAuthCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		respondError(w, http.StatusNotFound, errUserNotFound)
		return
	}
	respondJSON(w, http.StatusOK, user)
}

func (s *Server) handleUpdateAvatar(w http.ResponseWriter, r *http.Request) {
	var req model.UpdateAvatarRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	// Validate the avatar is a reasonable data URL (max ~500KB base64)
	if len(req.Avatar) > 700000 {
		respondError(w, http.StatusBadRequest, "avatar image too large (max 500KB)")
		return
	}

	if req.Avatar != "" {
		validPrefixes := []string{"data:image/png", "data:image/jpeg", "data:image/gif", "data:image/webp"}
		valid := false
		for _, p := range validPrefixes {
			if strings.HasPrefix(req.Avatar, p) {
				valid = true
				break
			}
		}
		if !valid {
			respondError(w, http.StatusBadRequest, "avatar must be a PNG, JPEG, GIF, or WebP image")
			return
		}
	}

	userID := UserIDFromContext(r.Context())
	var avatar *string
	if req.Avatar != "" {
		avatar = &req.Avatar
	}

	if err := s.store.UpdateUserAvatar(userID, avatar); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update avatar")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "avatar updated"})
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		respondError(w, http.StatusNotFound, errUserNotFound)
		return
	}
	if user.TOTPEnabled {
		respondError(w, http.StatusConflict, "TOTP is already enabled")
		return
	}

	key, err := auth.GenerateTOTPSecret(user.Username, "AeroDocs")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}

	// Capture plaintext secret and QR URL before encrypting
	plaintextSecret := key.Secret()
	qrURL := key.URL()

	// Encrypt the secret before storing
	encryptedSecret, err := s.encryptTOTPSecret(plaintextSecret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to encrypt TOTP secret")
		return
	}

	// Store encrypted secret (not yet enabled)
	if err := s.store.UpdateUserTOTP(userID, &encryptedSecret, false); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to store TOTP secret")
		return
	}

	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &userID,
		Action:    model.AuditUserTOTPSetup,
		IPAddress: &ip,
	})

	// Respond with plaintext secret and QR URL for the user's authenticator app
	respondJSON(w, http.StatusOK, model.TOTPSetupResponse{
		Secret: plaintextSecret,
		QRURL:  qrURL,
	})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	var req model.TOTPEnableRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	userID := UserIDFromContext(r.Context())
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		respondError(w, http.StatusNotFound, errUserNotFound)
		return
	}

	if user.TOTPSecret == nil {
		respondError(w, http.StatusBadRequest, "TOTP not set up — call /api/auth/totp/setup first")
		return
	}

	totpSecretForValidation, err := s.totpSecretForValidation(user.TOTPSecret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to decrypt TOTP secret")
		return
	}

	if !auth.ValidateTOTPWithReplay(s.totpCache, userID, *totpSecretForValidation, req.Code) {
		respondError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	if err := s.rotateTemporaryPasswordDuringTOTPEnable(r, user, req.NewPassword); err != nil {
		status, message := totpEnablePasswordError(err)
		respondError(w, status, message)
		return
	}

	// Encrypt the TOTP secret before final storage
	encryptedSecret, err := s.encryptTOTPSecret(*totpSecretForValidation)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to encrypt TOTP secret")
		return
	}

	if err := s.store.UpdateUserTOTP(userID, &encryptedSecret, true); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to enable TOTP")
		return
	}

	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &userID,
		Action:    model.AuditUserTOTPEnabled,
		IPAddress: &ip,
	})
	if s.notifier != nil {
		s.notifier.Notify(model.NotifyTOTPChanged, map[string]string{
			"username": user.Username, "detail": "TOTP enabled",
			"timestamp": time.Now().UTC().Format(model.NotifyTimestampFormat),
		})
	}

	// Generate full access tokens now that 2FA is enabled
	accessToken, refreshToken, err := auth.GenerateTokenPair(s.jwtSecret, user.ID, string(user.Role), user.TokenGeneration)
	if err != nil {
		respondError(w, http.StatusInternalServerError, errFailedToGenerateTokens)
		return
	}

	// Refresh user to get updated totp_enabled
	user, _ = s.store.GetUserByID(userID)

	setAuthCookies(w, accessToken, refreshToken)
	respondJSON(w, http.StatusOK, model.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         *user,
	})
}

func (s *Server) totpSecretForValidation(secret *string) (*string, error) {
	if secret == nil || !strings.HasPrefix(*secret, "enc:") {
		return secret, nil
	}
	decrypted, err := s.decryptTOTPSecret(*secret)
	if err != nil {
		return nil, err
	}
	return &decrypted, nil
}

func (s *Server) rotateTemporaryPasswordDuringTOTPEnable(r *http.Request, user *model.User, newPassword string) error {
	if !user.MustChangePassword {
		return nil
	}
	settings := s.store.GetAuditSettings()
	if newPassword == "" {
		return fmt.Errorf("bad_request:new_password is required for temporary-password users")
	}
	if err := auth.ValidatePasswordPolicy(newPassword); err != nil {
		return fmt.Errorf("bad_request:%s", err.Error())
	}
	matchesRecent, err := s.store.PasswordMatchesRecent(user.ID, newPassword, settings.PasswordHistoryCount)
	if err != nil {
		return fmt.Errorf("internal:failed to validate password history")
	}
	if matchesRecent {
		ip := clientIP(r)
		s.auditLogRequest(r, model.AuditEntry{
			ID:        uuid.NewString(),
			UserID:    &user.ID,
			Action:    model.AuditUserPasswordReuseRejected,
			IPAddress: &ip,
			Outcome:   model.AuditOutcomeFailure,
		})
		return fmt.Errorf("bad_request:new password must not match a recent password")
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("internal:%s", errFailedToHashPassword)
	}
	if err := s.store.UpdateUserPassword(user.ID, hash); err != nil {
		return fmt.Errorf("internal:failed to update password")
	}
	_ = s.store.AddPasswordHistory(user.ID, hash)
	_ = s.store.TrimPasswordHistory(user.ID, settings.PasswordHistoryCount)
	user.PasswordHash = hash
	user.MustChangePassword = false
	user.TempPasswordExpiresAt = nil
	return nil
}

func totpEnablePasswordError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	message := err.Error()
	if strings.HasPrefix(message, "bad_request:") {
		return http.StatusBadRequest, strings.TrimPrefix(message, "bad_request:")
	}
	if strings.HasPrefix(message, "internal:") {
		return http.StatusInternalServerError, strings.TrimPrefix(message, "internal:")
	}
	return http.StatusInternalServerError, "failed to update password"
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req model.ChangePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	userID := UserIDFromContext(r.Context())
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		respondError(w, http.StatusNotFound, errUserNotFound)
		return
	}

	if !auth.ComparePassword(user.PasswordHash, req.CurrentPassword) {
		respondError(w, http.StatusUnauthorized, "invalid current password")
		return
	}

	if err := auth.ValidatePasswordPolicy(req.NewPassword); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	settings := s.store.GetAuditSettings()
	matchesRecent, err := s.store.PasswordMatchesRecent(userID, req.NewPassword, settings.PasswordHistoryCount)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to validate password history")
		return
	}
	if matchesRecent {
		ip := clientIP(r)
		s.auditLogRequest(r, model.AuditEntry{
			ID:        uuid.NewString(),
			UserID:    &userID,
			Action:    model.AuditUserPasswordReuseRejected,
			IPAddress: &ip,
			Outcome:   model.AuditOutcomeFailure,
		})
		respondError(w, http.StatusBadRequest, "new password must not match a recent password")
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		respondError(w, http.StatusInternalServerError, errFailedToHashPassword)
		return
	}

	if err := s.store.UpdateUserPassword(userID, hash); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update password")
		return
	}
	_ = s.store.AddPasswordHistory(userID, hash)
	_ = s.store.TrimPasswordHistory(userID, settings.PasswordHistoryCount)

	// Invalidate all existing sessions by incrementing token generation
	if _, err := s.store.IncrementTokenGeneration(userID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to invalidate sessions")
		return
	}

	// Revoke all API tokens — password change is a security event that should invalidate all credentials
	if err := s.store.RevokeAllAPITokensByUserID(userID); err != nil {
		log.Printf("warning: failed to revoke api tokens on password change for user %s: %v", userID, err)
	}

	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &userID,
		Action:    model.AuditUserPasswordChanged,
		IPAddress: &ip,
	})
	if s.notifier != nil {
		s.notifier.Notify(model.NotifyPasswordChanged, map[string]string{
			"username":  user.Username,
			"timestamp": time.Now().UTC().Format(model.NotifyTimestampFormat),
		})
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "password updated"})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var req model.TOTPDisableRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	adminID := UserIDFromContext(r.Context())
	if req.UserID == adminID {
		respondError(w, http.StatusBadRequest, "cannot disable your own 2FA")
		return
	}

	// Verify admin's own TOTP code
	admin, err := s.store.GetUserByID(adminID)
	if err != nil {
		respondError(w, http.StatusNotFound, "admin user not found")
		return
	}

	// Decrypt admin's TOTP secret if encrypted
	adminTOTPSecret := admin.TOTPSecret
	if adminTOTPSecret != nil && strings.HasPrefix(*adminTOTPSecret, "enc:") {
		decrypted, err := s.decryptTOTPSecret(*adminTOTPSecret)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to decrypt admin TOTP secret")
			return
		}
		adminTOTPSecret = &decrypted
	}

	if adminTOTPSecret == nil || !auth.ValidateTOTPWithReplay(s.totpCache, adminID, *adminTOTPSecret, req.AdminTOTPCode) {
		respondError(w, http.StatusUnauthorized, "invalid admin TOTP code")
		return
	}

	// Verify target user exists
	targetUser, err := s.store.GetUserByID(req.UserID)
	if err != nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	// Disable target user's TOTP
	if err := s.store.UpdateUserTOTP(req.UserID, nil, false); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to disable TOTP")
		return
	}

	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &adminID,
		Action:    model.AuditUserTOTPDisabled,
		Target:    &req.UserID,
		IPAddress: &ip,
	})
	if s.notifier != nil {
		s.notifier.Notify(model.NotifyTOTPChanged, map[string]string{
			"username": targetUser.Username, "detail": "TOTP disabled",
			"timestamp": time.Now().UTC().Format(model.NotifyTimestampFormat),
		})
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "totp disabled"})
}

func validateUsername(username string) error {
	if len(username) < 3 || len(username) > 32 {
		return fmt.Errorf("username must be 3-32 characters")
	}
	for _, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return fmt.Errorf("username may only contain alphanumeric characters and underscores")
		}
	}
	return nil
}

// encryptTOTPSecret encrypts a TOTP secret and returns it with "enc:" prefix.
func (s *Server) encryptTOTPSecret(secret string) (string, error) {
	key := auth.DeriveKey(s.jwtSecret)
	encrypted, err := auth.Encrypt([]byte(secret), key)
	if err != nil {
		return "", err
	}
	return "enc:" + hex.EncodeToString(encrypted), nil
}

// decryptTOTPSecret decrypts a TOTP secret that has the "enc:" prefix.
func (s *Server) decryptTOTPSecret(encrypted string) (string, error) {
	if !strings.HasPrefix(encrypted, "enc:") {
		return encrypted, nil
	}
	data, err := hex.DecodeString(encrypted[4:])
	if err != nil {
		return "", fmt.Errorf("invalid encrypted TOTP secret format: %w", err)
	}
	key := auth.DeriveKey(s.jwtSecret)
	decrypted, err := auth.Decrypt(data, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
