package server

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/notify"
)

const redactedValue = "********"

// handleGetSMTPConfig returns the current SMTP configuration.
// Password is write-only: returns redactedValue if set, empty string if not.
func (s *Server) handleGetSMTPConfig(w http.ResponseWriter, r *http.Request) {
	cfg := notify.LoadSMTPConfig(s.store)

	// Mask the password
	if cfg.Password != "" {
		cfg.Password = redactedValue
	}

	respondJSON(w, http.StatusOK, cfg)
}

// validateSMTPConfig checks that a SMTPConfig has valid field values when enabled.
func validateSMTPConfig(req model.SMTPConfig) error {
	if !req.Enabled {
		return nil
	}
	if req.Port < 1 || req.Port > 65535 {
		return fmt.Errorf("SMTP port must be between 1 and 65535")
	}
	if !strings.Contains(req.From, "@") {
		return fmt.Errorf("SMTP from address must contain @")
	}
	if req.Host == "" {
		return fmt.Errorf("SMTP host is required when enabled")
	}
	return nil
}

// handleUpdateSMTPConfig saves SMTP configuration fields to the store.
// If password is "********" or empty, the existing password is preserved.
func (s *Server) handleUpdateSMTPConfig(w http.ResponseWriter, r *http.Request) {
	var req model.SMTPConfig
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	if err := validateSMTPConfig(req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	configs := map[string]string{
		"smtp_host":     req.Host,
		"smtp_port":     strconv.Itoa(req.Port),
		"smtp_username": req.Username,
		"smtp_from":     req.From,
		"smtp_tls":      fmt.Sprintf("%t", req.TLS),
		"smtp_enabled":  fmt.Sprintf("%t", req.Enabled),
	}
	if req.Password != "" && req.Password != redactedValue {
		encrypted, err := encryptSMTPPassword(s.jwtSecret, req.Password)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to encrypt SMTP password")
			return
		}
		configs["smtp_password"] = encrypted
	}

	tx, err := s.store.DB().Begin()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	for key, value := range configs {
		if _, err := tx.Exec("INSERT INTO _config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value); err != nil {
			tx.Rollback()
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save %s", key))
			return
		}
	}
	if err := tx.Commit(); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to commit config")
		return
	}

	// Invalidate cached SMTP config so the notifier picks up changes immediately
	if s.notifier != nil {
		s.notifier.InvalidateSMTPCache()
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleTestSMTP sends a test email to the given recipient using the current SMTP config.
func (s *Server) handleTestSMTP(w http.ResponseWriter, r *http.Request) {
	var req model.SMTPTestRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	if req.Recipient == "" {
		respondError(w, http.StatusBadRequest, "recipient is required")
		return
	}

	cfg := notify.LoadSMTPConfig(s.store, s.jwtSecret)

	// Force enabled for the test send so SendEmail doesn't skip it
	cfg.Enabled = true

	if err := notify.SendEmail(cfg, req.Recipient, "Veyport SMTP Test", "This is a test email from Veyport. Your SMTP configuration is working correctly."); err != nil {
		log.Printf("SMTP test send failed: %v", err)
		respondError(w, http.StatusBadGateway, "failed to send test email — check SMTP settings and server logs")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// handleGetNotificationPreferences returns the authenticated user's notification preferences.
func (s *Server) handleGetNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	prefs, err := s.store.GetNotificationPreferences(userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to get notification preferences")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"preferences": prefs})
}

// handleUpdateNotificationPreferences saves notification preference updates for the authenticated user.
func (s *Server) handleUpdateNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	var req model.NotificationPreferencesRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	userID := UserIDFromContext(r.Context())

	// Build a set of valid event types for O(1) lookup
	validEvents := make(map[string]bool, len(model.AllNotifyEvents))
	for _, e := range model.AllNotifyEvents {
		validEvents[e.Type] = true
	}

	for _, pref := range req.Preferences {
		if !validEvents[pref.EventType] {
			respondError(w, http.StatusBadRequest, "unknown event type: "+pref.EventType)
			return
		}
		if err := s.store.SetNotificationPreference(userID, pref.EventType, pref.Enabled); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to update preference for "+pref.EventType)
			return
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleListNotificationLog returns a paginated list of notification log entries.
func (s *Server) handleListNotificationLog(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePagination(r.URL.Query(), 50)

	entries, total, err := s.store.ListNotificationLog(limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list notification log")
		return
	}

	// Return empty slice rather than null
	if entries == nil {
		entries = []model.NotificationLogEntry{}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"total":   total,
	})
}

// encryptSMTPPassword encrypts an SMTP password and returns it with "enc:" prefix.
func encryptSMTPPassword(jwtSecret, password string) (string, error) {
	key := auth.DeriveKey(jwtSecret)
	encrypted, err := auth.Encrypt([]byte(password), key)
	if err != nil {
		return "", err
	}
	return "enc:" + hex.EncodeToString(encrypted), nil
}

// DecryptSMTPPassword decrypts an SMTP password that has the "enc:" prefix.
// If the value does not have the prefix, it is treated as legacy plaintext.
func DecryptSMTPPassword(jwtSecret, stored string) (string, error) {
	if !strings.HasPrefix(stored, "enc:") {
		return stored, nil // legacy plaintext — backward compatible
	}
	data, err := hex.DecodeString(stored[4:])
	if err != nil {
		return "", fmt.Errorf("invalid encrypted SMTP password format: %w", err)
	}
	key := auth.DeriveKey(jwtSecret)
	decrypted, err := auth.Decrypt(data, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
