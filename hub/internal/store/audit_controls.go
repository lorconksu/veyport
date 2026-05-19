package store

import (
	"fmt"
	"strconv"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

const (
	configAuditFailureCount                 = "audit.failure_count"
	configAuditLastFailureAt                = "audit.last_failure_at"
	configAuditLastFailureReason            = "audit.last_failure_reason"
	configAuditDegraded                     = "audit.degraded"
	configAuditLastRecoveredAt              = "audit.last_recovered_at"
	configAuditRetentionDays                = "audit.retention_days"
	configAuditReviewReminderDays           = "audit.review_reminder_days"
	configAuthPasswordHistoryCount          = "auth.password_history_count"
	configAuthTemporaryPasswordTTLHours     = "auth.temporary_password_ttl_hours"
	configAuditLoginFailureThreshold        = "audit.threshold.login_failures_per_hour"
	configAuditRegistrationFailureThreshold = "audit.threshold.registration_failures_per_hour"
	configAuditPrivilegedActionThreshold    = "audit.threshold.privileged_actions_per_hour"
)

func (s *Store) GetAuditHealth() (model.AuditHealth, error) {
	health := model.AuditHealth{}
	health.FailureCount = s.getConfigIntDefault(configAuditFailureCount, 0)
	health.Degraded = s.getConfigBoolDefault(configAuditDegraded, false)
	if v := s.getConfigString(configAuditLastFailureAt); v != "" {
		health.LastFailureAt = &v
	}
	if v := s.getConfigString(configAuditLastFailureReason); v != "" {
		health.LastFailureReason = &v
	}
	if v := s.getConfigString(configAuditLastRecoveredAt); v != "" {
		health.LastRecoveredAt = &v
	}
	return health, nil
}

func (s *Store) GetAuditSettings() model.AuditSettings {
	return model.AuditSettings{
		RetentionDays:             s.getConfigIntDefault(configAuditRetentionDays, 90),
		ReviewReminderDays:        s.getConfigIntDefault(configAuditReviewReminderDays, 7),
		PasswordHistoryCount:      s.getConfigIntDefault(configAuthPasswordHistoryCount, defaultPasswordHistoryLimit),
		TemporaryPasswordTTLHours: s.getConfigIntDefault(configAuthTemporaryPasswordTTLHours, 72),
		Thresholds: model.AuditThresholds{
			LoginFailuresPerHour:        s.getConfigIntDefault(configAuditLoginFailureThreshold, 10),
			RegistrationFailuresPerHour: s.getConfigIntDefault(configAuditRegistrationFailureThreshold, 5),
			PrivilegedActionsPerHour:    s.getConfigIntDefault(configAuditPrivilegedActionThreshold, 20),
		},
	}
}

func (s *Store) UpdateAuditSettings(settings model.AuditSettings) error {
	values := map[string]string{
		configAuditRetentionDays:                strconv.Itoa(settings.RetentionDays),
		configAuditReviewReminderDays:           strconv.Itoa(settings.ReviewReminderDays),
		configAuthPasswordHistoryCount:          strconv.Itoa(settings.PasswordHistoryCount),
		configAuthTemporaryPasswordTTLHours:     strconv.Itoa(settings.TemporaryPasswordTTLHours),
		configAuditLoginFailureThreshold:        strconv.Itoa(settings.Thresholds.LoginFailuresPerHour),
		configAuditRegistrationFailureThreshold: strconv.Itoa(settings.Thresholds.RegistrationFailuresPerHour),
		configAuditPrivilegedActionThreshold:    strconv.Itoa(settings.Thresholds.PrivilegedActionsPerHour),
	}
	for key, value := range values {
		if err := s.SetConfig(key, value); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) noteAuditFailure(err error) {
	s.auditStateMu.Lock()
	wasDegraded := s.auditDegraded
	s.auditDegraded = true
	s.auditStateMu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	failureCount := s.getConfigIntDefault(configAuditFailureCount, 0) + 1
	_ = s.SetConfig(configAuditFailureCount, strconv.Itoa(failureCount))
	_ = s.SetConfig(configAuditLastFailureAt, now)
	_ = s.SetConfig(configAuditLastFailureReason, err.Error())
	_ = s.SetConfig(configAuditDegraded, "true")

	if !wasDegraded {
		if health, getErr := s.GetAuditHealth(); getErr == nil {
			s.auditStateMu.Lock()
			onFailure := s.onAuditFailure
			s.auditStateMu.Unlock()
			if onFailure != nil {
				onFailure(health)
			}
		}
	}
}

func (s *Store) noteAuditSuccess() {
	s.auditStateMu.Lock()
	wasDegraded := s.auditDegraded
	s.auditDegraded = false
	s.auditStateMu.Unlock()

	if !wasDegraded {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_ = s.SetConfig(configAuditDegraded, "false")
	_ = s.SetConfig(configAuditLastRecoveredAt, now)
	if health, err := s.GetAuditHealth(); err == nil {
		s.auditStateMu.Lock()
		onRecovery := s.onAuditRecovery
		s.auditStateMu.Unlock()
		if onRecovery != nil {
			onRecovery(health)
		}
	}
}

func (s *Store) getConfigString(key string) string {
	value, err := s.GetConfig(key)
	if err != nil {
		return ""
	}
	return value
}

func (s *Store) getConfigIntDefault(key string, fallback int) int {
	value, err := s.GetConfig(key)
	if err != nil {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func (s *Store) getConfigBoolDefault(key string, fallback bool) bool {
	value, err := s.GetConfig(key)
	if err != nil {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func ValidateAuditSettings(settings model.AuditSettings) error {
	if settings.RetentionDays < 1 || settings.RetentionDays > 3650 {
		return fmt.Errorf("retention_days must be between 1 and 3650")
	}
	if settings.ReviewReminderDays < 1 || settings.ReviewReminderDays > 365 {
		return fmt.Errorf("review_reminder_days must be between 1 and 365")
	}
	if settings.PasswordHistoryCount < 1 || settings.PasswordHistoryCount > 24 {
		return fmt.Errorf("password_history_count must be between 1 and 24")
	}
	if settings.TemporaryPasswordTTLHours < 1 || settings.TemporaryPasswordTTLHours > 24*30 {
		return fmt.Errorf("temporary_password_ttl_hours must be between 1 and 720")
	}
	if settings.Thresholds.LoginFailuresPerHour < 1 || settings.Thresholds.LoginFailuresPerHour > 10000 {
		return fmt.Errorf("login_failures_per_hour must be between 1 and 10000")
	}
	if settings.Thresholds.RegistrationFailuresPerHour < 1 || settings.Thresholds.RegistrationFailuresPerHour > 10000 {
		return fmt.Errorf("registration_failures_per_hour must be between 1 and 10000")
	}
	if settings.Thresholds.PrivilegedActionsPerHour < 1 || settings.Thresholds.PrivilegedActionsPerHour > 10000 {
		return fmt.Errorf("privileged_actions_per_hour must be between 1 and 10000")
	}
	return nil
}
