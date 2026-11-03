package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/wyiu/veyport/hub/internal/model"
)

const (
	configAuditRetentionDays                = "audit.retention_days"
	configAuditReviewReminderDays           = "audit.review_reminder_days"
	configAuthPasswordHistoryCount          = "auth.password_history_count"
	configAuthTemporaryPasswordTTLHours     = "auth.temporary_password_ttl_hours"
	configAuditLoginFailureThreshold        = "audit.threshold.login_failures_per_hour"
	configAuditRegistrationFailureThreshold = "audit.threshold.registration_failures_per_hour"
	configAuditPrivilegedActionThreshold    = "audit.threshold.privileged_actions_per_hour"
)

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

// UpdateAuditSettings is the trusted system entry point. HTTP callers must use
// UpdateAuditSettingsAudited to bind the write to live administrator authority.
func (s *Store) UpdateAuditSettings(settings model.AuditSettings) error {
	if err := ValidateAuditSettings(settings); err != nil {
		return err
	}
	appended := false
	err := s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		if err := guardStandardAuditSettings(ctx, conn); err != nil {
			return err
		}
		err := logAuditSettingsConn(ctx, conn, settings, model.AuditEntry{ActorType: model.AuditActorTypeSystem})
		appended = err == nil
		return err
	})
	s.noteAuditSettingsResult(err, appended)
	return err
}

func guardStandardAuditSettings(ctx context.Context, conn *sql.Conn) error {
	var allowed bool
	if err := conn.QueryRowContext(ctx, "SELECT state='standard' AND pending_version IS NULL FROM audit_policy_state WHERE id=1").Scan(&allowed); err != nil {
		return err
	}
	enrolled, err := governanceEnrolled(ctx, conn)
	if err != nil {
		return err
	}
	if !allowed || enrolled {
		return ErrProtectedChange
	}
	return nil
}

func AuditSettingsConfig(settings model.AuditSettings) map[string]string {
	return map[string]string{
		configAuditRetentionDays:                strconv.Itoa(settings.RetentionDays),
		configAuditReviewReminderDays:           strconv.Itoa(settings.ReviewReminderDays),
		configAuthPasswordHistoryCount:          strconv.Itoa(settings.PasswordHistoryCount),
		configAuthTemporaryPasswordTTLHours:     strconv.Itoa(settings.TemporaryPasswordTTLHours),
		configAuditLoginFailureThreshold:        strconv.Itoa(settings.Thresholds.LoginFailuresPerHour),
		configAuditRegistrationFailureThreshold: strconv.Itoa(settings.Thresholds.RegistrationFailuresPerHour),
		configAuditPrivilegedActionThreshold:    strconv.Itoa(settings.Thresholds.PrivilegedActionsPerHour),
	}
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
