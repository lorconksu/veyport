package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

// UpdateAuditSettingsAudited commits the settings and their success record only
// while the administrator's authority and Standard-mode guard remain valid.
func (s *Store) UpdateAuditSettingsAudited(settings model.AuditSettings, now time.Time, entry model.AuditEntry, actor AccountManagementActor) error {
	if err := ValidateAuditSettings(settings); err != nil {
		return err
	}
	entry.UserID = &actor.UserID
	entry.ActorType = model.AuditActorTypeUser
	appended := false
	err := s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		if err := guardAdministratorActor(ctx, conn, []AccountManagementActor{actor}, clock, false); err != nil {
			return err
		}
		if err := guardStandardAuditSettings(ctx, conn); err != nil {
			return err
		}
		err := logAuditSettingsConn(ctx, conn, settings, entry)
		appended = err == nil
		if err != nil {
			return err
		}
		return guardAdministratorActor(ctx, conn, []AccountManagementActor{actor}, clock, false)
	})
	s.noteAuditSettingsResult(err, appended)
	return err
}

func auditSettingsConn(ctx context.Context, conn *sql.Conn) (model.AuditSettings, error) {
	settings := model.AuditSettings{RetentionDays: 90, ReviewReminderDays: 7,
		PasswordHistoryCount: defaultPasswordHistoryLimit, TemporaryPasswordTTLHours: 72,
		Thresholds: model.AuditThresholds{LoginFailuresPerHour: 10, RegistrationFailuresPerHour: 5, PrivilegedActionsPerHour: 20}}
	values := []struct {
		key   string
		value *int
	}{
		{configAuditRetentionDays, &settings.RetentionDays},
		{configAuditReviewReminderDays, &settings.ReviewReminderDays},
		{configAuthPasswordHistoryCount, &settings.PasswordHistoryCount},
		{configAuthTemporaryPasswordTTLHours, &settings.TemporaryPasswordTTLHours},
		{configAuditLoginFailureThreshold, &settings.Thresholds.LoginFailuresPerHour},
		{configAuditRegistrationFailureThreshold, &settings.Thresholds.RegistrationFailuresPerHour},
		{configAuditPrivilegedActionThreshold, &settings.Thresholds.PrivilegedActionsPerHour},
	}
	for _, item := range values {
		var raw string
		err := conn.QueryRowContext(ctx, "SELECT value FROM _config WHERE key=?", item.key).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return model.AuditSettings{}, fmt.Errorf("read audit setting %s: %w", item.key, err)
		}
		value, err := strconv.Atoi(raw)
		if err != nil {
			return model.AuditSettings{}, fmt.Errorf("parse audit setting %s: %w", item.key, err)
		}
		*item.value = value
	}
	return settings, nil
}

// logAuditSettingsConn reads the effective before values, changes all settings,
// and appends one audit record using the caller's existing writer transaction.
func logAuditSettingsConn(ctx context.Context, conn *sql.Conn, settings model.AuditSettings, entry model.AuditEntry) error {
	previous, err := auditSettingsConn(ctx, conn)
	if err != nil {
		return err
	}
	for key, value := range AuditSettingsConfig(settings) {
		if _, err := conn.ExecContext(ctx, "INSERT INTO _config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value); err != nil {
			return err
		}
	}
	entry.Action = model.AuditAuditRetentionUpdated
	entry.Outcome = model.AuditOutcomeSuccess
	resource := "audit"
	entry.ResourceType = &resource
	entry.Detail = auditDetail(struct {
		Before model.AuditSettings `json:"before"`
		After  model.AuditSettings `json:"after"`
	}{Before: previous, After: settings})
	if err := logAuditConn(ctx, conn, entry); err != nil {
		return &auditSettingsPersistenceError{err: err}
	}
	return nil
}

type auditSettingsPersistenceError struct{ err error }

func (e *auditSettingsPersistenceError) Error() string { return e.err.Error() }
func (e *auditSettingsPersistenceError) Unwrap() error { return e.err }

// Rejected authority, policy, configuration reads and settings writes do not
// recover audit health or claim an audit persistence failure.
func (s *Store) noteAuditSettingsResult(err error, appended bool) {
	if err == nil && appended {
		s.noteAuditSuccess()
		return
	}
	var appendFailure *auditSettingsPersistenceError
	var commitFailure *transactionCommitError
	if errors.As(err, &appendFailure) || appended && errors.As(err, &commitFailure) {
		s.noteAuditFailure(err)
	}
}
