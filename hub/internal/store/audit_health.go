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

const (
	configAuditFailureCount      = "audit.failure_count"
	configAuditLastFailureAt     = "audit.last_failure_at"
	configAuditLastFailureReason = "audit.last_failure_reason"
	configAuditDegraded          = "audit.degraded"
	configAuditLastRecoveredAt   = "audit.last_recovered_at"
)

func (s *Store) GetAuditHealth() (model.AuditHealth, error) {
	s.auditStateMu.Lock()
	defer s.auditStateMu.Unlock()

	health, err := s.readAuditHealth()
	if err == nil && !s.auditHealthDirty {
		s.auditHealth = health
	}
	health = cloneAuditHealth(s.auditHealth)
	err = errors.Join(err, s.auditHealthErr)
	if err != nil {
		// Callers must never mistake an unavailable or corrupt status store
		// for a healthy audit subsystem, even if they ignore the error.
		health.Degraded = true
	}
	return health, err
}

// Read all status keys in one snapshot. Only absent keys get initial defaults;
// settings' permissive default helpers must not conceal status read failures.
func (s *Store) readAuditHealth() (model.AuditHealth, error) {
	rows, err := s.db.Query(`SELECT key, value FROM _config WHERE key IN (?, ?, ?, ?, ?)`,
		configAuditFailureCount, configAuditDegraded, configAuditLastFailureAt,
		configAuditLastFailureReason, configAuditLastRecoveredAt)
	if err != nil {
		return model.AuditHealth{}, fmt.Errorf("read audit health: %w", err)
	}
	defer rows.Close()
	values := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return model.AuditHealth{}, fmt.Errorf("read audit health: %w", err)
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		return model.AuditHealth{}, fmt.Errorf("read audit health: %w", err)
	}
	return parseAuditHealth(values)
}

func parseAuditHealth(values map[string]string) (model.AuditHealth, error) {
	var health model.AuditHealth
	var err error
	if value, ok := values[configAuditFailureCount]; ok {
		health.FailureCount, err = strconv.Atoi(value)
		if err != nil || health.FailureCount < 0 {
			return health, fmt.Errorf("invalid audit health %s: expected nonnegative integer", configAuditFailureCount)
		}
	}
	if value, ok := values[configAuditDegraded]; ok {
		health.Degraded, err = strconv.ParseBool(value)
		if err != nil {
			return health, fmt.Errorf("invalid audit health %s: %w", configAuditDegraded, err)
		}
	}
	health.LastFailureAt, err = auditHealthTimestamp(configAuditLastFailureAt, values[configAuditLastFailureAt])
	if err != nil {
		return health, err
	}
	health.LastRecoveredAt, err = auditHealthTimestamp(configAuditLastRecoveredAt, values[configAuditLastRecoveredAt])
	if value := values[configAuditLastFailureReason]; value != "" {
		health.LastFailureReason = &value
	}
	return health, err
}

func auditHealthTimestamp(key, value string) (*string, error) {
	if value == "" {
		return nil, nil
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return nil, fmt.Errorf("invalid audit health %s: %w", key, err)
	}
	return &value, nil
}

// The mutex serializes the read/update/write sequence and preserves failures
// locally when storage is unavailable. Observers always run after unlocking.
func (s *Store) noteAuditFailure(failure error) {
	s.auditStateMu.Lock()
	health, err := s.readAuditHealth()
	if err == nil && !s.auditHealthDirty {
		s.auditHealth = health
	}
	wasDegraded := s.auditHealth.Degraded
	now, reason := time.Now().UTC().Format(time.RFC3339), failure.Error()
	s.auditHealth.Degraded = true
	s.auditHealth.FailureCount++
	s.auditHealth.LastFailureAt = &now
	s.auditHealth.LastFailureReason = &reason
	if err == nil {
		err = s.persistAuditHealth(s.auditHealth)
	}
	s.auditHealthErr = err
	s.auditHealthDirty = err != nil
	onFailure, snapshot := s.onAuditFailure, cloneAuditHealth(s.auditHealth)
	s.auditStateMu.Unlock()
	if !wasDegraded && onFailure != nil {
		onFailure(snapshot)
	}
}

func (s *Store) noteAuditSuccess() {
	s.auditStateMu.Lock()
	if !s.auditHealth.Degraded && !s.auditHealthDirty {
		s.auditStateMu.Unlock()
		return
	}
	health, err := s.readAuditHealth()
	if err == nil {
		if s.auditHealthDirty {
			health = s.auditHealth
		}
		now := time.Now().UTC().Format(time.RFC3339)
		health.Degraded = false
		health.LastRecoveredAt = &now
		err = s.persistAuditHealth(health)
	}
	s.auditHealthErr = err
	s.auditHealthDirty = err != nil
	if err != nil {
		// A successful log write cannot recover status that could not be
		// read or durably updated. Keep the previous failure and retry later.
		s.auditStateMu.Unlock()
		return
	}
	s.auditHealth = health
	onRecovery, snapshot := s.onAuditRecovery, cloneAuditHealth(health)
	s.auditStateMu.Unlock()
	if onRecovery != nil {
		onRecovery(snapshot)
	}
}

func (s *Store) persistAuditHealth(health model.AuditHealth) error {
	values := []struct{ key, value string }{
		{configAuditFailureCount, strconv.Itoa(health.FailureCount)},
		{configAuditDegraded, strconv.FormatBool(health.Degraded)},
		{configAuditLastFailureAt, auditHealthString(health.LastFailureAt)},
		{configAuditLastFailureReason, auditHealthString(health.LastFailureReason)},
		{configAuditLastRecoveredAt, auditHealthString(health.LastRecoveredAt)},
	}
	err := s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		for _, value := range values {
			if _, err := conn.ExecContext(ctx, `INSERT INTO _config(key,value) VALUES(?,?)
				ON CONFLICT(key) DO UPDATE SET value=excluded.value`, value.key, value.value); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("persist audit health: %w", err)
	}
	return nil
}

func auditHealthString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// Snapshots may be retained or changed by callers; don't expose cached pointers.
func cloneAuditHealth(health model.AuditHealth) model.AuditHealth {
	for _, value := range []**string{&health.LastFailureAt, &health.LastFailureReason, &health.LastRecoveredAt} {
		if *value != nil {
			copied := **value
			*value = &copied
		}
	}
	return health
}
