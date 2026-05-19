package store

import (
	"fmt"

	"github.com/wyiu/veyport/hub/internal/model"
)

// GetNotificationPreferences returns all event types with the user's enabled/disabled state.
// Explicit overrides from the DB are merged with the defaults from model.AllNotifyEvents.
func (s *Store) GetNotificationPreferences(userID string) ([]model.NotificationPreference, error) {
	rows, err := s.db.Query(
		`SELECT event_type, enabled FROM notification_preferences WHERE user_id = ?`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("query notification preferences: %w", err)
	}
	defer rows.Close()

	overrides := make(map[string]bool)
	for rows.Next() {
		var eventType string
		var enabled bool
		if err := rows.Scan(&eventType, &enabled); err != nil {
			return nil, fmt.Errorf("scan notification preference: %w", err)
		}
		overrides[eventType] = enabled
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notification preferences: %w", err)
	}

	prefs := make([]model.NotificationPreference, 0, len(model.AllNotifyEvents))
	for _, def := range model.AllNotifyEvents {
		enabled := def.DefaultOn
		if override, ok := overrides[def.Type]; ok {
			enabled = override
		}
		prefs = append(prefs, model.NotificationPreference{
			EventType: def.Type,
			Label:     def.Label,
			Category:  def.Category,
			Enabled:   enabled,
		})
	}
	return prefs, nil
}

// SetNotificationPreference upserts a preference row for the given user and event type.
func (s *Store) SetNotificationPreference(userID, eventType string, enabled bool) error {
	_, err := s.db.Exec(
		`INSERT INTO notification_preferences (user_id, event_type, enabled)
		 VALUES (?, ?, ?)
		 ON CONFLICT(user_id, event_type) DO UPDATE SET enabled = excluded.enabled`,
		userID, eventType, enabled,
	)
	if err != nil {
		return fmt.Errorf("set notification preference: %w", err)
	}
	return nil
}

// NotificationRecipient holds the minimal fields needed for sending notifications.
// This avoids loading sensitive fields (password_hash, totp_secret) into memory.
type NotificationRecipient struct {
	ID    string
	Email string
}

// GetEnabledRecipients returns the users who should receive notifications for the given event type.
// For default-on events: all users EXCEPT those who explicitly disabled it.
// For default-off events: only users who explicitly enabled it.
// Only returns id and email — no sensitive fields are loaded.
func (s *Store) GetEnabledRecipients(eventType string) ([]NotificationRecipient, error) {
	// Look up the default state for this event
	defaultOn := false
	for _, def := range model.AllNotifyEvents {
		if def.Type == eventType {
			defaultOn = def.DefaultOn
			break
		}
	}

	var (
		query string
		args  []interface{}
	)

	if defaultOn {
		// All users EXCEPT those who explicitly disabled
		query = `SELECT id, email FROM users
		         WHERE id NOT IN (
		             SELECT user_id FROM notification_preferences
		             WHERE event_type = ? AND enabled = 0
		         )
		         ORDER BY created_at ASC`
		args = []interface{}{eventType}
	} else {
		// Only users who explicitly enabled
		query = `SELECT id, email FROM users
		         WHERE id IN (
		             SELECT user_id FROM notification_preferences
		             WHERE event_type = ? AND enabled = 1
		         )
		         ORDER BY created_at ASC`
		args = []interface{}{eventType}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query enabled recipients: %w", err)
	}
	defer rows.Close()

	var recipients []NotificationRecipient
	for rows.Next() {
		var r NotificationRecipient
		if err := rows.Scan(&r.ID, &r.Email); err != nil {
			return nil, fmt.Errorf("scan notification recipient: %w", err)
		}
		recipients = append(recipients, r)
	}
	return recipients, rows.Err()
}

// LogNotification inserts a notification delivery log entry.
func (s *Store) LogNotification(id, userID, eventType, subject, status string, errMsg *string) error {
	_, err := s.db.Exec(
		`INSERT INTO notification_log (id, user_id, event_type, subject, status, error)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, userID, eventType, subject, status, errMsg,
	)
	if err != nil {
		return fmt.Errorf("log notification: %w", err)
	}
	return nil
}

// ListNotificationLog returns paginated notification log entries with usernames joined,
// plus the total count of all entries.
func (s *Store) ListNotificationLog(limit, offset int) ([]model.NotificationLogEntry, int, error) {
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notification_log`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count notification log: %w", err)
	}

	rows, err := s.db.Query(
		`SELECT nl.id, nl.user_id, COALESCE(u.username, nl.user_id), nl.event_type, nl.subject, nl.status, nl.error, nl.created_at
		 FROM notification_log nl
		 LEFT JOIN users u ON u.id = nl.user_id
		 ORDER BY nl.created_at DESC
		 LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("query notification log: %w", err)
	}
	defer rows.Close()

	var entries []model.NotificationLogEntry
	for rows.Next() {
		var e model.NotificationLogEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.EventType, &e.Subject, &e.Status, &e.Error, &e.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan notification log entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}
