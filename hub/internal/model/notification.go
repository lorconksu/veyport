package model

// NotifyTimestampFormat is the standard timestamp layout used in notification context maps.
const NotifyTimestampFormat = "2006-01-02 15:04:05 UTC"

// Notification event types
const (
	NotifyAgentOffline    = "agent.offline"
	NotifyAgentOnline     = "agent.online"
	NotifyAgentRegistered = "agent.registered"
	NotifyLoginFailed     = "security.login_failed"
	NotifyAccountLocked   = "security.account_locked"
	NotifyUserCreated     = "security.user_created"
	NotifyTOTPChanged     = "security.totp_changed"
	NotifyPasswordChanged = "security.password_changed"
	NotifyFileUploaded    = "system.file_uploaded"
	NotifyAuditDegraded   = "security.audit_degraded"
	NotifyAuditRecovered  = "security.audit_recovered"
)

// AllNotifyEvents lists every event type with its default enabled state and display label.
var AllNotifyEvents = []NotifyEventDef{
	{Type: NotifyAgentOffline, Label: "Agent went offline", Category: "Agent", DefaultOn: true},
	{Type: NotifyAgentOnline, Label: "Agent came online", Category: "Agent", DefaultOn: false},
	{Type: NotifyAgentRegistered, Label: "New agent enrolled", Category: "Agent", DefaultOn: true},
	{Type: NotifyLoginFailed, Label: "Failed login attempt", Category: "Security", DefaultOn: true},
	{Type: NotifyAccountLocked, Label: "Account locked after repeated failures", Category: "Security", DefaultOn: true},
	{Type: NotifyUserCreated, Label: "New user created", Category: "Security", DefaultOn: true},
	{Type: NotifyTOTPChanged, Label: "2FA configuration changed", Category: "Security", DefaultOn: true},
	{Type: NotifyPasswordChanged, Label: "Password changed", Category: "Security", DefaultOn: false},
	{Type: NotifyAuditDegraded, Label: "Audit pipeline degraded", Category: "Security", DefaultOn: true},
	{Type: NotifyAuditRecovered, Label: "Audit pipeline recovered", Category: "Security", DefaultOn: true},
	{Type: NotifyFileUploaded, Label: "File uploaded", Category: "System", DefaultOn: false},
}

type NotifyEventDef struct {
	Type      string `json:"type"`
	Label     string `json:"label"`
	Category  string `json:"category"`
	DefaultOn bool   `json:"default_on"`
}

type NotificationPreference struct {
	EventType string `json:"event_type"`
	Label     string `json:"label"`
	Category  string `json:"category"`
	Enabled   bool   `json:"enabled"`
}

type NotificationLogEntry struct {
	ID        string  `json:"id"`
	UserID    string  `json:"user_id"`
	Username  string  `json:"username"`
	EventType string  `json:"event_type"`
	Subject   string  `json:"subject"`
	Status    string  `json:"status"`
	Error     *string `json:"error"`
	CreatedAt string  `json:"created_at"`
}

type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	TLS      bool   `json:"tls"`
	Enabled  bool   `json:"enabled"`
}

type SMTPTestRequest struct {
	Recipient string `json:"recipient"`
}

type NotificationPreferencesRequest struct {
	Preferences []NotificationPrefUpdate `json:"preferences"`
}

type NotificationPrefUpdate struct {
	EventType string `json:"event_type"`
	Enabled   bool   `json:"enabled"`
}
