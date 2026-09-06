package model

import "time"

// Session kind constants. "web" and "cli" are persisted rows in the
// sessions table; "ssh" and "terminal" identify shell entries surfaced from
// the terminal-session registry (see grpcserver.TerminalSessions) and are
// never written to the sessions table itself (the CHECK constraint on
// sessions.kind only allows web/cli).
const (
	SessionKindWeb      = "web"
	SessionKindCLI      = "cli"
	SessionKindSSH      = "ssh"
	SessionKindTerminal = "terminal"
)

// Session end-reason constants.
const (
	SessionEndRevokedAdmin    = "revoked_admin"
	SessionEndRevokedSelf     = "revoked_self"
	SessionEndRevokedDisable  = "revoked_disable"
	SessionEndLogout          = "logout"
	SessionEndExpiredIdle     = "expired_idle"
	SessionEndExpiredAbsolute = "expired_absolute"
)

// Session is a server-side record of a signed-in session (web or CLI) or,
// for shell rows sourced from the terminal-session registry, an open SSH or
// web-terminal shell. See specs/009-session-records/data-model.md.
type Session struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	Kind           string     `json:"kind"`
	IP             string     `json:"ip"`
	UserAgent      string     `json:"user_agent"`
	CreatedAt      time.Time  `json:"created_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	IdleDeadlineAt *time.Time `json:"idle_deadline_at,omitempty"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
	EndReason      string     `json:"end_reason,omitempty"`
	EndedBy        *string    `json:"ended_by,omitempty"`
	Current        bool       `json:"current"`

	// Shell-only fields, populated from the terminal-session registry.
	Server         string     `json:"server,omitempty"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	LastActivityAt *time.Time `json:"last_activity_at,omitempty"`
}

// SessionListResponse is the payload for the session-listing endpoints.
type SessionListResponse struct {
	Sessions []Session `json:"sessions"`
}

// EndedCountResponse is the payload for bulk session-ending endpoints.
type EndedCountResponse struct {
	Ended        int `json:"ended"`
	ShellsClosed int `json:"shells_closed"`
}
