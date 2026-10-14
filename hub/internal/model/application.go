package model

import "time"

type Application struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	Description    string    `json:"description"`
	PublicHostname string    `json:"public_hostname"`
	Route          string    `json:"route"`
	NodeID         string    `json:"node_id,omitempty"`
	BackendURL     string    `json:"backend_url"`
	AllowedCIDRs   []string  `json:"allowed_cidrs"`
	CAPEM          string    `json:"ca_pem,omitempty"`
	Enabled        bool      `json:"enabled"`
	ConfigVersion  int64     `json:"config_version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
type ApplicationGrant struct {
	Kind      string `json:"kind"`
	SubjectID string `json:"subject_id"`
}
type ApplicationGroup struct {
	MemberCount int      `json:"member_count"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	UserIDs     []string `json:"user_ids"`
	Version     int64    `json:"version"`
}
type ApplicationAnchor struct {
	ID, UserID      string
	CompletedMFAAt  time.Time
	TokenGeneration int
	RevokedAt       *time.Time
}
type ApplicationLaunchTicket struct {
	Digest, ApplicationID, UserID, AnchorID, Hostname, Path, DirectoryFingerprint string
	ConfigVersion, AccessRevision                                                 int64
	ExpiresAt                                                                     time.Time
}
type ApplicationSession struct {
	ApplicationName      string     `json:"application_name,omitempty"`
	IdleDeadlineAt       *time.Time `json:"idle_deadline_at,omitempty"`
	ID                   string     `json:"id"`
	CredentialDigest     string     `json:"-"`
	ApplicationID        string     `json:"application_id"`
	UserID               string     `json:"user_id"`
	AnchorID             string     `json:"-"`
	ConfigVersion        int64      `json:"-"`
	AccessRevision       int64      `json:"-"`
	DirectoryFingerprint string     `json:"-"`
	CreatedAt            time.Time  `json:"created_at"`
	LastSeenAt           time.Time  `json:"last_seen_at"`
	ExpiresAt            time.Time  `json:"expires_at"`
	EndedAt              *time.Time `json:"ended_at,omitempty"`
	EndReason            string     `json:"end_reason,omitempty"`
}
