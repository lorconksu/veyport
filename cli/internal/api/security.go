package api

import (
	"encoding/json"
	"time"
)

// These types mirror the published governance API. Secret values and step-up
// proofs are deliberately absent from printable response types. Change remains
// raw to preserve the server's canonical bytes; commands validate its typed
// allowlist before displaying or submitting it.
type SecurityProposal struct {
	Reason          string          `json:"reason"`
	ExpectedVersion uint64          `json:"expected_version"`
	Change          json.RawMessage `json:"change"`
}

type SecurityPreview struct {
	Digest   string           `json:"digest"`
	Proposal SecurityProposal `json:"proposal"`
}

type AuditPolicy struct {
	Profile             string   `json:"profile"`
	Actors              []string `json:"actors"`
	Nodes               []string `json:"nodes"`
	RuntimeSeconds      int      `json:"runtime_seconds"`
	RetentionHours      int      `json:"retention_hours"`
	Destination         string   `json:"destination"`
	CredentialRef       string   `json:"credential_ref"`
	TrustKeyIDs         []string `json:"trust_key_ids"`
	QualificationSHA256 string   `json:"qualification_sha256"`
}

type SecurityNomination struct {
	UserID       string   `json:"user_id"`
	PersonID     string   `json:"person_id"`
	Roles        []string `json:"roles"`
	Verification string   `json:"verification"`
}

type SecurityRoleChange struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	Grant  bool   `json:"grant"`
}

type SecurityPersonChange struct {
	UserID       string `json:"user_id"`
	PersonID     string `json:"person_id"`
	Verification string `json:"verification"`
}

type SecurityRecovery struct {
	UserID    string `json:"user_id"`
	Operation string `json:"operation"`
	SecretRef string `json:"secret_ref,omitempty"`
}

type SecurityAuditSettings struct {
	RetentionDays             int `json:"retention_days"`
	ReviewReminderDays        int `json:"review_reminder_days"`
	PasswordHistoryCount      int `json:"password_history_count"`
	TemporaryPasswordTTLHours int `json:"temporary_password_ttl_hours"`
	Thresholds                struct {
		LoginFailuresPerHour        int `json:"login_failures_per_hour"`
		RegistrationFailuresPerHour int `json:"registration_failures_per_hour"`
		PrivilegedActionsPerHour    int `json:"privileged_actions_per_hour"`
	} `json:"thresholds"`
}

type SecurityLDAPSettings struct {
	Enabled             bool     `json:"enabled"`
	URL                 string   `json:"url"`
	BindDN              string   `json:"bind_dn"`
	BindCredentialRef   string   `json:"bind_credential_ref"`
	ClearBindPassword   bool     `json:"clear_bind_password"`
	UserBaseDN          string   `json:"user_base_dn"`
	GroupBaseDN         string   `json:"group_base_dn"`
	UserSearchFilter    string   `json:"user_search_filter"`
	GroupSearchFilter   string   `json:"group_search_filter"`
	UsernameAttribute   string   `json:"username_attribute"`
	EmailAttribute      string   `json:"email_attribute"`
	ExternalIDAttribute string   `json:"external_id_attribute"`
	GroupNameAttribute  string   `json:"group_name_attribute"`
	StartTLS            bool     `json:"start_tls"`
	TLSServerName       string   `json:"tls_server_name"`
	CACertPEM           string   `json:"ca_cert_pem"`
	AdminGroups         []string `json:"admin_groups"`
	AuditorGroups       []string `json:"auditor_groups"`
	ViewerGroups        []string `json:"viewer_groups"`
	TerminalGroups      []string `json:"terminal_groups"`
}

type SecurityPayload struct {
	Kind          string                 `json:"kind"`
	Policy        *AuditPolicy           `json:"policy,omitempty"`
	Nominations   []SecurityNomination   `json:"nominations,omitempty"`
	Role          *SecurityRoleChange    `json:"role,omitempty"`
	Person        *SecurityPersonChange  `json:"person,omitempty"`
	AuditSettings *SecurityAuditSettings `json:"audit_settings,omitempty"`
	LDAP          *SecurityLDAPSettings  `json:"ldap,omitempty"`
	Recovery      *SecurityRecovery      `json:"recovery,omitempty"`
}

type SecurityApproval struct {
	UserID        string     `json:"user_id"`
	PersonID      string     `json:"person_id"`
	ProofSHA256   string     `json:"proof_sha256"`
	ApprovedAt    time.Time  `json:"approved_at"`
	InvalidatedAt *time.Time `json:"invalidated_at,omitempty"`
}

type SecurityChange struct {
	ID                string             `json:"id"`
	Revision          int                `json:"revision"`
	RequesterID       string             `json:"requester_id"`
	RequesterPersonID string             `json:"requester_person_id"`
	ApplierID         string             `json:"applier_id,omitempty"`
	ApplierPersonID   string             `json:"applier_person_id,omitempty"`
	ExpectedVersion   uint64             `json:"expected_version"`
	Digest            string             `json:"digest"`
	Reason            string             `json:"reason"`
	Change            json.RawMessage    `json:"change"`
	State             string             `json:"state"`
	CreatedAt         time.Time          `json:"created_at"`
	ExpiresAt         time.Time          `json:"expires_at"`
	Approvals         []SecurityApproval `json:"approvals"`
	IntentRef         string             `json:"intent_ref,omitempty"`
	CommitRef         string             `json:"commit_ref,omitempty"`
	ResultRef         string             `json:"result_ref,omitempty"`
}

type SecurityChangesPage struct {
	Changes []SecurityChange `json:"changes"`
	Limit   int              `json:"limit"`
	Offset  int              `json:"offset"`
}

type SecurityPolicyVersion struct {
	Version   uint64      `json:"version"`
	Policy    AuditPolicy `json:"policy"`
	SHA256    string      `json:"sha256"`
	RequestID string      `json:"request_id,omitempty"`
}

type SecurityPolicyStatus struct {
	Policy        *SecurityPolicyVersion `json:"policy,omitempty"`
	Pending       *SecurityPolicyVersion `json:"pending,omitempty"`
	Version       uint64                 `json:"version,omitempty"`
	Profile       string                 `json:"profile,omitempty"`
	State         string                 `json:"state"`
	Capabilities  []string               `json:"capabilities"`
	CredentialSet bool                   `json:"credential_set"`
	Readiness     *struct {
		Governance          bool `json:"governance"`
		ArchiveAndTransport bool `json:"archive_and_transport"`
		EnrollmentMarker    bool `json:"enrollment_marker"`
	} `json:"readiness,omitempty"`
}
