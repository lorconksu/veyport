package model

import (
	"encoding/json"
	"time"
)

const (
	RoleSecurityOfficer  Role = "security-officer"
	RoleSecurityApprover Role = "security-approver"
	RoleOriginalReader   Role = "original-reader"
)

// Security roles are additive; the legacy role field retains its operational meaning.
func IsSecurityRole(role Role) bool {
	return role == RoleSecurityOfficer || role == RoleSecurityApprover || role == RoleOriginalReader
}
func IsAssignableRole(role Role) bool { return IsValidRole(role) || IsSecurityRole(role) }

type EffectiveCapabilities struct {
	UserID       string   `json:"user_id"`
	PersonID     string   `json:"person_id"`
	Roles        []Role   `json:"roles"`
	Capabilities []string `json:"capabilities"`
}

func (e EffectiveCapabilities) Can(capability string) bool {
	for _, c := range e.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}
func (e EffectiveCapabilities) HasRole(role Role) bool {
	for _, r := range e.Roles {
		if r == role {
			return true
		}
	}
	return false
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

func (p AuditPolicy) Covers(actor, node string) bool {
	if p.Profile != "enhanced" {
		return false
	}
	if len(p.Actors) == 0 && len(p.Nodes) == 0 {
		return true
	}
	for _, id := range p.Actors {
		if id == actor {
			return true
		}
	}
	for _, id := range p.Nodes {
		if id == node {
			return true
		}
	}
	return false
}

type ExecutionPolicy struct {
	Version          uint64 `json:"version"`
	SHA256           string `json:"sha256"`
	Enhanced         bool   `json:"enhanced"`
	RuntimeSeconds   int    `json:"runtime_seconds"`
	RecoveryRequired bool   `json:"recovery_required"`
}
type PolicyVersion struct {
	Version   uint64      `json:"version"`
	Policy    AuditPolicy `json:"policy"`
	SHA256    string      `json:"sha256"`
	RequestID string      `json:"request_id,omitempty"`
}
type PolicyState struct {
	Active        PolicyVersion  `json:"active"`
	Pending       *PolicyVersion `json:"pending,omitempty"`
	State         string         `json:"state"`
	Previous      *PolicyVersion `json:"previous,omitempty"`
	PendingChange string         `json:"pending_change,omitempty"`
}
type SecurityNomination struct {
	UserID       string `json:"user_id"`
	PersonID     string `json:"person_id"`
	Roles        []Role `json:"roles"`
	Verification string `json:"verification"`
}
type SecurityRoleChange struct {
	UserID string `json:"user_id"`
	Role   Role   `json:"role"`
	Grant  bool   `json:"grant"`
}
type SecurityPersonChange struct {
	UserID       string `json:"user_id"`
	PersonID     string `json:"person_id"`
	Verification string `json:"verification"`
}
type SecurityRecovery struct {
	UserID               string `json:"user_id"`
	Operation            string `json:"operation"`
	SecretRef            string `json:"secret_ref,omitempty"`
	PreparedPasswordHash string `json:"-"`
}
type SecurityChangePayload struct {
	Kind           string                `json:"kind"`
	Policy         *AuditPolicy          `json:"policy,omitempty"`
	Nominations    []SecurityNomination  `json:"nominations,omitempty"`
	Role           *SecurityRoleChange   `json:"role,omitempty"`
	Person         *SecurityPersonChange `json:"person,omitempty"`
	AuditSettings  *AuditSettings        `json:"audit_settings,omitempty"`
	LDAP           *SecurityLDAPSettings `json:"ldap,omitempty"`
	PreparedConfig map[string]string     `json:"-"`
	Recovery       *SecurityRecovery     `json:"recovery,omitempty"`
}
type SecurityApproval struct {
	UserID          string     `json:"user_id"`
	PersonID        string     `json:"person_id"`
	ProofSHA256     string     `json:"proof_sha256"`
	ApprovedAt      time.Time  `json:"approved_at"`
	TokenGeneration int        `json:"-"`
	InvalidatedAt   *time.Time `json:"invalidated_at,omitempty"`
}
type SecurityChange struct {
	ID                  string             `json:"id"`
	Revision            int                `json:"revision"`
	RequesterID         string             `json:"requester_id"`
	RequesterPersonID   string             `json:"requester_person_id"`
	ApplierID           string             `json:"applier_id,omitempty"`
	ApplierPersonID     string             `json:"applier_person_id,omitempty"`
	ApplierRevision     int                `json:"-"`
	RequesterGeneration int                `json:"-"`
	ExpectedVersion     uint64             `json:"expected_version"`
	Digest              string             `json:"digest"`
	Reason              string             `json:"reason"`
	Payload             json.RawMessage    `json:"change"`
	ApprovedBytes       []byte             `json:"-"`
	State               string             `json:"state"`
	CreatedAt           time.Time          `json:"created_at"`
	ExpiresAt           time.Time          `json:"expires_at"`
	Approvals           []SecurityApproval `json:"approvals"`
	IntentRef           string             `json:"intent_ref,omitempty"`
	CommitRef           string             `json:"commit_ref,omitempty"`
	ResultRef           string             `json:"result_ref,omitempty"`
}

// SecurityLDAPSettings carries versioned references instead of password values.
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
