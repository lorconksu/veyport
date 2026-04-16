package model

import "time"

type AuditEntry struct {
	ID            string    `json:"id"`
	UserID        *string   `json:"user_id"`
	Action        string    `json:"action"`
	Target        *string   `json:"target"`
	Detail        *string   `json:"detail"`
	IPAddress     *string   `json:"ip_address"`
	Outcome       string    `json:"outcome"`
	ActorType     string    `json:"actor_type"`
	CorrelationID *string   `json:"correlation_id"`
	ResourceType  *string   `json:"resource_type"`
	PrevHash      string    `json:"prev_hash,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type AuditFilter struct {
	UserID        *string
	Action        *string
	Outcome       *string
	ActorType     *string
	CorrelationID *string
	ResourceType  *string
	From          *string // ISO 8601 datetime
	To            *string // ISO 8601 datetime
	Limit         int
	Offset        int
}

// Audit action constants
const (
	AuditUserLogin                 = "user.login"
	AuditUserLoginFailed           = "user.login_failed"
	AuditUserLoginTOTPFailed       = "user.login_totp_failed"
	AuditUserRegistered            = "user.registered"
	AuditUserTOTPSetup             = "user.totp_setup"
	AuditUserTOTPEnabled           = "user.totp_enabled"
	AuditUserTOTPDisabled          = "user.totp_disabled"
	AuditUserCreated               = "user.created"
	AuditUserTOTPReset             = "user.totp_reset"
	AuditUserPasswordChanged       = "user.password_changed"
	AuditUserPasswordReuseRejected = "user.password_reuse_rejected"
	AuditUserRoleUpdated           = "user.role_updated"
	AuditUserDeleted               = "user.deleted"
)

const (
	AuditServerCreated            = "server.created"
	AuditServerUpdated            = "server.updated"
	AuditServerDeleted            = "server.deleted"
	AuditServerBatchDeleted       = "server.batch_deleted"
	AuditServerRegistered         = "server.registered"
	AuditServerRegistrationFailed = "server.registration_failed"
	AuditServerConnected          = "server.connected"
	AuditServerDisconnected       = "server.disconnected"
	AuditServerUnregistered       = "server.unregistered"
)

// File access events
const (
	AuditFileRead    = "file.read"
	AuditPathGranted = "path.granted"
	AuditPathRevoked = "path.revoked"
)

const (
	AuditLogTailStarted = "log.tail_started"
)

const (
	AuditFileUploaded = "file.uploaded"
)

const (
	AuditAPITokenCreated = "api_token.created"
	AuditAPITokenRevoked = "api_token.revoked"
)

const (
	AuditAuditExported          = "audit.exported"
	AuditAuditReviewCompleted   = "audit.review_completed"
	AuditAuditFilterSaved       = "audit.filter_saved"
	AuditAuditFilterDeleted     = "audit.filter_deleted"
	AuditAuditRetentionUpdated  = "audit.retention_updated"
	AuditAuditRetentionExecuted = "audit.retention_executed"
	AuditAuditFlagCreated       = "audit.flag_created"
)

const (
	AuditOutcomeSuccess = "success"
	AuditOutcomeFailure = "failure"
)

const (
	AuditActorTypeUser      = "user"
	AuditActorTypeDevice    = "device"
	AuditActorTypeAnonymous = "anonymous"
	AuditActorTypeSystem    = "system"
)
