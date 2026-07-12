package model

const (
	AuditCatalogLastUpdated      = "2026-06-12T00:00:00Z"
	auditCategoryUserManagement  = "User Management"
	auditCategoryAgentLifecycle  = "Agent Lifecycle"
	auditCategoryFileAccess      = "File Access"
	auditCategoryAuditGovernance = "Audit Governance"
)

var AuditCatalog = []AuditCatalogEntry{
	{Action: AuditUserLogin, Label: "User login", Category: "Authentication", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "user"},
	{Action: AuditUserLoginFailed, Label: "User login failed", Category: "Authentication", Outcome: AuditOutcomeFailure, ActorType: AuditActorTypeAnonymous, ResourceType: "user"},
	{Action: AuditUserLoginTOTPFailed, Label: "User TOTP failed", Category: "Authentication", Outcome: AuditOutcomeFailure, ActorType: AuditActorTypeUser, ResourceType: "user"},
	{Action: AuditUserRegistered, Label: "Initial admin registered", Category: "Authentication", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeAnonymous, ResourceType: "user"},
	{Action: AuditUserTOTPSetup, Label: "TOTP setup started", Category: "Authentication", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "user"},
	{Action: AuditUserTOTPEnabled, Label: "TOTP enabled", Category: "Authentication", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "user"},
	{Action: AuditUserTOTPDisabled, Label: "TOTP disabled", Category: "Authentication", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "user"},
	{Action: AuditUserCreated, Label: "User created", Category: auditCategoryUserManagement, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "user"},
	{Action: AuditUserTOTPReset, Label: "TOTP reset", Category: auditCategoryUserManagement, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeSystem, ResourceType: "user"},
	{Action: AuditUserPasswordChanged, Label: "Password changed", Category: "Authentication", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "user"},
	{Action: AuditUserPasswordReuseRejected, Label: "Password reuse rejected", Category: "Authentication", Outcome: AuditOutcomeFailure, ActorType: AuditActorTypeUser, ResourceType: "user"},
	{Action: AuditUserRoleUpdated, Label: "User role updated", Category: auditCategoryUserManagement, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "user"},
	{Action: AuditUserDeleted, Label: "User deleted", Category: auditCategoryUserManagement, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "user"},
	{Action: AuditServerCreated, Label: "Server created", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "server"},
	{Action: AuditServerUpdated, Label: "Server updated", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "server"},
	{Action: AuditServerDeleted, Label: "Server deleted", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "server"},
	{Action: AuditServerBatchDeleted, Label: "Servers batch deleted", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "server"},
	{Action: AuditServerRegistered, Label: "Server registered", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeDevice, ResourceType: "server"},
	{Action: AuditServerRegistrationFailed, Label: "Server registration failed", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeFailure, ActorType: AuditActorTypeDevice, ResourceType: "server"},
	{Action: AuditServerConnected, Label: "Server connected", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeDevice, ResourceType: "server"},
	{Action: AuditServerDisconnected, Label: "Server disconnected", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeDevice, ResourceType: "server"},
	{Action: AuditServerUnregistered, Label: "Server unregistered", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "server"},
	{Action: AuditFileRead, Label: "File read", Category: auditCategoryFileAccess, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "file"},
	{Action: AuditFileUploaded, Label: "File uploaded", Category: auditCategoryFileAccess, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "file"},
	{Action: AuditPathGranted, Label: "Path granted", Category: auditCategoryFileAccess, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "path"},
	{Action: AuditPathRevoked, Label: "Path revoked", Category: auditCategoryFileAccess, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "path"},
	{Action: AuditLogTailStarted, Label: "Log tail started", Category: "Log Access", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "log"},
	{Action: AuditTerminalOpened, Label: "Terminal session opened", Category: "Terminal Access", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "terminal"},
	{Action: AuditTerminalClosed, Label: "Terminal session closed", Category: "Terminal Access", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "terminal"},
	{Action: AuditAuditExported, Label: "Audit exported", Category: auditCategoryAuditGovernance, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "audit"},
	{Action: AuditAuditReviewCompleted, Label: "Audit review completed", Category: auditCategoryAuditGovernance, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "audit"},
	{Action: AuditAuditFilterSaved, Label: "Audit filter saved", Category: auditCategoryAuditGovernance, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "audit"},
	{Action: AuditAuditFilterDeleted, Label: "Audit filter deleted", Category: auditCategoryAuditGovernance, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "audit"},
	{Action: AuditAuditRetentionUpdated, Label: "Audit retention updated", Category: auditCategoryAuditGovernance, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "audit"},
	{Action: AuditAuditRetentionExecuted, Label: "Audit retention executed", Category: auditCategoryAuditGovernance, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "audit"},
	{Action: AuditAuditFlagCreated, Label: "Audit flag created", Category: auditCategoryAuditGovernance, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeUser, ResourceType: "audit"},
	{Action: AuditAPITokenCreated, Label: "API token created", Category: auditCategoryUserManagement, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeSystem, ResourceType: "api_token"},
	{Action: AuditAPITokenRevoked, Label: "API token revoked", Category: auditCategoryUserManagement, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeSystem, ResourceType: "api_token"},
	{Action: AuditJWTSecretRotated, Label: "JWT signing secret rotated via admin CLI; all sessions invalidated and API tokens revoked", Category: "Authentication", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeSystem, ResourceType: "jwt_secret"},
	{Action: AuditStorageKeySeparated, Label: "One-time startup migration separating the storage encryption key from the JWT signing secret", Category: "Authentication", Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeSystem, ResourceType: "storage_key"},
	// Agent re-enrollment events (P2)
	{Action: AuditReEnrollRequested, Label: "Agent re-enrollment requested", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeDevice, ResourceType: "server"},
	{Action: AuditReEnrollApproved, Label: "Agent re-enrollment approved", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeSuccess, ActorType: AuditActorTypeSystem, ResourceType: "server"},
	{Action: AuditReEnrollDenied, Label: "Agent re-enrollment denied", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeFailure, ActorType: AuditActorTypeSystem, ResourceType: "server"},
	{Action: AuditCloneSuspected, Label: "Possible agent clone or replay detected during re-enrollment", Category: auditCategoryAgentLifecycle, Outcome: AuditOutcomeFailure, ActorType: AuditActorTypeSystem, ResourceType: "server"},
}
