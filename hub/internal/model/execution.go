package model

import "time"

// Execution contains only stable identity snapshots, hashes and outcomes.
// Submitted commands, scripts and output are never ordinary metadata.
type Execution struct {
	ID            string               `json:"id"`
	ActorID       string               `json:"actor_id"`
	ActorName     string               `json:"actor_name"`
	ActorProvider string               `json:"actor_provider"`
	NodeID        string               `json:"node_id"`
	NodeName      string               `json:"node_name"`
	RequestedUser string               `json:"requested_user"`
	CommandSHA256 string               `json:"command_sha256"`
	CommandLength int                  `json:"command_length"`
	PolicyVersion string               `json:"policy_version"`
	Preparation   ExecutionPreparation `json:"preparation"`
	State         string               `json:"state"`
	EvidenceState string               `json:"evidence_state"`
	ExitCode      *int32               `json:"exit_code,omitempty"`
	Signal        string               `json:"signal,omitempty"`
	Reason        string               `json:"reason,omitempty"`
	CreatedAt     time.Time            `json:"created_at"`
	UpdatedAt     time.Time            `json:"updated_at"`
	FinishedAt    *time.Time           `json:"finished_at,omitempty"`
}

type ExecutionPreparation struct {
	PreparationID    string            `json:"preparation_id"`
	BootID           string            `json:"boot_id"`
	ExpiresUnixMilli int64             `json:"expires_unix_milli"`
	Identity         ExecutionIdentity `json:"identity"`
}

type ExecutionIdentity struct {
	Username       string   `json:"username"`
	UID            uint32   `json:"uid"`
	GID            uint32   `json:"gid"`
	Groups         []uint32 `json:"groups"`
	GroupsSHA256   string   `json:"groups_sha256"`
	IdentitySHA256 string   `json:"identity_sha256"`
	Home           string   `json:"home"`
	Shell          string   `json:"shell"`
	Cwd            string   `json:"cwd"`
}

const (
	AuditExecutionSubmitted  = "execution.submitted"
	AuditExecutionPrepared   = "execution.prepared"
	AuditExecutionDispatched = "execution.dispatched"
	AuditExecutionFinished   = "execution.finished"
	AuditExecutionRefused    = "execution.refused"
)
