package model

import (
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

const OriginalReadAction = "audit.original.read"

// ExecutionView carries redacted metadata. A nil preparation means no OS
// identity was prepared; UID zero must never stand in for a missing identity.
type ExecutionView struct {
	*Execution
	Preparation *ExecutionPreparation `json:"preparation"`
	Originals   []string              `json:"originals"`
}

type ExecutionFilter struct {
	ActorID, NodeID, OSUser, PolicyVersion, State, EvidenceState string
	Limit, Offset                                                int
}

type OriginalAccessRequest struct {
	Purpose string   `json:"purpose"`
	Records []string `json:"records"`
}

type OriginalDescriptor struct {
	Kind      string `json:"kind"`
	EventID   string `json:"event_id"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	VersionID string `json:"version_id"`
}

type OriginalPreview struct {
	Action  string               `json:"action"`
	Digest  string               `json:"digest"`
	Records []OriginalDescriptor `json:"records"`
}

// OriginalAccess contains only authority and evidence metadata, never original
// bytes. Raw handles and intent tokens are excluded from ordinary JSON APIs.
type OriginalAccess struct {
	ID, ExecutionID, UserID, PersonID, SessionID string
	SecurityRevision                             int
	PolicyVersion                                uint64
	PolicySHA256, Digest, Purpose, Kind          string
	Object                                       auditrecord.ObjectRef `json:"-"`
	Actor                                        auditrecord.Actor
	Intent                                       []byte `json:"-"`
	IntentToken                                  string `json:"-"`
	HandleSHA256                                 string `json:"-"`
	CreatedAt, ExpiresAt                         time.Time
	ConsumedAt                                   *time.Time
	State, EvidenceState                         string
	BytesWritten                                 int64
}

type OriginalEvidence struct {
	EventID, AccessID string
	PolicyVersion     uint64
	Raw               []byte
	MinRetainUntil    time.Time
	CreatedAt         time.Time
	Attempts          int
}
