// Package auditrecord defines the bounded protected archive wire contract.
// It contains no signing keys, persistence implementation, or execution authority.
package auditrecord

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion      = 1
	MaxEnvelopeBytes   = 128 << 10
	MaxCommandBytes    = 32 << 10
	MaxAttachmentBytes = 16 << 20
	MaxAttachments     = 4
	MaxReceiptBytes    = 16 << 10
	ExecutionAdmission = "execution.admission"
	ExecutionLifecycle = "execution.lifecycle"
	ExecutionDenial    = "execution.denial"
	PolicyIntent       = "policy.intent"
	PolicyCommit       = "policy.commit"
	PolicyResult       = "policy.result"
	OriginalReadIntent = "original_read.intent"
	OriginalReadResult = "original_read.result"
	PolicyAnchor       = "policy.anchor"
)

var ErrSchema = errors.New("invalid protected audit record")

type AttachmentInput struct {
	ID     string
	Reader io.Reader
}

type Actor struct {
	UserID   string `json:"user_id"`
	PersonID string `json:"person_id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

type Identity struct {
	Username       string   `json:"username"`
	UID            uint32   `json:"uid"`
	GID            uint32   `json:"gid"`
	Groups         []uint32 `json:"groups"`
	GroupsSHA256   string   `json:"groups_sha256"`
	IdentitySHA256 string   `json:"identity_sha256"`
	Home           string   `json:"home"`
	Shell          string   `json:"shell"`
	CWD            string   `json:"cwd"`
}

type Limits struct {
	MaxFrameBytes          uint32 `json:"max_frame_bytes"`
	MaxBufferBytes         uint32 `json:"max_buffer_bytes"`
	RuntimeSeconds         uint32 `json:"runtime_seconds"`
	TermGraceSeconds       uint32 `json:"term_grace_seconds"`
	BlockedConsumerSeconds uint32 `json:"blocked_consumer_seconds"`
}

type ExecutionBinding struct {
	ExecutionID   string    `json:"execution_id"`
	PreparationID string    `json:"preparation_id"`
	BootID        string    `json:"boot_id"`
	NodeID        string    `json:"node_id"`
	NodeName      string    `json:"node_name"`
	Identity      Identity  `json:"identity"`
	CommandSHA256 string    `json:"command_sha256"`
	CommandBytes  int64     `json:"command_bytes"`
	ScriptSHA256  string    `json:"script_sha256,omitempty"`
	ScriptBytes   int64     `json:"script_bytes,omitempty"`
	PreparedUntil time.Time `json:"prepared_until"`
	Limits        Limits    `json:"limits"`
}

type SubmissionBinding struct {
	NodeID        string `json:"node_id"`
	NodeName      string `json:"node_name"`
	CommandSHA256 string `json:"command_sha256"`
	CommandBytes  int64  `json:"command_bytes"`
	ScriptSHA256  string `json:"script_sha256,omitempty"`
	ScriptBytes   int64  `json:"script_bytes,omitempty"`
}

type Attachment struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Details uses an explicit allowlist. It cannot smuggle arbitrary raw log fields.
type Details struct {
	Submission            *SubmissionBinding `json:"submission,omitempty"`
	InstallationID        string             `json:"installation_id,omitempty"`
	Requester             *Actor             `json:"requester,omitempty"`
	CorrelationID         string             `json:"correlation_id"`
	RequestID             string             `json:"request_id,omitempty"`
	RequestSHA256         string             `json:"request_sha256,omitempty"`
	ExpectedPolicyVersion uint64             `json:"expected_policy_version,omitempty"`
	NewPolicyVersion      uint64             `json:"new_policy_version,omitempty"`
	SessionSHA256         string             `json:"session_sha256,omitempty"`
	Reason                string             `json:"reason,omitempty"`
	State                 string             `json:"state,omitempty"`
	ExitCode              *int32             `json:"exit_code,omitempty"`
	Originals             []ObjectRef        `json:"originals,omitempty"`
	ApproverPersonIDs     []string           `json:"approver_person_ids,omitempty"`
	ApprovedChange        []byte             `json:"approved_change,omitempty"`
	Approvals             []ApprovalEvidence `json:"approvals,omitempty"`
}

type ApprovalEvidence struct {
	UserID            string    `json:"user_id"`
	PersonID          string    `json:"person_id"`
	StepupProofSHA256 string    `json:"stepup_proof_sha256"`
	ApprovedAt        time.Time `json:"approved_at"`
}

type Envelope struct {
	SchemaVersion int               `json:"schema_version"`
	EventID       string            `json:"event_id"`
	EventType     string            `json:"event_type"`
	Actor         Actor             `json:"actor"`
	Execution     *ExecutionBinding `json:"execution,omitempty"`
	PolicyVersion uint64            `json:"policy_version"`
	PolicySHA256  string            `json:"policy_sha256"`
	OccurredAt    time.Time         `json:"occurred_at"`
	Command       []byte            `json:"command,omitempty"`
	Attachments   []Attachment      `json:"attachments,omitempty"`
	Details       *Details          `json:"details,omitempty"`
}

type ObjectRef struct {
	Bucket      string    `json:"bucket"`
	Key         string    `json:"key"`
	VersionID   string    `json:"version_id"`
	SHA256      string    `json:"sha256"`
	Bytes       int64     `json:"bytes"`
	RetainUntil time.Time `json:"retain_until"`
}

// Expected must be reconstructed from the submitted bytes and live preparation,
// not from the receipt being verified.
type Expected struct {
	EventID        string
	EventType      string
	RecordSHA256   string
	ActorSHA256    string
	BindingSHA256  string
	PolicyVersion  uint64
	PolicySHA256   string
	Execution      *ExecutionBinding
	MinRetainUntil time.Time
	Nonce          string
}

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func ValidID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

func ValidHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}

func bounded(s string, n int) bool {
	return len(s) <= n && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

func (e Envelope) Validate() error {
	if e.SchemaVersion != SchemaVersion || !ValidID(e.EventID) || !ValidID(e.Actor.UserID) || !ValidID(e.Actor.PersonID) || !bounded(e.Actor.Name, 256) || !bounded(e.Actor.Provider, 128) || !bounded(e.Actor.Subject, 512) || e.PolicyVersion == 0 || !ValidHash(e.PolicySHA256) || e.OccurredAt.IsZero() {
		return ErrSchema
	}
	switch e.EventType {
	case ExecutionAdmission, ExecutionLifecycle, ExecutionDenial, PolicyIntent, PolicyCommit, PolicyResult, OriginalReadIntent, OriginalReadResult, PolicyAnchor:
	default:
		return ErrSchema
	}
	if len(e.Command) > MaxCommandBytes || !utf8.Valid(e.Command) || strings.ContainsRune(string(e.Command), 0) || len(e.Attachments) > MaxAttachments {
		return ErrSchema
	}
	total := int64(0)
	seen := map[string]bool{}
	for _, a := range e.Attachments {
		if !ValidID(a.ID) || !ValidHash(a.SHA256) || a.Bytes < 0 || a.Bytes > MaxAttachmentBytes || seen[a.ID] {
			return ErrSchema
		}
		seen[a.ID] = true
		total += a.Bytes
	}
	if total > MaxAttachmentBytes {
		return ErrSchema
	}
	if e.Execution != nil {
		x := e.Execution
		if !ValidID(x.ExecutionID) || !ValidID(x.PreparationID) || !ValidID(x.BootID) || !ValidID(x.NodeID) || !bounded(x.NodeName, 256) || !bounded(x.Identity.Username, 128) || x.Identity.Username == "" || !ValidHash(x.Identity.GroupsSHA256) || !ValidHash(x.Identity.IdentitySHA256) || len(x.Identity.Groups) > 1024 || !bounded(x.Identity.Home, 4096) || !strings.HasPrefix(x.Identity.Home, "/") || !bounded(x.Identity.Shell, 4096) || !strings.HasPrefix(x.Identity.Shell, "/") || !bounded(x.Identity.CWD, 4096) || !strings.HasPrefix(x.Identity.CWD, "/") || !ValidHash(x.CommandSHA256) || x.CommandBytes < 1 || x.CommandBytes > MaxCommandBytes || x.PreparedUntil.IsZero() || x.Limits.MaxFrameBytes == 0 || x.Limits.MaxFrameBytes > 64<<10 || x.Limits.MaxBufferBytes < x.Limits.MaxFrameBytes || x.Limits.MaxBufferBytes > 2<<20 || x.Limits.RuntimeSeconds == 0 || x.Limits.TermGraceSeconds == 0 || x.Limits.BlockedConsumerSeconds == 0 {
			return ErrSchema
		}
		if x.ScriptBytes < 0 || x.ScriptBytes > MaxAttachmentBytes || (x.ScriptSHA256 != "" && !ValidHash(x.ScriptSHA256)) || (x.ScriptSHA256 == "" && x.ScriptBytes != 0) {
			return ErrSchema
		}
	}
	if e.EventType == ExecutionAdmission {
		if e.Execution == nil || len(e.Command) == 0 || int64(len(e.Command)) != e.Execution.CommandBytes || Hash(e.Command) != e.Execution.CommandSHA256 {
			return ErrSchema
		}
		if e.Execution.ScriptSHA256 != "" {
			if len(e.Attachments) != 1 || e.Attachments[0].ID != "script" || e.Attachments[0].SHA256 != e.Execution.ScriptSHA256 || e.Attachments[0].Bytes != e.Execution.ScriptBytes {
				return ErrSchema
			}
		} else if len(e.Attachments) != 0 {
			return ErrSchema
		}
	} else if len(e.Command) != 0 {
		return ErrSchema
	}
	if e.EventType != ExecutionAdmission && len(e.Attachments) != 0 {
		return ErrSchema
	}
	if strings.HasPrefix(e.EventType, "policy.") && e.Execution != nil {
		return ErrSchema
	}
	if e.EventType == ExecutionDenial && (e.Execution != nil || e.Details == nil || e.Details.State == "" || e.Details.Reason != "" || e.Details.Submission == nil) {
		return ErrSchema
	}
	if e.EventType == ExecutionLifecycle && e.Execution == nil {
		return ErrSchema
	}
	if e.Details != nil {
		d := e.Details
		if d.Submission != nil {
			x := d.Submission
			if e.EventType != ExecutionDenial || !ValidID(x.NodeID) || !bounded(x.NodeName, 256) || !ValidHash(x.CommandSHA256) || x.CommandBytes < 1 || x.CommandBytes > MaxCommandBytes || x.ScriptBytes < 0 || x.ScriptBytes > MaxAttachmentBytes || (x.ScriptSHA256 != "" && !ValidHash(x.ScriptSHA256)) || (x.ScriptSHA256 == "" && x.ScriptBytes != 0) {
				return ErrSchema
			}
		}
		if d.Requester != nil && !d.Requester.Valid() {
			return ErrSchema
		}
		if !ValidID(d.CorrelationID) || !bounded(d.Reason, 4096) || !bounded(d.State, 64) || len(d.Originals) > 16 || len(d.ApproverPersonIDs) > 16 || len(d.ApprovedChange) > 64<<10 || len(d.Approvals) > 16 || (d.RequestID != "" && !ValidID(d.RequestID)) || (d.RequestSHA256 != "" && !ValidHash(d.RequestSHA256)) || (d.SessionSHA256 != "" && !ValidHash(d.SessionSHA256)) {
			return ErrSchema
		}
		for _, id := range d.ApproverPersonIDs {
			if !ValidID(id) {
				return ErrSchema
			}
		}
		for _, o := range d.Originals {
			if !o.Valid() {
				return ErrSchema
			}
		}
		for _, a := range d.Approvals {
			if !ValidID(a.UserID) || !ValidID(a.PersonID) || !ValidHash(a.StepupProofSHA256) || a.ApprovedAt.IsZero() {
				return ErrSchema
			}
		}
	}
	switch e.EventType {
	case PolicyIntent, PolicyCommit, PolicyResult, PolicyAnchor:
		if e.Details == nil || !ValidID(e.Details.RequestID) || !ValidHash(e.Details.RequestSHA256) {
			return ErrSchema
		}
		if e.EventType == PolicyIntent && (e.Details.Requester == nil || e.Details.Reason == "" || len(e.Details.ApprovedChange) == 0 || Hash(e.Details.ApprovedChange) != e.Details.RequestSHA256 || len(e.Details.Approvals) < 2) {
			return ErrSchema
		}
		if e.EventType == PolicyAnchor && (!ValidID(e.Details.InstallationID) || e.Details.ExpectedPolicyVersion == 0 || e.Details.ExpectedPolicyVersion == ^uint64(0) || e.Details.NewPolicyVersion != e.Details.ExpectedPolicyVersion+1 || e.PolicyVersion != e.Details.NewPolicyVersion || len(e.Details.ApprovedChange) != 0) {
			return ErrSchema
		}
	case OriginalReadIntent, OriginalReadResult:
		if e.Details == nil || !ValidHash(e.Details.SessionSHA256) || len(e.Details.Originals) == 0 || e.Details.Reason == "" {
			return ErrSchema
		}
	}
	return nil
}

func (o ObjectRef) Valid() bool {
	return len(o.Bucket) > 0 && len(o.Bucket) <= 128 && len(o.Key) > 0 && len(o.Key) <= 1024 && len(o.VersionID) > 0 && o.VersionID != "null" && len(o.VersionID) <= 1024 && ValidHash(o.SHA256) && o.Bytes >= 0 && !o.RetainUntil.IsZero()
}

func (a Actor) Valid() bool {
	return ValidID(a.UserID) && ValidID(a.PersonID) && bounded(a.Name, 256) && bounded(a.Provider, 128) && bounded(a.Subject, 512)
}
