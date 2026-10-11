package auditingest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

const RedactionRuleVersion = "structured-omit-arguments-v1"

// Projection is deliberately independent of Envelope. Do not embed raw types:
// additions to the protected schema must never become search fields implicitly.
type Projection struct {
	Timestamp            time.Time `json:"@timestamp"`
	SchemaVersion        int       `json:"schema_version"`
	RedactionRuleVersion string    `json:"redaction_rule_version"`
	EventID              string    `json:"event_id"`
	EventType            string    `json:"event_type"`
	RecordSHA256         string    `json:"record_sha256"`
	ActorUserID          string    `json:"actor_user_id"`
	ActorPersonID        string    `json:"actor_person_id"`
	ActorName            string    `json:"actor_name"`
	ExecutionID          string    `json:"execution_id,omitempty"`
	NodeID               string    `json:"node_id,omitempty"`
	NodeName             string    `json:"node_name,omitempty"`
	RunAs                string    `json:"run_as,omitempty"`
	UID                  *uint32   `json:"uid,omitempty"`
	GID                  *uint32   `json:"gid,omitempty"`
	IdentitySHA256       string    `json:"identity_sha256,omitempty"`
	PolicyVersion        uint64    `json:"policy_version"`
	PolicySHA256         string    `json:"policy_sha256"`
	CommandSummary       string    `json:"command_summary,omitempty"`
	CommandBytes         int64     `json:"command_bytes,omitempty"`
	CommandSHA256        string    `json:"command_sha256,omitempty"`
	ScriptBytes          int64     `json:"script_bytes,omitempty"`
	ScriptSHA256         string    `json:"script_sha256,omitempty"`
	ProcessState         string    `json:"process_state"`
	EvidenceState        string    `json:"evidence_state"`
	CorrelationID        string    `json:"correlation_id,omitempty"`
	RequestID            string    `json:"request_id,omitempty"`
	ExitCode             *int32    `json:"exit_code,omitempty"`
	ManifestSHA256       string    `json:"manifest_sha256"`
	ManifestVersionID    string    `json:"manifest_version_id"`
	RetainUntil          time.Time `json:"retain_until"`
}

// MetadataText bounds printable identity snapshots. Credentials in names and
// operator-selected metadata are outside the command redaction guarantee.
func metadataText(value string, max int) string {
	if len(value) > max {
		return "[metadata omitted]"
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return "[metadata omitted]"
		}
	}
	return value
}

// CommandSummary recognizes a fixed executable vocabulary only. All arguments,
// assignments, quoting, substitutions and additional lines are omitted. This is
// intentionally conservative; no blacklist can reliably identify every secret.
func CommandSummary(command []byte) string {
	value := strings.TrimSpace(string(command))
	if strings.ContainsAny(value, "\r\n") {
		return "[multiline command redacted]"
	}
	first, _, _ := strings.Cut(value, " ")
	first = strings.TrimPrefix(first, "/bin/")
	first = strings.TrimPrefix(first, "/usr/bin/")
	switch first {
	case "bash", "sh", "curl", "wget", "env", "printf", "echo", "true", "false", "cat", "ls", "id", "whoami", "uname", "date", "sleep", "sudo", "systemctl", "python3", "node", "git", "docker", "kubectl":
		return first + " [arguments redacted]"
	default:
		return "[command redacted]"
	}
}

func Project(raw []byte, ref ExportReference) (Projection, error) {
	var e auditrecord.Envelope
	if !ref.valid() || len(raw) > auditrecord.MaxEnvelopeBytes || auditrecord.Hash(raw) != ref.RecordSHA256 || auditrecord.Decode(raw, &e, auditrecord.MaxEnvelopeBytes) != nil || e.Validate() != nil || e.EventID != ref.EventID || e.EventType != ref.EventType {
		return Projection{}, ErrUnavailable
	}
	p := Projection{Timestamp: e.OccurredAt, SchemaVersion: 1, RedactionRuleVersion: RedactionRuleVersion, EventID: e.EventID, EventType: e.EventType, RecordSHA256: ref.RecordSHA256, ActorUserID: e.Actor.UserID, ActorPersonID: e.Actor.PersonID, ActorName: metadataText(e.Actor.Name, 256), PolicyVersion: e.PolicyVersion, PolicySHA256: e.PolicySHA256, ProcessState: "not_applicable", EvidenceState: "archived", ManifestSHA256: ref.Manifest.SHA256, ManifestVersionID: ref.Manifest.VersionID, RetainUntil: ref.Manifest.RetainUntil}
	if e.Execution != nil {
		x := e.Execution
		p.ExecutionID = x.ExecutionID
		p.NodeID = x.NodeID
		p.NodeName = metadataText(x.NodeName, 256)
		p.RunAs = metadataText(x.Identity.Username, 128)
		uid, gid := x.Identity.UID, x.Identity.GID
		p.UID = &uid
		p.GID = &gid
		p.IdentitySHA256 = x.Identity.IdentitySHA256
		p.CommandBytes = x.CommandBytes
		p.CommandSHA256 = x.CommandSHA256
		p.ScriptBytes = x.ScriptBytes
		p.ScriptSHA256 = x.ScriptSHA256
		if len(e.Command) > 0 {
			p.CommandSummary = CommandSummary(e.Command)
		}
		p.ProcessState = "unconfirmed"
	}
	if e.Details != nil {
		if e.Details.Submission != nil {
			x := e.Details.Submission
			p.NodeID = x.NodeID
			p.NodeName = metadataText(x.NodeName, 256)
			p.CommandSHA256 = x.CommandSHA256
			p.CommandBytes = x.CommandBytes
			p.ScriptSHA256 = x.ScriptSHA256
			p.ScriptBytes = x.ScriptBytes
			p.ProcessState = "denied"
		}
		p.CorrelationID = e.Details.CorrelationID
		p.RequestID = e.Details.RequestID
		p.ExitCode = e.Details.ExitCode
		switch e.Details.State {
		case "synthetic-readiness-no-process":
			if e.EventType == auditrecord.ExecutionLifecycle && len(e.Command) == 0 && len(e.Attachments) == 0 {
				p.ProcessState = "synthetic_readiness_not_applicable"
				p.UID, p.GID = nil, nil
				p.RunAs = ""
			}
		case "prepared", "admitted", "started", "running", "completed", "failed", "cancelled", "denied", "interrupted", "unconfirmed", "unknown", "not_started", "exited", "refused", "uncertain":
			p.ProcessState = e.Details.State
		}
	}
	return p, nil
}

// DocumentID remains stable across retries, full rescans and redaction upgrades.
func (p Projection) DocumentID() string    { return p.EventID }
func (p Projection) JSON() ([]byte, error) { return json.Marshal(p) }
