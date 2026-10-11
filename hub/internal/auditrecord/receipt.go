package auditrecord

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

// Claims binds the exact protected record and prepared execution to an immutable
// manifest version. Only an independent service signs these claims.
type Claims struct {
	jwt.RegisteredClaims
	SchemaVersion       int       `json:"schema_version"`
	KeyID               string    `json:"key_id"`
	EventID             string    `json:"event_id"`
	EventType           string    `json:"event_type"`
	RecordSHA256        string    `json:"record_sha256"`
	ActorSHA256         string    `json:"actor_sha256"`
	BindingSHA256       string    `json:"binding_sha256"`
	PolicyVersion       uint64    `json:"policy_version"`
	PolicySHA256        string    `json:"policy_sha256"`
	ExecutionID         string    `json:"execution_id,omitempty"`
	PreparationID       string    `json:"preparation_id,omitempty"`
	BootID              string    `json:"boot_id,omitempty"`
	NodeID              string    `json:"node_id,omitempty"`
	IdentitySHA256      string    `json:"identity_sha256,omitempty"`
	Manifest            ObjectRef `json:"manifest"`
	QualificationSHA256 string    `json:"qualification_sha256"`
	LookupNonce         string    `json:"lookup_nonce,omitempty"`
}

type Receipt struct {
	Token    string    `json:"token"`
	Manifest ObjectRef `json:"manifest"`
}

type AnchorResponse struct {
	Record  []byte  `json:"record"`
	Receipt Receipt `json:"receipt"`
	Nonce   string  `json:"nonce"`
}

// AnchorNotFoundResponse is authenticated by the live TLS exchange and is only
// usable for initial bootstrap, never as proof that an enrolled policy vanished.
type AnchorNotFoundResponse struct {
	Code           string `json:"code"`
	InstallationID string `json:"installation_id"`
	Nonce          string `json:"nonce"`
}

type Manifest struct {
	SchemaVersion int             `json:"schema_version"`
	EventID       string          `json:"event_id"`
	RecordSHA256  string          `json:"record_sha256"`
	Envelope      ObjectRef       `json:"envelope"`
	Attachments   []ObjectRef     `json:"attachments,omitempty"`
	SigningKeyID  string          `json:"signing_key_id"`
	IssuedAt      jwt.NumericDate `json:"issued_at"`
	ExpiresAt     jwt.NumericDate `json:"expires_at"`
	// Retention preserves the acceptance instant's precision; JWT timestamps
	// remain whole seconds and do not shorten the configured retention duration.
	RetainUntil         time.Time `json:"retain_until"`
	QualificationSHA256 string    `json:"qualification_sha256"`
}

func Digest(v any) string { b, _ := json.Marshal(v); return Hash(b) }

func ExpectedFor(data []byte) (Expected, Envelope, error) {
	var e Envelope
	if Decode(data, &e, MaxEnvelopeBytes) != nil || e.Validate() != nil {
		return Expected{}, e, ErrSchema
	}
	x := Expected{EventID: e.EventID, EventType: e.EventType, RecordSHA256: Hash(data), ActorSHA256: Digest(e.Actor), BindingSHA256: Digest(struct {
		Execution *ExecutionBinding `json:"execution"`
		Details   *Details          `json:"details"`
	}{e.Execution, e.Details}), PolicyVersion: e.PolicyVersion, PolicySHA256: e.PolicySHA256, Execution: e.Execution}
	return x, e, nil
}
