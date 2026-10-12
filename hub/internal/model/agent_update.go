package model

// AgentArtifact is selected exclusively from the Hub's verified distribution.
type AgentArtifact struct {
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Version    string `json:"version"`
	Revision   string `json:"revision"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
	BinaryPath string `json:"-"`
}

// AgentUpdate keeps authority and recovery metadata, never binary data or a ticket.
type AgentUpdate struct {
	ID                     string          `json:"id"`
	NodeID                 string          `json:"node_id"`
	ActorID                string          `json:"-"`
	SessionID              string          `json:"-"`
	State                  string          `json:"state"`
	Reason                 string          `json:"reason,omitempty"`
	Target                 AgentArtifact   `json:"target"`
	BootstrapArtifacts     []AgentArtifact `json:"-"`
	BootstrapIdleConfirmed bool            `json:"-"`
	BootstrapConnectionID  string          `json:"-"`
	PreviousVersion        string          `json:"previous_version,omitempty"`
	PreviousRevision       string          `json:"previous_revision,omitempty"`
	PreviousSHA256         string          `json:"previous_sha256,omitempty"`
	PreviousBootID         string          `json:"-"`
	ObservedVersion        string          `json:"observed_version,omitempty"`
	ObservedRevision       string          `json:"observed_revision,omitempty"`
	ObservedSHA256         string          `json:"observed_sha256,omitempty"`
	ObservedBootID         string          `json:"-"`
	TicketHash             string          `json:"-"`
	ExpiresAt              int64           `json:"expires_at"`
	CreatedAt              int64           `json:"created_at"`
	UpdatedAt              int64           `json:"updated_at"`
}

func (u AgentUpdate) Terminal() bool {
	switch u.State {
	case "succeeded", "failed", "rolled_back", "expired", "recovery_acknowledged":
		return true
	}
	return false
}
