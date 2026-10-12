package api

type AgentArtifact struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
}
type AgentUpdate struct {
	ID               string        `json:"id"`
	NodeID           string        `json:"node_id"`
	State            string        `json:"state"`
	Reason           string        `json:"reason,omitempty"`
	Target           AgentArtifact `json:"target"`
	PreviousVersion  string        `json:"previous_version,omitempty"`
	PreviousRevision string        `json:"previous_revision,omitempty"`
	PreviousSHA256   string        `json:"previous_sha256,omitempty"`
	ObservedVersion  string        `json:"observed_version,omitempty"`
	ObservedRevision string        `json:"observed_revision,omitempty"`
	ObservedSHA256   string        `json:"observed_sha256,omitempty"`
	ExpiresAt        int64         `json:"expires_at"`
	CreatedAt        int64         `json:"created_at"`
	UpdatedAt        int64         `json:"updated_at"`
}
type AgentUpdateCheck struct {
	Supported         bool   `json:"supported"`
	Reason            string `json:"reason,omitempty"`
	UpdateAvailable   bool   `json:"update_available"`
	BootstrapRequired bool   `json:"bootstrap_required"`
	Current           *struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
		SHA256   string `json:"sha256"`
	} `json:"current,omitempty"`
	Target    AgentArtifact `json:"target"`
	Operation *AgentUpdate  `json:"operation,omitempty"`
}
type AgentUpdateStart struct {
	Operation        AgentUpdate `json:"operation"`
	BootstrapTicket  string      `json:"bootstrap_ticket,omitempty"`
	BootstrapCommand string      `json:"bootstrap_command,omitempty"`
}
