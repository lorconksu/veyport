package model

type ReEnrollRequest struct {
	ID           string `json:"id"`
	ServerID     string `json:"server_id"`
	RequestedAt  string `json:"requested_at"`
	IPAddress    string `json:"ip_address"`
	Fingerprint  string `json:"fingerprint"`
	Status       string `json:"status"` // pending | approved | denied | expired
	AnomalyFlags string `json:"anomaly_flags"` // JSON: {"fingerprint_changed":bool,"original_online":bool}
	DecidedBy    string `json:"decided_by,omitempty"`
}
