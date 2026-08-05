package api

// All types in this file decode hub JSON responses. Decoding uses plain
// encoding/json, which silently ignores unknown fields by default — new
// fields the hub adds later are forward-compatible without a CLI change
// (contracts/rest-api.md: "Unknown JSON fields in any response: ignored").
//
// Field names and shapes are pinned against the hub's actual handlers
// (hub/internal/server/handlers_auth.go, handlers_servers.go,
// handlers_files.go, hub/internal/model/*.go) and docs/wiki/API-Reference.md,
// which are the shapes contracts/rest-api.md cites as source of truth.

// LoginTOTPPending is the 202 response from POST /api/auth/login when the
// account has TOTP enabled: password was correct, a TOTP code is needed
// next. TOTPToken is single-use and expires after 60 seconds.
type LoginTOTPPending struct {
	TOTPToken string `json:"totp_token"`
}

// LoginSetupRequired is the 200 response from POST /api/auth/login when the
// account has not completed TOTP enrollment yet. The CLI must abort with
// enrollment guidance and store nothing.
type LoginSetupRequired struct {
	SetupToken        string `json:"setup_token"`
	RequiresTOTPSetup bool   `json:"requires_totp_setup"`
}

// User is the identity payload embedded in TokenPair (from
// POST /api/auth/login/totp) and returned standalone by GET /api/auth/me.
type User struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// TokenPair is the 200 response from POST /api/auth/login/totp (with User
// populated) and from POST /api/auth/refresh (User absent/zero-value: the
// refresh endpoint returns only the rotated access/refresh tokens).
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	User         User   `json:"user"`
}

// Me is the 200 response from GET /api/auth/me.
type Me struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Server mirrors the hub's server resource (hub/internal/model.Server).
type Server struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Hostname     *string `json:"hostname,omitempty"`
	IPAddress    *string `json:"ip_address,omitempty"`
	OS           *string `json:"os,omitempty"`
	Status       string  `json:"status"`
	AgentVersion *string `json:"agent_version,omitempty"`
	Labels       string  `json:"labels,omitempty"`
	LastSeenAt   *string `json:"last_seen_at,omitempty"`
	CreatedAt    string  `json:"created_at,omitempty"`
	UpdatedAt    string  `json:"updated_at,omitempty"`
}

// ServersPage is the 200 response from GET /api/servers
// (hub/internal/model.ServerListResponse). The CLI passes limit/offset
// through unchanged and never fetches unbounded.
type ServersPage struct {
	Servers []Server `json:"servers"`
	Total   int      `json:"total"`
	Limit   int      `json:"limit"`
	Offset  int      `json:"offset"`
}

// FileEntry describes one entry in a directory listing
// (GET /api/servers/{id}/files). Name/Path/IsDir/Size/Readable mirror the
// agent's FileNode proto (proto/veyport/v1/agent.pb.go); ModTime/Mode are
// carried for forward-compatibility with docs/wiki/API-Reference.md's
// documented example shape.
type FileEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	IsDir    bool   `json:"is_dir,omitempty"`
	Size     int64  `json:"size"`
	Readable bool   `json:"readable,omitempty"`
	ModTime  string `json:"mod_time,omitempty"`
	Mode     string `json:"mode,omitempty"`
}

// FileListing is the 200 response from GET /api/servers/{id}/files
// (hub/internal/model.FileListResult).
type FileListing struct {
	Files []FileEntry `json:"files"`
}

// FileContent is the 200 response from GET /api/servers/{id}/files/read
// (hub/internal/model.FileReadResult). Data is base64-encoded file content;
// decoding/streaming it to stdout is a command-layer concern.
type FileContent struct {
	Data      string `json:"data"`
	TotalSize int64  `json:"total_size"`
	MimeType  string `json:"mime_type"`
}

// errorResponse is the hub's standard error envelope: {"error": "..."}.
type errorResponse struct {
	Error string `json:"error"`
}
