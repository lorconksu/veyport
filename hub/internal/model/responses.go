package model

import pb "github.com/wyiu/aerodocs/proto/aerodocs/v1"

// SetupResponse is returned after initial user registration.
type SetupResponse struct {
	SetupToken string `json:"setup_token"`
	User       *User  `json:"user"`
}

// ServerListResponse is returned by the list-servers endpoint.
type ServerListResponse struct {
	Servers []Server `json:"servers"`
	Total   int      `json:"total"`
	Limit   int      `json:"limit"`
	Offset  int      `json:"offset"`
}

// BatchDeleteResponse is returned after a batch-delete operation.
type BatchDeleteResponse struct {
	Status  string `json:"status"`
	Deleted int    `json:"deleted"`
}

// UploadFileResponse is returned after a successful file upload.
type UploadFileResponse struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

// FileListResult wraps the file listing returned by the agent.
type FileListResult struct {
	Files []*pb.FileNode `json:"files"`
}

// FileReadResult wraps the content returned by a file-read request.
type FileReadResult struct {
	Data      string `json:"data"`
	TotalSize int64  `json:"total_size"`
	MimeType  string `json:"mime_type"`
}

// TerminalSessionResponse is returned after creating a terminal session.
type TerminalSessionResponse struct {
	SessionID string `json:"session_id"`
}

// PermissionListResponse wraps a list of path permissions for a server.
type PermissionListResponse struct {
	Paths []Permission `json:"paths"`
}

// UserPathsResponse wraps the allowed paths for a user on a server.
type UserPathsResponse struct {
	Paths []string `json:"paths"`
}

// UserListResponse wraps a list of users.
type UserListResponse struct {
	Users []User `json:"users"`
}

// UserResponse wraps a single user.
type UserResponse struct {
	User *User `json:"user"`
}

// AuditListResponse is returned by the audit-log listing endpoint.
type AuditListResponse struct {
	Entries []AuditEntry `json:"entries"`
	Total   int          `json:"total"`
	Limit   int          `json:"limit"`
	Offset  int          `json:"offset"`
}
