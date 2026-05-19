package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	maxFileReadSize      = 1048576  // 1MB
	maxFileViewSize      = 10485760 // 10MB hard cap
	agentTimeoutDuration = 10 * time.Second
)

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	serverID := r.PathValue("id")
	if !s.checkFileAccess(w, r, serverID, path) {
		return
	}

	// Check agent is connected
	if _, ok := s.requireAgent(w, r); !ok {
		return
	}

	// Send request via gRPC and wait for response
	raw := s.sendAgentRequest(w, serverID, func(requestID string) *pb.HubMessage {
		return &pb.HubMessage{
			Payload: &pb.HubMessage_FileListRequest{
				FileListRequest: &pb.FileListRequest{
					RequestId: requestID,
					Path:      path,
				},
			},
		}
	}, agentTimeoutDuration)
	if raw == nil {
		return
	}

	resp, ok := raw.(*pb.FileListResponse)
	if !ok {
		respondError(w, http.StatusInternalServerError, errUnexpectedResponse)
		return
	}
	if resp.Error != "" {
		respondError(w, http.StatusNotFound, resp.Error)
		return
	}
	respondJSON(w, http.StatusOK, model.FileListResult{Files: resp.Files})
}

func (s *Server) handleReadFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	serverID := r.PathValue("id")
	if !s.checkFileAccess(w, r, serverID, path) {
		return
	}

	// Check agent is connected
	if _, ok := s.requireAgent(w, r); !ok {
		return
	}

	// Send request — use offset -1 to tell the agent to return the tail (last 1MB).
	// The agent interprets negative offsets as "from end of file".
	raw := s.sendAgentRequest(w, serverID, func(requestID string) *pb.HubMessage {
		return &pb.HubMessage{
			Payload: &pb.HubMessage_FileReadRequest{
				FileReadRequest: &pb.FileReadRequest{
					RequestId: requestID,
					Path:      path,
					Offset:    -1,
					Limit:     maxFileReadSize,
				},
			},
		}
	}, agentTimeoutDuration)
	if raw == nil {
		return
	}

	resp, ok := raw.(*pb.FileReadResponse)
	if !ok {
		respondError(w, http.StatusInternalServerError, errUnexpectedResponse)
		return
	}
	if resp.Error != "" {
		respondError(w, http.StatusNotFound, resp.Error)
		return
	}
	if resp.TotalSize > maxFileViewSize {
		respondError(w, http.StatusRequestEntityTooLarge, "file too large for viewing")
		return
	}

	// Audit log
	userID := UserIDFromContext(r.Context())
	ip := clientIP(r)
	detail := path
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &userID,
		Action:    model.AuditFileRead,
		Target:    &serverID,
		Detail:    &detail,
		IPAddress: &ip,
	})

	respondJSON(w, http.StatusOK, model.FileReadResult{
		Data:      base64.StdEncoding.EncodeToString(resp.Data),
		TotalSize: resp.TotalSize,
		MimeType:  resp.MimeType,
	})
}

// checkFileAccess validates the path and checks that the user is allowed to access it.
// Returns false (and writes the error response) if access should be denied.
func (s *Server) checkFileAccess(w http.ResponseWriter, r *http.Request, serverID, path string) bool {
	if err := validateRequestPath(path); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return false
	}

	role := UserRoleFromContext(r.Context())
	if role != "admin" {
		userID := UserIDFromContext(r.Context())
		allowed, err := s.isPathAllowed(userID, serverID, path)
		if err != nil || !allowed {
			respondError(w, http.StatusForbidden, "access denied")
			return false
		}
	}
	return true
}

// isPathAllowed checks if the requested path is under one of the user's allowed roots.
func (s *Server) isPathAllowed(userID, serverID, requestedPath string) (bool, error) {
	paths, err := s.store.GetUserPathsForServer(userID, serverID)
	if err != nil {
		return false, err
	}
	cleanedReq := filepath.Clean(requestedPath)
	for _, allowed := range paths {
		cleanedAllowed := filepath.Clean(allowed)
		rel, err := filepath.Rel(cleanedAllowed, cleanedReq)
		if err != nil {
			continue
		}
		// rel must not escape the allowed root — "." means exact match,
		// anything starting with ".." means the path is outside the root.
		if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..") {
			return true, nil
		}
	}
	return false, nil
}

// validateRequestPath checks for path traversal and ensures absolute path.
func validateRequestPath(path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path must be absolute")
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed")
	}
	return nil
}
