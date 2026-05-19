package server

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

func (s *Server) handleListPaths(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	perms, err := s.store.ListPermissionsForServer(serverID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list paths")
		return
	}
	if perms == nil {
		perms = []model.Permission{}
	}
	respondJSON(w, http.StatusOK, model.PermissionListResponse{Paths: perms})
}

func (s *Server) handleCreatePath(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")

	var req struct {
		UserID string `json:"user_id"`
		Path   string `json:"path"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UserID == "" || req.Path == "" {
		respondError(w, http.StatusBadRequest, "user_id and path are required")
		return
	}

	if err := validateRequestPath(req.Path); err != nil {
		respondError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}

	perm, err := s.store.CreatePermission(req.UserID, serverID, req.Path)
	if err != nil {
		respondError(w, http.StatusConflict, "permission already exists or invalid reference")
		return
	}

	// Audit log
	userID := UserIDFromContext(r.Context())
	detail := req.UserID + ":" + req.Path
	s.auditLogRequest(r, model.AuditEntry{
		ID:     uuid.NewString(),
		UserID: &userID,
		Action: model.AuditPathGranted,
		Target: &serverID,
		Detail: &detail,
	})

	respondJSON(w, http.StatusCreated, perm)
}

func (s *Server) handleDeletePath(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	pathID := r.PathValue("pathId")

	// Verify the permission belongs to this server
	perm, err := s.store.GetPermissionByID(pathID)
	if err != nil {
		respondError(w, http.StatusNotFound, "permission not found")
		return
	}
	if perm.ServerID != serverID {
		respondError(w, http.StatusNotFound, "permission not found")
		return
	}

	if err := s.store.DeletePermission(pathID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete permission")
		return
	}

	// Audit log
	userID := UserIDFromContext(r.Context())
	detail := perm.UserID + ":" + perm.Path
	s.auditLogRequest(r, model.AuditEntry{
		ID:     uuid.NewString(),
		UserID: &userID,
		Action: model.AuditPathRevoked,
		Target: &serverID,
		Detail: &detail,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetUserPaths(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	userID := UserIDFromContext(r.Context())
	role := UserRoleFromContext(r.Context())

	if role == "admin" {
		// Admins see all paths (they have unrestricted access)
		respondJSON(w, http.StatusOK, model.UserPathsResponse{Paths: []string{"/"}})
		return
	}

	paths, err := s.store.GetUserPathsForServer(userID, serverID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to get paths")
		return
	}
	if paths == nil {
		paths = []string{}
	}
	respondJSON(w, http.StatusOK, model.UserPathsResponse{Paths: paths})
}
