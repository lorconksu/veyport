package server

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/wyiu/veyport/hub"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
)

// ResolveAgentArtifact shares the same verified distribution as local updates.
func (s *Server) ResolveAgentArtifact(osName, arch string) (model.AgentArtifact, error) {
	a, err := s.resolveDistribution("agent", osName, arch)
	return model.AgentArtifact{OS: a.OS, Arch: a.Arch, Version: a.Version, Revision: a.Revision, SHA256: a.SHA256, Bytes: a.Bytes, BinaryPath: a.BinaryPath}, err
}
func (s *Server) updateAvailable(w http.ResponseWriter) bool {
	if s.agentUpdates == nil {
		respondError(w, http.StatusServiceUnavailable, "agent update service unavailable")
		return false
	}
	return true
}
func agentUpdateError(w http.ResponseWriter, err error) {
	code := http.StatusConflict
	if errors.Is(err, grpcserver.ErrAgentUpdateDenied) {
		code = http.StatusForbidden
	} else if errors.Is(err, sql.ErrNoRows) {
		code = http.StatusNotFound
	}
	respondError(w, code, err.Error())
}
func (s *Server) handleAgentUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if !s.updateAvailable(w) {
		return
	}
	result, err := s.agentUpdates.Check(UserIDFromContext(r.Context()), SessionIDFromContext(r.Context()), r.PathValue("id"))
	if err != nil {
		agentUpdateError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, result)
}
func (s *Server) handleAgentUpdateStart(w http.ResponseWriter, r *http.Request) {
	if !s.updateAvailable(w) {
		return
	}
	var body struct {
		ExpectedVersion  string `json:"expected_version"`
		ExpectedRevision string `json:"expected_revision"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 2049))
	r.Body.Close()
	if err != nil || auditrecord.Decode(raw, &body, 2048) != nil || body.ExpectedVersion == "" || body.ExpectedRevision == "" {
		respondError(w, http.StatusBadRequest, "expected_version and expected_revision are required; no other update parameters are accepted")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	op, ticket, err := s.agentUpdates.Start(ctx, UserIDFromContext(r.Context()), SessionIDFromContext(r.Context()), r.PathValue("id"), body.ExpectedVersion, body.ExpectedRevision)
	if err != nil {
		agentUpdateError(w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, struct {
		Operation       model.AgentUpdate `json:"operation"`
		BootstrapTicket string            `json:"bootstrap_ticket,omitempty"`
	}{op, ticket})
}
func (s *Server) handleAgentUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if !s.updateAvailable(w) {
		return
	}
	op, err := s.agentUpdates.Status(r.PathValue("id"), r.URL.Query().Get("operation_id"))
	if err != nil {
		agentUpdateError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, op)
}
func (s *Server) handleAgentUpdateRecovery(w http.ResponseWriter, r *http.Request) {
	if !s.updateAvailable(w) {
		return
	}
	var body struct {
		OperationID    string `json:"operation_id"`
		VerifiedSHA256 string `json:"verified_sha256"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 2049))
	r.Body.Close()
	if err != nil || auditrecord.Decode(raw, &body, 2048) != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	op, err := s.agentUpdates.AcknowledgeRecovery(UserIDFromContext(r.Context()), SessionIDFromContext(r.Context()), r.PathValue("id"), body.OperationID, body.VerifiedSHA256)
	if err != nil {
		agentUpdateError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, op)
}
func (s *Server) handleAgentUpdateScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(headerContentType, "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(hub.AgentUpdateScript)
}
