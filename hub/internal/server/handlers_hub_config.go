package server

import (
	"net/http"
	"regexp"
)

type hubConfigResponse struct {
	GRPCExternalAddr   string  `json:"grpc_external_addr"`
	JWTSecretRotatedAt *string `json:"jwt_secret_rotated_at,omitempty"`
}

type hubConfigRequest struct {
	GRPCExternalAddr string `json:"grpc_external_addr"`
}

func (s *Server) handleGetHubConfig(w http.ResponseWriter, r *http.Request) {
	cfg := hubConfigResponse{}

	// DB value takes priority; fall back to CLI flag
	if addr, err := s.store.GetConfig("grpc_external_addr"); err == nil {
		cfg.GRPCExternalAddr = addr
	} else if s.grpcExternalAddr != "" {
		cfg.GRPCExternalAddr = s.grpcExternalAddr
	}

	// Read-only: timestamp of last JWT secret rotation; omitted when never rotated.
	if rotatedAt, err := s.store.GetConfig("jwt_secret_rotated_at"); err == nil {
		cfg.JWTSecretRotatedAt = &rotatedAt
	}

	respondJSON(w, http.StatusOK, cfg)
}

// grpcAddrPattern allows hostnames, IPs, and ports — no shell metacharacters.
var grpcAddrPattern = regexp.MustCompile(`^[a-zA-Z0-9._:\-\[\]]+$`)

func (s *Server) handleUpdateHubConfig(w http.ResponseWriter, r *http.Request) {
	var req hubConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	if req.GRPCExternalAddr != "" && !grpcAddrPattern.MatchString(req.GRPCExternalAddr) {
		respondError(w, http.StatusBadRequest, "invalid gRPC address format")
		return
	}

	if err := s.store.SetConfig("grpc_external_addr", req.GRPCExternalAddr); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to save hub config")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
