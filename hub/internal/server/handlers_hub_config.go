package server

import (
	"net/http"
	"regexp"
	"strconv"

	"github.com/wyiu/veyport/hub/internal/lockout"
)

type hubConfigResponse struct {
	GRPCExternalAddr       string  `json:"grpc_external_addr"`
	JWTSecretRotatedAt     *string `json:"jwt_secret_rotated_at,omitempty"`
	LockoutThreshold       int     `json:"lockout_threshold"`
	LockoutWindowMinutes   int     `json:"lockout_window_minutes"`
	LockoutDurationMinutes int     `json:"lockout_duration_minutes"`
	DormantDays            int     `json:"dormant_days"`
}

type hubConfigRequest struct {
	GRPCExternalAddr       *string `json:"grpc_external_addr"`
	LockoutThreshold       *int    `json:"lockout_threshold"`
	LockoutWindowMinutes   *int    `json:"lockout_window_minutes"`
	LockoutDurationMinutes *int    `json:"lockout_duration_minutes"`
	DormantDays            *int    `json:"dormant_days"`
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

	policy := lockout.Load(s.store.GetConfig)
	cfg.LockoutThreshold = policy.Threshold
	cfg.LockoutWindowMinutes = int(policy.Window.Minutes())
	cfg.LockoutDurationMinutes = int(policy.Duration.Minutes())
	cfg.DormantDays = policy.DormantDays

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

	if req.GRPCExternalAddr != nil && *req.GRPCExternalAddr != "" && !grpcAddrPattern.MatchString(*req.GRPCExternalAddr) {
		respondError(w, http.StatusBadRequest, "invalid gRPC address format")
		return
	}

	// Validate every present lockout field before writing anything, so a
	// rejected PUT never leaves a partial update behind.
	if req.LockoutThreshold != nil && *req.LockoutThreshold < 0 {
		respondError(w, http.StatusBadRequest, "lockout_threshold must be a non-negative integer")
		return
	}
	if req.LockoutWindowMinutes != nil && *req.LockoutWindowMinutes < 0 {
		respondError(w, http.StatusBadRequest, "lockout_window_minutes must be a non-negative integer")
		return
	}
	if req.LockoutDurationMinutes != nil && *req.LockoutDurationMinutes < 0 {
		respondError(w, http.StatusBadRequest, "lockout_duration_minutes must be a non-negative integer")
		return
	}
	if req.DormantDays != nil && *req.DormantDays < 0 {
		respondError(w, http.StatusBadRequest, "dormant_days must be a non-negative integer")
		return
	}

	if req.GRPCExternalAddr != nil {
		if err := s.store.SetConfig("grpc_external_addr", *req.GRPCExternalAddr); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to save hub config")
			return
		}
	}

	if req.LockoutThreshold != nil {
		if err := s.store.SetConfig(lockout.KeyThreshold, strconv.Itoa(*req.LockoutThreshold)); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to save hub config")
			return
		}
	}
	if req.LockoutWindowMinutes != nil {
		if err := s.store.SetConfig(lockout.KeyWindowMinutes, strconv.Itoa(*req.LockoutWindowMinutes)); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to save hub config")
			return
		}
	}
	if req.LockoutDurationMinutes != nil {
		if err := s.store.SetConfig(lockout.KeyDurationMinutes, strconv.Itoa(*req.LockoutDurationMinutes)); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to save hub config")
			return
		}
	}
	if req.DormantDays != nil {
		if err := s.store.SetConfig(lockout.KeyDormantDays, strconv.Itoa(*req.DormantDays)); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to save hub config")
			return
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
