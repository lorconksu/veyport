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
	SessionIdleMinutes     int     `json:"session_idle_minutes"`
	SessionMaxHours        int     `json:"session_max_hours"`
}

type hubConfigRequest struct {
	GRPCExternalAddr       *string `json:"grpc_external_addr"`
	LockoutThreshold       *int    `json:"lockout_threshold"`
	LockoutWindowMinutes   *int    `json:"lockout_window_minutes"`
	LockoutDurationMinutes *int    `json:"lockout_duration_minutes"`
	DormantDays            *int    `json:"dormant_days"`
	SessionIdleMinutes     *int    `json:"session_idle_minutes"`
	SessionMaxHours        *int    `json:"session_max_hours"`
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
	cfg.SessionIdleMinutes = int(policy.SessionIdle.Minutes())
	cfg.SessionMaxHours = int(policy.SessionMax.Hours())

	respondJSON(w, http.StatusOK, cfg)
}

// grpcAddrPattern allows hostnames, IPs, and ports — no shell metacharacters.
var grpcAddrPattern = regexp.MustCompile(`^[a-zA-Z0-9._:\-\[\]]+$`)

// lockoutConfigField binds one nullable integer field of hubConfigRequest to
// the store key it is persisted under and the message it reports when
// negative, so validation and persistence can share a single loop instead of
// repeating the same shape four times.
type lockoutConfigField struct {
	value       *int
	key         string
	negativeMsg string
}

func lockoutConfigFields(req *hubConfigRequest) []lockoutConfigField {
	return []lockoutConfigField{
		{req.LockoutThreshold, lockout.KeyThreshold, "lockout_threshold must be a non-negative integer"},
		{req.LockoutWindowMinutes, lockout.KeyWindowMinutes, "lockout_window_minutes must be a non-negative integer"},
		{req.LockoutDurationMinutes, lockout.KeyDurationMinutes, "lockout_duration_minutes must be a non-negative integer"},
		{req.DormantDays, lockout.KeyDormantDays, "dormant_days must be a non-negative integer"},
		{req.SessionIdleMinutes, lockout.KeySessionIdleMinutes, "session_idle_minutes must be a non-negative integer"},
		{req.SessionMaxHours, lockout.KeySessionMaxHours, "session_max_hours must be a non-negative integer"},
	}
}

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

	fields := lockoutConfigFields(&req)

	// Validate every present lockout field before writing anything, so a
	// rejected PUT never leaves a partial update behind.
	for _, f := range fields {
		if f.value != nil && *f.value < 0 {
			respondError(w, http.StatusBadRequest, f.negativeMsg)
			return
		}
	}

	if req.GRPCExternalAddr != nil {
		if err := s.store.SetConfig("grpc_external_addr", *req.GRPCExternalAddr); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to save hub config")
			return
		}
	}

	for _, f := range fields {
		if f.value == nil {
			continue
		}
		if err := s.store.SetConfig(f.key, strconv.Itoa(*f.value)); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to save hub config")
			return
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
