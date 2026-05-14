package server

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/model"
)

var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9._:\-]+$`)

func hostFromAddr(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := model.ServerFilter{}
	filter.Limit, filter.Offset = parsePagination(q, 50)

	if v := q.Get("status"); v != "" {
		filter.Status = &v
	}
	if v := q.Get("search"); v != "" {
		filter.Search = &v
	}

	role := UserRoleFromContext(r.Context())
	userID := UserIDFromContext(r.Context())

	var servers []model.Server
	var total int
	var err error

	if role == "admin" {
		servers, total, err = s.store.ListServers(filter)
	} else {
		servers, total, err = s.store.ListServersForUser(userID, filter)
	}

	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list servers")
		return
	}

	respondJSON(w, http.StatusOK, model.ServerListResponse{
		Servers: servers,
		Total:   total,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
	})
}

// resolveGRPCTarget determines the gRPC target address using priority:
// DB setting > CLI flag > default (hostname:9443). In dev mode, uses the raw
// gRPC listen address.
func (s *Server) resolveGRPCTarget(host string) string {
	if s.isDev {
		return s.grpcAddr
	}
	// Default: derive from Host header with port 9443
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	target := hostname + ":9443"

	// CLI flag override
	if s.grpcExternalAddr != "" {
		target = s.grpcExternalAddr
	}

	// DB setting override (admin UI)
	if dbAddr, err := s.store.GetConfig("grpc_external_addr"); err == nil && dbAddr != "" {
		target = dbAddr
	}
	return target
}

func (s *Server) resolvePublicBaseURL(r *http.Request) (string, error) {
	if raw := strings.TrimSpace(os.Getenv("AERODOCS_PUBLIC_BASE_URL")); raw != "" {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return "", fmt.Errorf("invalid public base url")
		}
		return strings.TrimRight(raw, "/"), nil
	}

	if r != nil && r.Host != "" {
		host := r.Host
		if !hostPattern.MatchString(host) {
			return "", fmt.Errorf("invalid public hub address")
		}
		return fmt.Sprintf("%s://%s", s.requestScheme(r), host), nil
	}

	if s.isDev {
		return "http://localhost:8080", nil
	}

	grpcTarget := s.resolveGRPCTarget("")
	if grpcTarget == "" {
		return "", fmt.Errorf("public hub address is not configured")
	}

	host := hostFromAddr(grpcTarget)
	if host == "" || !hostPattern.MatchString(host) {
		return "", fmt.Errorf("invalid public hub address")
	}

	return fmt.Sprintf("https://%s", host), nil
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	var req model.CreateServerRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "server name is required")
		return
	}

	// Check for duplicate server names
	if existing, err := s.store.GetServerByName(req.Name); err == nil && existing != nil {
		respondError(w, http.StatusConflict, "a server with this name already exists")
		return
	}

	if req.Labels == "" {
		req.Labels = "{}"
	}

	// Generate raw registration token
	rawToken := uuid.NewString()

	// Hash it for storage
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := fmt.Sprintf("%x", hash)

	expiresAt := time.Now().Add(1 * time.Hour).UTC().Format("2006-01-02 15:04:05")

	srv := &model.Server{
		ID:                uuid.NewString(),
		Name:              req.Name,
		Status:            "pending",
		RegistrationToken: &tokenHash,
		TokenExpiresAt:    &expiresAt,
		Labels:            req.Labels,
	}

	if err := s.store.CreateServer(srv); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create server")
		return
	}

	adminID := UserIDFromContext(r.Context())
	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &adminID,
		Action:    model.AuditServerCreated,
		Target:    &srv.ID,
		IPAddress: &ip,
	})

	baseURL, err := s.resolvePublicBaseURL(r)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "public hub address is not configured")
		return
	}
	grpcTarget := s.resolveGRPCTarget(hostFromAddr(strings.TrimPrefix(baseURL, "https://")))

	// Validate the gRPC target address (skip in dev mode where listen addr may be ":0")
	if !s.isDev && !isValidGRPCAddr(grpcTarget) {
		respondError(w, http.StatusInternalServerError, "invalid gRPC address")
		return
	}

	// Compute the HMAC-based self-unregister token for this server
	unregisterToken := s.selfUnregisterToken(srv.ID)

	installArgs := fmt.Sprintf(
		"-s -- --token '%s' --hub '%s' --url '%s' --unregister-token '%s' --ca-pin '%s'",
		rawToken, grpcTarget, baseURL, unregisterToken, s.grpcCACertSHA256,
	)
	installCmd := fmt.Sprintf(
		"curl -sSL '%s/install.sh' | { if [ \"$(id -u)\" -eq 0 ]; then bash %s; elif command -v sudo >/dev/null 2>&1; then sudo bash %s; elif command -v doas >/dev/null 2>&1; then doas bash %s; else echo 'This installer needs root. Re-run as root or install sudo/doas.' >&2; exit 1; fi; }",
		baseURL, installArgs, installArgs, installArgs,
	)

	respondJSON(w, http.StatusCreated, model.CreateServerResponse{
		Server:            *srv,
		RegistrationToken: rawToken,
		InstallCommand:    installCmd,
	})
}

func (s *Server) handleGetServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Check role first — non-admins get 403 whether or not the server exists
	// to avoid leaking server IDs via 404 vs 403 differences.
	role := UserRoleFromContext(r.Context())

	srv, err := s.store.GetServerByID(id)
	if err != nil {
		if role != "admin" {
			respondError(w, http.StatusForbidden, "access denied")
			return
		}
		respondError(w, http.StatusNotFound, errServerNotFound)
		return
	}

	// Viewers must have permission on this specific server
	if role != "admin" {
		userID := UserIDFromContext(r.Context())
		paths, err := s.store.GetUserPathsForServer(userID, id)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to check permissions")
			return
		}
		if len(paths) == 0 {
			respondError(w, http.StatusForbidden, "access denied")
			return
		}
	}

	respondJSON(w, http.StatusOK, srv)
}

func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req struct {
		Name   string `json:"name"`
		Labels string `json:"labels"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "server name is required")
		return
	}

	if err := s.store.UpdateServer(id, req.Name, req.Labels); err != nil {
		respondError(w, http.StatusNotFound, errServerNotFound)
		return
	}

	adminID := UserIDFromContext(r.Context())
	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &adminID,
		Action:    model.AuditServerUpdated,
		Target:    &id,
		IPAddress: &ip,
	})

	srv, _ := s.store.GetServerByID(id)
	respondJSON(w, http.StatusOK, srv)
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if err := s.store.DeleteServer(id); err != nil {
		respondError(w, http.StatusNotFound, errServerNotFound)
		return
	}

	// Disconnect the agent if it's currently connected
	if s.connMgr != nil {
		s.connMgr.Unregister(id)
	}

	adminID := UserIDFromContext(r.Context())
	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &adminID,
		Action:    model.AuditServerDeleted,
		Target:    &id,
		IPAddress: &ip,
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleBatchDeleteServers(w http.ResponseWriter, r *http.Request) {
	var req model.BatchDeleteRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	if len(req.IDs) == 0 {
		respondError(w, http.StatusBadRequest, "ids list cannot be empty")
		return
	}
	if len(req.IDs) > 100 {
		respondError(w, http.StatusBadRequest, "maximum 100 servers per batch")
		return
	}

	if err := s.store.DeleteServers(req.IDs); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete servers")
		return
	}

	// Disconnect any agents that were connected
	if s.connMgr != nil {
		for _, id := range req.IDs {
			s.connMgr.Unregister(id)
		}
	}

	adminID := UserIDFromContext(r.Context())
	ip := clientIP(r)
	detail := fmt.Sprintf("deleted %d servers", len(req.IDs))
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &adminID,
		Action:    model.AuditServerBatchDeleted,
		Detail:    &detail,
		IPAddress: &ip,
	})

	respondJSON(w, http.StatusOK, model.BatchDeleteResponse{
		Status:  "deleted",
		Deleted: len(req.IDs),
	})
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/install.sh")
}

func (s *Server) handleAgentBinary(w http.ResponseWriter, r *http.Request) {
	osName := r.PathValue("os")
	arch := r.PathValue("arch")
	if osName != "linux" || (arch != "amd64" && arch != "arm64") {
		respondError(w, http.StatusNotFound, "unsupported platform")
		return
	}
	filename := fmt.Sprintf("aerodocs-agent-%s-%s", osName, arch)
	binaryPath := filepath.Join(s.agentBinDir, filename)
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		respondError(w, http.StatusNotFound, "agent binary not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	http.ServeFile(w, r, binaryPath)
}

func (s *Server) handleAgentBinaryChecksum(w http.ResponseWriter, r *http.Request) {
	osName := r.PathValue("os")
	arch := r.PathValue("arch")
	if osName != "linux" || (arch != "amd64" && arch != "arm64") {
		respondError(w, http.StatusNotFound, "unsupported platform")
		return
	}
	filename := fmt.Sprintf("aerodocs-agent-%s-%s.sha256", osName, arch)
	checksumPath := filepath.Join(s.agentBinDir, filename)
	data, err := os.ReadFile(checksumPath)
	if err != nil {
		respondError(w, http.StatusNotFound, "checksum not found")
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(strings.TrimSpace(string(data))))
}

// isValidGRPCAddr validates a gRPC address (host:port format).
func isValidGRPCAddr(addr string) bool {
	if addr == "" {
		return false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || port == "" {
		return false
	}
	return hostPattern.MatchString(host)
}
