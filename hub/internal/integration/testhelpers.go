package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/ca"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
	"github.com/wyiu/veyport/hub/internal/store"
)

const (
	// httpURLFormat is the format string used to build HTTP URLs for the test harness.
	httpURLFormat = "http://%s%s"
	// bearerPrefix is the Authorization header prefix for bearer tokens.
	bearerPrefix  = "Bearer "
	cookieAccess  = "veyport_access"
	cookieRefresh = "veyport_refresh"
)

// TestHarness holds all components for an in-process hub integration test.
type TestHarness struct {
	Store       *store.Store
	ConnMgr     *connmgr.ConnManager
	Pending     *grpcserver.PendingRequests
	LogSessions *grpcserver.LogSessions
	HTTPServer  *server.Server
	GRPCAddr    string
	HTTPAddr    string
	JWTSecret   string
	HubCAPin    string
}

// StartHarness starts an in-process hub (gRPC + HTTP) and returns a TestHarness.
// It registers cleanup to stop both servers and close the store.
func StartHarness(t *testing.T) *TestHarness {
	t.Helper()

	// Create in-memory store
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	// Initialize JWT secret
	jwtSecret, err := server.InitJWTSecret(st)
	if err != nil {
		st.Close()
		t.Fatalf("init jwt secret: %v", err)
	}

	// Initialize CA
	caCert, caKey, err := ca.InitCA(st, jwtSecret)
	if err != nil {
		st.Close()
		t.Fatalf("init CA: %v", err)
	}

	cm := connmgr.New()
	pending := grpcserver.NewPendingRequests()
	logSessions := grpcserver.NewLogSessions()
	grpcCAPin := fmt.Sprintf("%x", sha256.Sum256(caCert.Raw))

	// Find two free TCP ports
	grpcPort := freePort(t)
	httpPort := freePort(t)

	grpcAddr := fmt.Sprintf("127.0.0.1:%d", grpcPort)
	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

	// Start gRPC server
	gs := grpcserver.New(grpcserver.Config{
		Addr:                   grpcAddr,
		HeartbeatFlushInterval: 1 * time.Second,
		Store:                  st,
		ConnMgr:                cm,
		Pending:                pending,
		LogSessions:            logSessions,
		CACert:                 caCert,
		CAKey:                  caKey,
	})

	grpcErrCh := make(chan error, 1)
	go func() {
		grpcErrCh <- gs.Start()
	}()

	// Start HTTP server
	hs := server.New(server.Config{
		Addr:             httpAddr,
		Store:            st,
		JWTSecret:        jwtSecret,
		IsDev:            true,
		FrontendFS:       nil,
		AgentBinDir:      "",
		GRPCAddr:         grpcAddr,
		GRPCCACertSHA256: grpcCAPin,
		ConnMgr:          cm,
		Pending:          pending,
		LogSessions:      logSessions,
	})

	httpErrCh := make(chan error, 1)
	go func() {
		httpErrCh <- hs.Start()
	}()

	// Wait for both ports to be ready
	waitForPort(t, grpcAddr, 5*time.Second)
	waitForPort(t, httpAddr, 5*time.Second)

	// Check for immediate startup errors
	select {
	case err := <-grpcErrCh:
		t.Fatalf("gRPC server failed to start: %v", err)
	default:
	}
	select {
	case err := <-httpErrCh:
		t.Fatalf("HTTP server failed to start: %v", err)
	default:
	}

	// Register cleanup
	t.Cleanup(func() {
		gs.Stop()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
		st.Close()
	})

	return &TestHarness{
		Store:       st,
		ConnMgr:     cm,
		Pending:     pending,
		LogSessions: logSessions,
		HTTPServer:  hs,
		GRPCAddr:    grpcAddr,
		HTTPAddr:    httpAddr,
		JWTSecret:   jwtSecret,
		HubCAPin:    grpcCAPin,
	}
}

// SetupAdmin registers the first admin user, completes TOTP setup, and returns
// an access token.
func (h *TestHarness) SetupAdmin(t *testing.T) string {
	t.Helper()

	baseURL := fmt.Sprintf("http://%s", h.HTTPAddr)

	// Register first user (admin)
	regBody := map[string]string{
		"username": "admin",
		"email":    "admin@test.com",
		"password": "TestPassword123!",
	}
	resp := h.HTTPPost(t, "/api/auth/register", regBody, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register admin: status=%d body=%s", resp.StatusCode, body)
	}

	var regResp struct {
		SetupToken string `json:"setup_token"`
	}
	json.NewDecoder(resp.Body).Decode(&regResp)

	// TOTP setup
	setupResp := h.HTTPPost(t, "/api/auth/totp/setup", nil, regResp.SetupToken)
	defer setupResp.Body.Close()
	if setupResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(setupResp.Body)
		t.Fatalf("totp setup: status=%d body=%s url=%s", setupResp.StatusCode, body, baseURL+"/api/auth/totp/setup")
	}

	var totpResp model.TOTPSetupResponse
	json.NewDecoder(setupResp.Body).Decode(&totpResp)

	// Generate valid TOTP code and enable
	code, err := auth.GenerateValidCode(totpResp.Secret)
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}

	enableResp := h.HTTPPost(t, "/api/auth/totp/enable", model.TOTPEnableRequest{Code: code}, regResp.SetupToken)
	defer enableResp.Body.Close()
	if enableResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(enableResp.Body)
		t.Fatalf("totp enable: status=%d body=%s", enableResp.StatusCode, body)
	}

	var authResp model.AuthResponse
	json.NewDecoder(enableResp.Body).Decode(&authResp)

	for _, cookie := range enableResp.Cookies() {
		if cookie.Name == cookieAccess && cookie.Value != "" {
			return cookie.Value
		}
	}

	t.Fatal("SetupAdmin: got empty access token cookie")
	return ""
}

// CreateServer calls POST /api/servers and returns the server ID and the plaintext
// registration token.
func (h *TestHarness) CreateServer(t *testing.T, accessToken, name string) (serverID, registrationToken string) {
	t.Helper()

	resp := h.HTTPPost(t, "/api/servers", model.CreateServerRequest{Name: name}, accessToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create server: status=%d body=%s", resp.StatusCode, body)
	}

	var csResp model.CreateServerResponse
	json.NewDecoder(resp.Body).Decode(&csResp)

	return csResp.Server.ID, csResp.RegistrationToken
}

// HTTPGet performs a GET request against the hub's HTTP server.
func (h *TestHarness) HTTPGet(t *testing.T, path, token string) *http.Response {
	t.Helper()

	url := fmt.Sprintf(httpURLFormat, h.HTTPAddr, path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("create GET request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", bearerPrefix+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

// httpRequestWithBody builds and executes an HTTP request with an optional JSON body.
// It is the shared implementation for HTTPPost and HTTPPut.
func (h *TestHarness) httpRequestWithBody(t *testing.T, method, path string, body interface{}, token string) *http.Response {
	t.Helper()

	url := fmt.Sprintf(httpURLFormat, h.HTTPAddr, path)

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("create %s request: %v", method, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", bearerPrefix+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// HTTPPost performs a POST request against the hub's HTTP server.
func (h *TestHarness) HTTPPost(t *testing.T, path string, body interface{}, token string) *http.Response {
	t.Helper()
	return h.httpRequestWithBody(t, "POST", path, body, token)
}

// HTTPPut performs a PUT request against the hub's HTTP server.
func (h *TestHarness) HTTPPut(t *testing.T, path string, body interface{}, token string) *http.Response {
	t.Helper()
	return h.httpRequestWithBody(t, "PUT", path, body, token)
}

// freePort returns a free TCP port on localhost.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// waitForPort polls a TCP address until it accepts connections or the timeout expires.
func waitForPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %s not ready within %v", addr, timeout)
}

// StartAgentProcess is in agent_process_test.go (needs access to test-only vars from main_test.go)
