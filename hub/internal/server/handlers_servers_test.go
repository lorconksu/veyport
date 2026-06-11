package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestListServers_Admin(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Create servers directly in the store
	s.store.CreateServer(&model.Server{ID: "s1", Name: "alpha", Status: "online", Labels: "{}"})
	s.store.CreateServer(&model.Server{ID: "s2", Name: "beta", Status: "pending", Labels: "{}"})

	req := httptest.NewRequest("GET", testServersPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	total := int(resp["total"].(float64))
	if total != 2 {
		t.Fatalf("expected total 2, got %d", total)
	}
}

func TestListServers_FilterByStatus(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	s.store.CreateServer(&model.Server{ID: "s1", Name: "alpha", Status: "online", Labels: "{}"})
	s.store.CreateServer(&model.Server{ID: "s2", Name: "beta", Status: "pending", Labels: "{}"})

	req := httptest.NewRequest("GET", "/api/servers?status=online", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200, rec.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	total := int(resp["total"].(float64))
	if total != 1 {
		t.Fatalf("expected total 1, got %d", total)
	}
}

func TestCreateServer(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateServerRequest{
		Name: "web-prod-1",
	})

	req := httptest.NewRequest("POST", testServersPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp model.CreateServerResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Server.Name != "web-prod-1" {
		t.Fatalf("expected name 'web-prod-1', got '%s'", resp.Server.Name)
	}
	if resp.Server.Status != "pending" {
		t.Fatalf("expected status 'pending', got '%s'", resp.Server.Status)
	}
	if resp.RegistrationToken == "" {
		t.Fatal("expected registration_token in response")
	}
	if resp.InstallCommand == "" {
		t.Fatal("expected install_command in response")
	}
	if !strings.Contains(resp.InstallCommand, "--ca-pin '") {
		t.Fatalf("expected install_command to include --ca-pin, got %q", resp.InstallCommand)
	}
	if !strings.Contains(resp.InstallCommand, "id -u") {
		t.Fatalf("expected install_command to handle root shells without sudo, got %q", resp.InstallCommand)
	}
}

func TestCreateServer_InstallCommandUsesRequestHostPort(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateServerRequest{Name: "preview-port-test"})

	req := httptest.NewRequest("POST", "https://10.10.1.95:4443/api/servers", bytes.NewReader(body))
	req.Host = "10.10.1.95:4443"
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp model.CreateServerResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if !strings.Contains(resp.InstallCommand, "https://10.10.1.95:4443/install.sh") {
		t.Fatalf("expected install_command to preserve request host and port, got %q", resp.InstallCommand)
	}
	if !strings.Contains(resp.InstallCommand, "--url 'https://10.10.1.95:4443'") {
		t.Fatalf("expected install_command to preserve request URL host and port, got %q", resp.InstallCommand)
	}
}

func TestCreateServer_InstallCommandUsesConfiguredPublicBaseURL(t *testing.T) {
	t.Setenv("VEYPORT_PUBLIC_BASE_URL", "http://10.10.1.95:8082")

	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateServerRequest{Name: "preview-install-base"})

	req := httptest.NewRequest("POST", "https://preview.example/api/servers", bytes.NewReader(body))
	req.Host = "preview.example"
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp model.CreateServerResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if !strings.Contains(resp.InstallCommand, "http://10.10.1.95:8082/install.sh") {
		t.Fatalf("expected install_command to use configured public base url, got %q", resp.InstallCommand)
	}
	if !strings.Contains(resp.InstallCommand, "--url 'http://10.10.1.95:8082'") {
		t.Fatalf("expected install_command to use configured public base url for downloads, got %q", resp.InstallCommand)
	}
}

func TestCreateServer_InstallCommandPrefersDBStoredPublicBaseURL(t *testing.T) {
	// Ensure the DB-stored public_base_url is preferred over r.Host so an
	// attacker who can spoof the Host header behind a misconfigured proxy
	// cannot poison the generated install command.
	s := testServer(t)
	if err := s.store.SetConfig("public_base_url", "https://hub.internal.example:443"); err != nil {
		t.Fatalf("set public_base_url: %v", err)
	}
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateServerRequest{Name: "preview-db-base"})
	req := httptest.NewRequest("POST", "https://attacker.example/api/servers", bytes.NewReader(body))
	req.Host = "attacker.example"
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.CreateServerResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if !strings.Contains(resp.InstallCommand, "https://hub.internal.example:443/install.sh") {
		t.Fatalf("expected DB-stored public_base_url to win over request Host, got %q", resp.InstallCommand)
	}
	if strings.Contains(resp.InstallCommand, "attacker.example") {
		t.Fatalf("install command leaked attacker-controlled host header: %q", resp.InstallCommand)
	}
}

func TestCreateServer_LegacyAerodocsEnvVarFallback(t *testing.T) {
	// Transitional shim: AERODOCS_PUBLIC_BASE_URL should populate the public
	// base URL when VEYPORT_PUBLIC_BASE_URL is unset, so operators upgrading
	// from v1.x don't fall through to the request Host header.
	t.Setenv("VEYPORT_PUBLIC_BASE_URL", "")
	t.Setenv("AERODOCS_PUBLIC_BASE_URL", "https://legacy.example:8443")
	// Reset the one-shot warning sentinel so a subsequent test run still warns.
	legacyPublicBaseURLWarn.Store(false)

	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateServerRequest{Name: "legacy-env-fallback"})
	req := httptest.NewRequest("POST", "https://attacker.example/api/servers", bytes.NewReader(body))
	req.Host = "attacker.example"
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.CreateServerResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if !strings.Contains(resp.InstallCommand, "https://legacy.example:8443/install.sh") {
		t.Fatalf("expected legacy AERODOCS_PUBLIC_BASE_URL to be honoured, got %q", resp.InstallCommand)
	}
	if strings.Contains(resp.InstallCommand, "attacker.example") {
		t.Fatalf("install command leaked attacker-controlled host header: %q", resp.InstallCommand)
	}
}

func TestCreateServer_VeyportEnvVarPreferredOverLegacy(t *testing.T) {
	// When both env vars are set, the new VEYPORT_PUBLIC_BASE_URL wins.
	t.Setenv("VEYPORT_PUBLIC_BASE_URL", "https://new.example:9443")
	t.Setenv("AERODOCS_PUBLIC_BASE_URL", "https://legacy.example:8443")

	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateServerRequest{Name: "veyport-env-preferred"})
	req := httptest.NewRequest("POST", "https://new.example/api/servers", bytes.NewReader(body))
	req.Host = "new.example"
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp model.CreateServerResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if !strings.Contains(resp.InstallCommand, "https://new.example:9443/install.sh") {
		t.Fatalf("expected VEYPORT_PUBLIC_BASE_URL to win over legacy, got %q", resp.InstallCommand)
	}
	if strings.Contains(resp.InstallCommand, "legacy.example") {
		t.Fatalf("install command should not contain legacy host, got %q", resp.InstallCommand)
	}
}

func TestValidatePublicBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "https with port and path keeps URL but strips trailing slash", input: "https://hub.example:9443/", want: "https://hub.example:9443", wantErr: false},
		{name: "http with port is accepted", input: "http://10.10.1.5:8080", want: "http://10.10.1.5:8080", wantErr: false},
		{name: "missing scheme is rejected", input: "hub.example:9443", wantErr: true},
		{name: "ftp scheme is rejected", input: "ftp://hub.example", wantErr: true},
		{name: "empty host is rejected", input: "https://", wantErr: true},
		{name: "garbage is rejected", input: "not a url", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validatePublicBaseURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validatePublicBaseURL(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validatePublicBaseURL(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("validatePublicBaseURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEnvPublicBaseURL(t *testing.T) {
	t.Run("returns new env var when set", func(t *testing.T) {
		t.Setenv("VEYPORT_PUBLIC_BASE_URL", "https://new.example")
		t.Setenv("AERODOCS_PUBLIC_BASE_URL", "https://legacy.example")
		if got := envPublicBaseURL(); got != "https://new.example" {
			t.Fatalf("envPublicBaseURL() = %q, want new.example", got)
		}
	})
	t.Run("falls back to legacy env var when new is empty", func(t *testing.T) {
		t.Setenv("VEYPORT_PUBLIC_BASE_URL", "")
		t.Setenv("AERODOCS_PUBLIC_BASE_URL", "https://legacy.example")
		legacyPublicBaseURLWarn.Store(false)
		if got := envPublicBaseURL(); got != "https://legacy.example" {
			t.Fatalf("envPublicBaseURL() = %q, want legacy.example", got)
		}
	})
	t.Run("deprecation warning fires at most once", func(t *testing.T) {
		t.Setenv("VEYPORT_PUBLIC_BASE_URL", "")
		t.Setenv("AERODOCS_PUBLIC_BASE_URL", "https://legacy.example")
		legacyPublicBaseURLWarn.Store(false)
		// First call should flip the sentinel to true (CompareAndSwap returns true).
		_ = envPublicBaseURL()
		if !legacyPublicBaseURLWarn.Load() {
			t.Fatal("expected warn sentinel to be true after first call")
		}
		// Second call hits the CompareAndSwap-returns-false branch (no re-log).
		if got := envPublicBaseURL(); got != "https://legacy.example" {
			t.Fatalf("envPublicBaseURL() = %q on repeat call, want legacy.example", got)
		}
	})
	t.Run("returns empty when both unset", func(t *testing.T) {
		t.Setenv("VEYPORT_PUBLIC_BASE_URL", "")
		t.Setenv("AERODOCS_PUBLIC_BASE_URL", "")
		if got := envPublicBaseURL(); got != "" {
			t.Fatalf("envPublicBaseURL() = %q, want empty", got)
		}
	})
}

func TestResolvePublicBaseURL_ErrorPaths(t *testing.T) {
	// Make sure neither env var is set so we exercise the lower fallback
	// branches in resolvePublicBaseURL.
	t.Setenv("VEYPORT_PUBLIC_BASE_URL", "")
	t.Setenv("AERODOCS_PUBLIC_BASE_URL", "")

	t.Run("invalid request Host header rejected", func(t *testing.T) {
		s := testServer(t)
		req := httptest.NewRequest("GET", "http://localhost/", nil)
		// A host containing a forbidden character (space) should fail hostPattern.
		req.Host = "bad host"
		if _, err := s.resolvePublicBaseURL(req); err == nil {
			t.Fatal("expected an error for hostile request Host header")
		}
	})

	t.Run("no request and no config returns error in prod mode", func(t *testing.T) {
		// In dev mode we'd return the localhost default; force prod mode and
		// provide neither a request Host nor a configured grpc-external-addr.
		s := testServer(t)
		s.isDev = false
		s.grpcAddr = ""
		s.grpcExternalAddr = ""
		if _, err := s.resolvePublicBaseURL(nil); err == nil {
			t.Fatal("expected an error when no public hub address is configured")
		}
	})

	t.Run("malformed grpc-derived host rejected", func(t *testing.T) {
		s := testServer(t)
		s.isDev = false
		// Inject a grpc target whose host won't match hostPattern (contains a space).
		s.grpcExternalAddr = "bad host:9443"
		if _, err := s.resolvePublicBaseURL(nil); err == nil {
			t.Fatal("expected an error when grpc-derived host is malformed")
		}
	})
}

func TestCreateServer_InvalidDBStoredPublicBaseURLRejected(t *testing.T) {
	s := testServer(t)
	if err := s.store.SetConfig("public_base_url", "not a url"); err != nil {
		t.Fatalf("set public_base_url: %v", err)
	}
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateServerRequest{Name: "preview-bad-base"})
	req := httptest.NewRequest("POST", "https://10.10.1.95:4443/api/servers", bytes.NewReader(body))
	req.Host = "10.10.1.95:4443"
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusCreated {
		t.Fatalf("expected a non-2xx when stored public_base_url is malformed, got 201 body=%s", rec.Body.String())
	}
}

func TestCreateServer_EmptyName(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.CreateServerRequest{Name: ""})

	req := httptest.NewRequest("POST", testServersPath, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}

func TestGetServer(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	s.store.CreateServer(&model.Server{ID: "s1", Name: "test-srv", Status: "online", Labels: "{}"})

	req := httptest.NewRequest("GET", testServerS1Path, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var srv model.Server
	json.NewDecoder(rec.Body).Decode(&srv)
	if srv.Name != "test-srv" {
		t.Fatalf("expected 'test-srv', got '%s'", srv.Name)
	}
}

func TestGetServer_NotFound(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/nonexistent", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestUpdateServer(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	s.store.CreateServer(&model.Server{ID: "s1", Name: "old-name", Status: "online", Labels: "{}"})

	body, _ := json.Marshal(map[string]string{"name": "new-name", "labels": `{"env":"staging"}`})

	req := httptest.NewRequest("PUT", testServerS1Path, bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

func TestDeleteServer(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	s.store.CreateServer(&model.Server{ID: "s1", Name: "doomed", Status: "online", Labels: "{}"})

	req := httptest.NewRequest("DELETE", testServerS1Path, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	// Verify it's gone
	_, err := s.store.GetServerByID("s1")
	if err == nil {
		t.Fatal("expected server to be deleted")
	}
}

func TestBatchDeleteServers(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	s.store.CreateServer(&model.Server{ID: "s1", Name: "a", Status: "online", Labels: "{}"})
	s.store.CreateServer(&model.Server{ID: "s2", Name: "b", Status: "online", Labels: "{}"})
	s.store.CreateServer(&model.Server{ID: "s3", Name: "c", Status: "online", Labels: "{}"})

	body, _ := json.Marshal(model.BatchDeleteRequest{IDs: []string{"s1", "s3"}})

	req := httptest.NewRequest("POST", "/api/servers/batch-delete", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	// Verify only s2 remains
	servers, total, _ := s.store.ListServers(model.ServerFilter{Limit: 50})
	if total != 1 {
		t.Fatalf("expected 1 remaining, got %d", total)
	}
	if servers[0].ID != "s2" {
		t.Fatalf("expected s2 to survive, got %s", servers[0].ID)
	}
}

func TestBatchDeleteServers_EmptyList(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body, _ := json.Marshal(model.BatchDeleteRequest{IDs: []string{}})

	req := httptest.NewRequest("POST", "/api/servers/batch-delete", bytes.NewReader(body))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400, rec.Code)
	}
}
