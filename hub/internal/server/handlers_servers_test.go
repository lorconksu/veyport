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
