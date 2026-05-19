package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleAgentBinaryChecksum_Success(t *testing.T) {
	s := testServer(t)

	// Create a temp dir with a fake binary and .sha256 file
	tmpDir := t.TempDir()
	s.agentBinDir = tmpDir

	fakeBinary := []byte("fake-agent-binary-content")
	expectedChecksum := "abc123def456"

	if err := os.WriteFile(filepath.Join(tmpDir, "veyport-agent-linux-amd64"), fakeBinary, 0755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "veyport-agent-linux-amd64.sha256"), []byte(expectedChecksum+"\n"), 0644); err != nil {
		t.Fatalf("write checksum file: %v", err)
	}

	req := httptest.NewRequest("GET", "/install/linux/amd64/sha256", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if body != expectedChecksum {
		t.Fatalf("expected checksum %q, got %q", expectedChecksum, body)
	}

	contentType := rec.Header().Get(testContentType)
	if contentType != "text/plain" {
		t.Fatalf("expected Content-Type text/plain, got %q", contentType)
	}
}

func TestHandleAgentBinaryChecksum_MissingFile(t *testing.T) {
	s := testServer(t)

	// Create a temp dir without any checksum files
	tmpDir := t.TempDir()
	s.agentBinDir = tmpDir

	req := httptest.NewRequest("GET", "/install/linux/arm64/sha256", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing checksum, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAgentBinaryChecksum_UnsupportedPlatform(t *testing.T) {
	s := testServer(t)

	tests := []struct {
		name string
		url  string
	}{
		{"unsupported OS", "/install/darwin/amd64/sha256"},
		{"unsupported arch", "/install/linux/arm32/sha256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("expected 404 for %s, got %d: %s", tt.name, rec.Code, rec.Body.String())
			}
		})
	}
}
