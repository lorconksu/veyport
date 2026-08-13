package server

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliPlatform is a supported (os, arch) combination for the `vey` CLI binary,
// per the allowlist in specs/004-cli-connector/contracts/rest-api.md.
type cliPlatform struct {
	os   string
	arch string
}

var cliAllowedPlatforms = []cliPlatform{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
}

// writeCLIFixture writes a fake vey-{os}-{arch} binary and matching .sha256
// checksum file into dir, returning the binary content and checksum string.
func writeCLIFixture(t *testing.T, dir, osName, arch string) (content, checksum string) {
	t.Helper()
	content = fmt.Sprintf("fake-vey-cli-%s-%s", osName, arch)
	checksum = fmt.Sprintf("checksum-%s-%s", osName, arch)

	binName := fmt.Sprintf("vey-%s-%s", osName, arch)
	if err := os.WriteFile(filepath.Join(dir, binName), []byte(content), 0755); err != nil {
		t.Fatalf("write fake cli binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, binName+".sha256"), []byte(checksum+"\n"), 0644); err != nil {
		t.Fatalf("write cli checksum file: %v", err)
	}
	return content, checksum
}

func TestHandleCLIBinary_ServesForAllowedPlatforms(t *testing.T) {
	s := testServer(t)
	tmpDir := t.TempDir()
	s.agentBinDir = tmpDir

	for _, p := range cliAllowedPlatforms {
		p := p
		t.Run(p.os+"/"+p.arch, func(t *testing.T) {
			content, _ := writeCLIFixture(t, tmpDir, p.os, p.arch)

			req := httptest.NewRequest("GET", fmt.Sprintf("/install/cli/%s/%s", p.os, p.arch), nil)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
			}
			if rec.Body.String() != content {
				t.Fatalf("expected body %q, got %q", content, rec.Body.String())
			}
			if ct := rec.Header().Get(testContentType); ct != "application/octet-stream" {
				t.Fatalf("expected Content-Type application/octet-stream, got %q", ct)
			}
			wantDisposition := fmt.Sprintf(`attachment; filename="vey-%s-%s"`, p.os, p.arch)
			if cd := rec.Header().Get("Content-Disposition"); cd != wantDisposition {
				t.Fatalf("expected Content-Disposition %q, got %q", wantDisposition, cd)
			}
		})
	}
}

func TestHandleCLIBinaryChecksum_ServesForAllowedPlatforms(t *testing.T) {
	s := testServer(t)
	tmpDir := t.TempDir()
	s.agentBinDir = tmpDir

	for _, p := range cliAllowedPlatforms {
		p := p
		t.Run(p.os+"/"+p.arch, func(t *testing.T) {
			_, checksum := writeCLIFixture(t, tmpDir, p.os, p.arch)

			req := httptest.NewRequest("GET", fmt.Sprintf("/install/cli/%s/%s/sha256", p.os, p.arch), nil)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
			}
			if rec.Body.String() != checksum {
				t.Fatalf("expected checksum %q, got %q", checksum, rec.Body.String())
			}
			if ct := rec.Header().Get(testContentType); ct != "text/plain" {
				t.Fatalf("expected Content-Type text/plain, got %q", ct)
			}
		})
	}
}

func TestHandleCLIBinary_UnsupportedPlatform(t *testing.T) {
	s := testServer(t)
	tmpDir := t.TempDir()
	s.agentBinDir = tmpDir

	// Populate every allowed platform so a 404 can only be explained by the
	// allowlist rejecting the (os, arch) pair, not by a missing file.
	for _, p := range cliAllowedPlatforms {
		writeCLIFixture(t, tmpDir, p.os, p.arch)
	}

	tests := []struct {
		name string
		url  string
	}{
		{"unsupported OS", "/install/cli/windows/amd64"},
		{"unsupported OS checksum", "/install/cli/windows/amd64/sha256"},
		{"unsupported arch", "/install/cli/linux/arm32"},
		{"unsupported arch checksum", "/install/cli/linux/arm32/sha256"},
		{"path traversal literal dotdot as os", "/install/cli/..%2f..%2fetc/amd64"},
		{"path traversal literal dotdot as arch", "/install/cli/linux/..%2f..%2fetc%2fpasswd"},
		{"path traversal encoded dotdot as os", "/install/cli/%2e%2e/amd64"},
		{"absolute-path-like arch", "/install/cli/linux/%2Fetc%2Fpasswd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("expected 404 for %s (%s), got %d: %s", tt.name, tt.url, rec.Code, rec.Body.String())
			}
			// Never disclose the raw binary bytes for a rejected platform.
			for _, p := range cliAllowedPlatforms {
				content := fmt.Sprintf("fake-vey-cli-%s-%s", p.os, p.arch)
				if rec.Body.String() == content {
					t.Fatalf("response leaked binary content for %s: %s", tt.url, rec.Body.String())
				}
			}
		})
	}
}

// TestHandleCLIBinary_DotSegmentRedirectDoesNotDisclose verifies that a
// "." path segment (which net/http's ServeMux itself cleans via a 307
// redirect before pattern matching even runs) never lands on a route that
// discloses a binary — following the redirect must still end up 404.
func TestHandleCLIBinary_DotSegmentRedirectDoesNotDisclose(t *testing.T) {
	s := testServer(t)
	tmpDir := t.TempDir()
	s.agentBinDir = tmpDir
	for _, p := range cliAllowedPlatforms {
		writeCLIFixture(t, tmpDir, p.os, p.arch)
	}

	req := httptest.NewRequest("GET", "/install/cli/./amd64", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	switch rec.Code {
	case http.StatusNotFound:
		// Rejected directly — fine.
	case http.StatusTemporaryRedirect, http.StatusMovedPermanently:
		location := rec.Header().Get("Location")
		req2 := httptest.NewRequest("GET", location, nil)
		rec2 := httptest.NewRecorder()
		s.routes().ServeHTTP(rec2, req2)
		if rec2.Code == http.StatusOK {
			t.Fatalf("dot-segment redirect to %q served a binary (200)", location)
		}
	default:
		t.Fatalf("unexpected status for dot-segment path: %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleCLIBinary_PathTraversalRejectedAtHandlerLevel calls the handler
// directly with PathValues set to values that a hostile client could not
// normally get past net/http's mux path cleaning, to prove the allowlist
// check (not just mux routing/path cleaning) is what blocks traversal.
func TestHandleCLIBinary_PathTraversalRejectedAtHandlerLevel(t *testing.T) {
	tmpDir := t.TempDir()

	// Plant a decoy file one level above tmpDir that a naive
	// filepath.Join(binDir, "../decoy") could disclose.
	decoyContent := "outside-bin-dir-secret"
	decoyPath := filepath.Join(filepath.Dir(tmpDir), "decoy-vey-linux-amd64")
	if err := os.WriteFile(decoyPath, []byte(decoyContent), 0644); err != nil {
		t.Fatalf("write decoy file: %v", err)
	}
	t.Cleanup(func() { os.Remove(decoyPath) })

	s := testServer(t)
	s.agentBinDir = tmpDir

	tests := []struct {
		name string
		os   string
		arch string
	}{
		{"dotdot os", "../" + filepath.Base(tmpDir), "amd64"},
		{"dotdot arch", "linux", "../" + filepath.Base(tmpDir)},
		{"empty os", "", "amd64"},
		{"empty arch", "linux", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name+" binary", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/install/cli/x/y", nil)
			req.SetPathValue("os", tt.os)
			req.SetPathValue("arch", tt.arch)
			rec := httptest.NewRecorder()
			s.handleCLIBinary(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
			}
			if rec.Body.String() == decoyContent {
				t.Fatalf("handler leaked decoy content outside bin dir")
			}
		})

		t.Run(tt.name+" checksum", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/install/cli/x/y/sha256", nil)
			req.SetPathValue("os", tt.os)
			req.SetPathValue("arch", tt.arch)
			rec := httptest.NewRecorder()
			s.handleCLIBinaryChecksum(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHandleCLIBinary_UnbuiltPlatform(t *testing.T) {
	s := testServer(t)
	// Empty dir: platform is allowlisted but no binary has been built for it.
	s.agentBinDir = t.TempDir()

	req := httptest.NewRequest("GET", "/install/cli/darwin/arm64", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unbuilt platform, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCLIBinaryChecksum_UnbuiltPlatform(t *testing.T) {
	s := testServer(t)
	s.agentBinDir = t.TempDir()

	req := httptest.NewRequest("GET", "/install/cli/darwin/arm64/sha256", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unbuilt platform checksum, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestExistingAgentBinaryRoutes_StillLinuxOnly is a regression guard: the CLI
// route generalization must not widen the agent binary allowlist to darwin.
func TestExistingAgentBinaryRoutes_StillLinuxOnly(t *testing.T) {
	s := testServer(t)
	tmpDir := t.TempDir()
	s.agentBinDir = tmpDir

	if err := os.WriteFile(filepath.Join(tmpDir, "veyport-agent-darwin-amd64"), []byte("x"), 0755); err != nil {
		t.Fatalf("write fake agent binary: %v", err)
	}

	req := httptest.NewRequest("GET", "/install/darwin/amd64", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected agent binary route to still reject darwin, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleInstall3rdSegmentDispatch_NeitherRouteMatches covers the final
// fallthrough in handleInstall3rdSegmentDispatch: a 3-segment "/install/a/b/c"
// path where c != "sha256" (so it isn't the agent-checksum route) and
// a != "cli" (so it isn't the CLI-binary route) matches neither
// interpretation and must 404.
func TestHandleInstall3rdSegmentDispatch_NeitherRouteMatches(t *testing.T) {
	s := testServer(t)
	s.agentBinDir = t.TempDir()

	req := httptest.NewRequest("GET", "/install/foo/bar/baz", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unmatched 3-segment install path, got %d: %s", rec.Code, rec.Body.String())
	}
}

// failingResponseWriter is an http.ResponseWriter whose Write always fails,
// used to exercise handleCLIBinaryChecksum's write-error logging path.
type failingResponseWriter struct {
	header http.Header
}

func (w *failingResponseWriter) Header() http.Header { return w.header }

func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("simulated write failure")
}

func (w *failingResponseWriter) WriteHeader(int) {}

// TestHandleCLIBinaryChecksum_WriteFailureIsLogged covers the error branch
// in handleCLIBinaryChecksum where writing the checksum response body fails:
// the handler must log the failure rather than panic or return an error to
// the caller (the response has already started, so there is nothing else it
// can do).
func TestHandleCLIBinaryChecksum_WriteFailureIsLogged(t *testing.T) {
	s := testServer(t)
	tmpDir := t.TempDir()
	s.agentBinDir = tmpDir
	writeCLIFixture(t, tmpDir, "linux", "amd64")

	var logBuf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOutput) })

	req := httptest.NewRequest("GET", "/install/cli/linux/amd64/sha256", nil)
	req.SetPathValue("os", "linux")
	req.SetPathValue("arch", "amd64")

	w := &failingResponseWriter{header: make(http.Header)}
	s.handleCLIBinaryChecksum(w, req)

	if !strings.Contains(logBuf.String(), "cli checksum write failed") {
		t.Fatalf("expected write-failure log message, got %q", logBuf.String())
	}
}
