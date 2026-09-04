package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"text/template"

	"github.com/wyiu/veyport/hub"
)

// TestHandleInstallCLIScript_WriteFailureIsLogged covers the branch where
// writing the rendered script to the response body fails: the handler must
// log the failure rather than panic (mirrors
// TestHandleCLIBinaryChecksum_WriteFailureIsLogged for the sibling
// checksum-serving handler).
func TestHandleInstallCLIScript_WriteFailureIsLogged(t *testing.T) {
	t.Setenv("VEYPORT_PUBLIC_BASE_URL", "https://hub.example")
	s := testServer(t)

	var logBuf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOutput) })

	req := httptest.NewRequest("GET", "/install/cli.sh", nil)
	w := &failingResponseWriter{header: make(http.Header)}
	s.handleInstallCLIScript(w, req)

	if !strings.Contains(logBuf.String(), "install-cli.sh write failed") {
		t.Fatalf("expected write-failure log message, got %q", logBuf.String())
	}
}

// TestHandleInstallCLIScript_UsesConfiguredPublicBaseURL verifies the
// templated one-liner (GET /install/cli.sh) renders the hub's configured
// public base URL with no leftover template markers, and needs no
// Authorization header (specs/006-cli-install-script/proposal.md: public,
// unauthenticated, same as /install.sh).
func TestHandleInstallCLIScript_UsesConfiguredPublicBaseURL(t *testing.T) {
	t.Setenv("VEYPORT_PUBLIC_BASE_URL", "https://hub.example:8443")

	s := testServer(t)
	req := httptest.NewRequest("GET", "/install/cli.sh", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get(testContentType); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Fatalf("expected shellscript content type, got %q", ct)
	}

	body := rec.Body.String()
	if !strings.HasPrefix(body, "#!/bin/sh") {
		t.Fatalf("expected script to start with #!/bin/sh, got %q", body[:min(40, len(body))])
	}
	if !strings.Contains(body, "https://hub.example:8443") {
		t.Fatalf("expected rendered script to contain the configured base URL, got:\n%s", body)
	}
	if strings.Contains(body, "{{") || strings.Contains(body, "}}") {
		t.Fatalf("expected no leftover template markers in rendered script, got:\n%s", body)
	}
}

// TestHandleInstallCLIScript_RequestHostFallback verifies that with no
// configured VEYPORT_PUBLIC_BASE_URL, the base URL is derived from the
// request (mirrors resolvePublicBaseURL's request-fallback branch used by
// TestCreateServer_InstallCommandUsesRequestHostPort).
func TestHandleInstallCLIScript_RequestHostFallback(t *testing.T) {
	t.Setenv("VEYPORT_PUBLIC_BASE_URL", "")
	t.Setenv("AERODOCS_PUBLIC_BASE_URL", "")

	s := testServer(t)
	// httptest.NewRequest sets r.TLS for an https:// target, which is what
	// drives requestScheme() to report "https" here.
	req := httptest.NewRequest("GET", "https://10.10.1.95:4443/install/cli.sh", nil)
	req.Host = "10.10.1.95:4443"
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://10.10.1.95:4443") {
		t.Fatalf("expected rendered script to derive base URL from request host, got:\n%s", body)
	}
	if strings.Contains(body, "{{") {
		t.Fatalf("expected no leftover template markers, got:\n%s", body)
	}
}

// TestHandleInstallCLIScript_NoAuthRequired verifies the route is reachable
// without any Authorization header, matching /install.sh's public route.
func TestHandleInstallCLIScript_NoAuthRequired(t *testing.T) {
	t.Setenv("VEYPORT_PUBLIC_BASE_URL", "https://hub.example")

	s := testServer(t)
	req := httptest.NewRequest("GET", "/install/cli.sh", nil)
	// Deliberately no Authorization header.
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected unauthenticated request to succeed, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleInstallCLIScript_ResolveErrorReturns500 verifies that a
// resolvePublicBaseURL failure (here: a request Host header that fails
// hostPattern validation) is surfaced as a 500 rather than a partially
// rendered script.
func TestHandleInstallCLIScript_ResolveErrorReturns500(t *testing.T) {
	t.Setenv("VEYPORT_PUBLIC_BASE_URL", "")
	t.Setenv("AERODOCS_PUBLIC_BASE_URL", "")

	s := testServer(t)
	req := httptest.NewRequest("GET", "/install/cli.sh", nil)
	req.Host = "bad host"
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for unresolvable public base URL, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestInstallCLIScript_RenderedScriptIsValidPOSIXSh renders the embedded
// template with a dummy base URL and runs `sh -n` (syntax-check only) over
// the result, catching bashisms or quoting mistakes that unit tests over the
// HTTP handler alone would not. Skips if `sh` isn't on PATH.
func TestInstallCLIScript_RenderedScriptIsValidPOSIXSh(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available on PATH")
	}

	rendered := renderInstallCLIScriptForTest(t, "https://hub.example:8443")

	if !strings.Contains(rendered, "sha256sum") || !strings.Contains(rendered, "shasum") {
		t.Fatalf("expected rendered script to reference both checksum tools (sha256sum, shasum), got:\n%s", rendered)
	}

	cmd := exec.Command("sh", "-n", "-")
	cmd.Stdin = strings.NewReader(rendered)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sh -n reported a syntax error: %v\n%s", err, stderr.String())
	}
}

// renderInstallCLIScriptForTest parses and executes the embedded
// install-cli.sh template directly (independent of the HTTP handler) so the
// syntax-check test above exercises exactly the same template the handler
// serves.
func renderInstallCLIScriptForTest(t *testing.T, baseURL string) string {
	t.Helper()
	tmpl, err := template.New("install-cli.sh").Parse(string(hub.InstallCLIScript))
	if err != nil {
		t.Fatalf("parse install-cli.sh template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ BaseURL string }{BaseURL: baseURL}); err != nil {
		t.Fatalf("execute install-cli.sh template: %v", err)
	}
	return buf.String()
}
