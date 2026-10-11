package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

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

const (
	installerOldVersion = "vey v2.0.28-11-g7c196b7-staging"
	installerNewVersion = "vey 2.0.50-prototype.2"
)

// installerProcessFixture runs the actual rendered POSIX script with private
// download fixtures. Only the fixed system install directory is redirected;
// no real install location, sudo or network request is touched.
type installerProcessFixture struct {
	home, systemBin, tools, scratch, payload, checksum, sudoCalled, requestLog string
}

func newInstallerProcessFixture(t *testing.T) installerProcessFixture {
	t.Helper()
	root := t.TempDir()
	f := installerProcessFixture{
		home: filepath.Join(root, "home with 'quote"), systemBin: filepath.Join(root, "system-bin"),
		tools: filepath.Join(root, "tools"), scratch: filepath.Join(root, "scratch"),
		payload: filepath.Join(root, "payload"), checksum: filepath.Join(root, "checksum"),
		sudoCalled: filepath.Join(root, "sudo-called"), requestLog: filepath.Join(root, "requests"),
	}
	for _, directory := range []string{f.userBin(), f.systemBin, f.tools, f.scratch} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeInstallerExecutable(t, f.payload, installerNewVersion)
	body, err := os.ReadFile(f.payload)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.checksum, []byte(fmt.Sprintf("%x\n", sha256.Sum256(body))), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name, script string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(f.tools, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("curl", `#!/bin/sh
set -eu
[ "$1" = '-fsSL' ] && [ "$3" = '-o' ] && [ "$#" -eq 4 ]
printf '%s\n' "$2" >> "$VEYPORT_TEST_REQUEST_LOG"
case "$2" in
  */sha256) cp "$VEYPORT_TEST_CHECKSUM_FILE" "$4" ;;
  *) cp "$VEYPORT_TEST_PAYLOAD_FILE" "$4" ;;
esac
`)
	write("uname", `#!/bin/sh
case "$1" in
  -s) printf '%s\n' "$VEYPORT_TEST_OS" ;;
  -m) printf '%s\n' "$VEYPORT_TEST_ARCH" ;;
  *) exit 1 ;;
esac
`)
	write("sudo", `#!/bin/sh
printf called > "$VEYPORT_TEST_SUDO_CALLED"
exit 1
`)
	return f
}

func (f installerProcessFixture) userBin() string { return filepath.Join(f.home, ".local", "bin") }

func writeInstallerExecutable(t *testing.T, destination, version string) {
	t.Helper()
	script := "#!/bin/sh\n[ \"${1:-}\" = --version ] || exit 42\nprintf '%s\\n' '" + version + "'\n"
	if err := os.WriteFile(destination, []byte(script), 0o775); err != nil {
		t.Fatal(err)
	}
}

func (f installerProcessFixture) run(t *testing.T, pathValue, osName, arch string) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(renderInstallCLIScriptForTest(t, "https://hub.example"), "/usr/local/bin", "${VEYPORT_TEST_SYSTEM_BIN}")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh, "-s")
	cmd.Stdin = strings.NewReader(script) // Piped stdin is deliberately not a TTY.
	cmd.Env = append(os.Environ(), "HOME="+f.home, "PATH="+pathValue, "TMPDIR="+f.scratch,
		"VEYPORT_TEST_SYSTEM_BIN="+f.systemBin, "VEYPORT_TEST_PAYLOAD_FILE="+f.payload,
		"VEYPORT_TEST_CHECKSUM_FILE="+f.checksum, "VEYPORT_TEST_SUDO_CALLED="+f.sudoCalled,
		"VEYPORT_TEST_REQUEST_LOG="+f.requestLog, "VEYPORT_TEST_OS="+osName, "VEYPORT_TEST_ARCH="+arch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("private installer process: %v\n%s", err, out)
	}
	if _, err := os.Stat(f.sudoCalled); !os.IsNotExist(err) {
		t.Fatal("piped installer attempted sudo")
	}
	if entries, err := os.ReadDir(f.scratch); err != nil || len(entries) != 0 {
		t.Fatalf("installer left download scratch files: %v %v", entries, err)
	}
	return string(out)
}

func assertInstallerNextStep(t *testing.T, output, pathValue string) {
	t.Helper()
	_, nextStep, ok := strings.Cut(output, "Next step:\n")
	const arguments = " --hub 'https://hub.example' login"
	command := strings.TrimSpace(nextStep)
	if !ok || !strings.HasSuffix(command, arguments) {
		t.Fatalf("missing exact installed-path login instruction:\n%s", output)
	}
	// Execute only --version, keeping the displayed path's original quoting.
	// PATH deliberately still contains the old executable first when shadowed.
	cmd := exec.Command("sh", "-c", strings.TrimSuffix(command, arguments)+" --version")
	cmd.Env = append(os.Environ(), "PATH="+pathValue)
	actual, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(actual)) != installerNewVersion {
		t.Fatalf("displayed login path did not select the new version: %v %s", err, actual)
	}
}

func TestInstallCLIScript_ShadowedFallbackReportsActualDestination(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires ordinary user permission checks for a non-writable system directory")
	}
	f := newInstallerProcessFixture(t)
	old := filepath.Join(f.systemBin, "vey")
	writeInstallerExecutable(t, old, installerOldVersion)
	before, err := os.ReadFile(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.systemBin, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.systemBin, 0o755) })
	pathValue := f.tools + ":" + f.systemBin + ":" + f.userBin() + ":" + os.Getenv("PATH")
	out := f.run(t, pathValue, "Linux", "x86_64")
	installed, err := os.ReadFile(filepath.Join(f.userBin(), "vey"))
	payload, payloadErr := os.ReadFile(f.payload)
	unchanged, oldErr := os.ReadFile(old)
	if err != nil || payloadErr != nil || oldErr != nil || !bytes.Equal(installed, payload) || !bytes.Equal(before, unchanged) {
		t.Fatal("fallback did not preserve the shadowing old executable and install the exact verified new bytes")
	}
	if strings.Contains(out, "==> Upgraded:") {
		t.Fatalf("reported an upgrade although PATH still selects the untouched old executable:\n%s", out)
	}
	if !strings.Contains(out, "PATH resolves vey to") || !strings.Contains(out, old) || !strings.Contains(out, installerOldVersion) {
		t.Fatalf("missing actual shadowed PATH/version diagnostic:\n%s", out)
	}
	if !strings.Contains(out, "Installed "+installerNewVersion) || !strings.Contains(out, filepath.Join(f.userBin(), "vey")) {
		t.Fatalf("missing exact installed destination/version:\n%s", out)
	}
	if strings.Contains(out, "    vey --hub") || !strings.Contains(out, "hash -r") {
		t.Fatalf("next step would still invoke the old PATH command or lacks shell-cache remediation:\n%s", out)
	}
	assertInstallerNextStep(t, out, pathValue)
	// The displayed export must be executable POSIX syntax even for a HOME
	// containing spaces and an apostrophe. It must select the new bytes.
	var exportLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "export PATH=") {
			exportLine = strings.TrimSpace(line)
		}
	}
	if exportLine == "" {
		t.Fatal("missing actionable PATH precedence correction")
	}
	cmd := exec.Command("sh", "-c", exportLine+"\nhash -r\nvey --version")
	cmd.Env = append(os.Environ(), "PATH="+pathValue)
	actual, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(actual)) != installerNewVersion {
		t.Fatalf("quoted PATH remediation did not select the new version: %v %s", err, actual)
	}
}

func TestInstallCLIScript_UpgradeResolvedDestination(t *testing.T) {
	for _, platform := range []struct{ os, arch string }{{"Linux", "x86_64"}, {"Darwin", "arm64"}} {
		t.Run(platform.os, func(t *testing.T) {
			f := newInstallerProcessFixture(t)
			writeInstallerExecutable(t, filepath.Join(f.systemBin, "vey"), installerOldVersion)
			pathValue := f.tools + ":" + f.systemBin + ":" + os.Getenv("PATH")
			out := f.run(t, pathValue, platform.os, platform.arch)
			if !strings.Contains(out, "Upgraded: "+installerOldVersion+" -> "+installerNewVersion) || !strings.Contains(out, filepath.Join(f.systemBin, "vey")) {
				t.Fatalf("normal upgrade did not name the actual resolved installed destination/version:\n%s", out)
			}
			if strings.Contains(out, "PATH resolves vey to") {
				t.Fatalf("normal resolved upgrade falsely reported PATH shadowing:\n%s", out)
			}
			assertInstallerNextStep(t, out, pathValue)
			requests, err := os.ReadFile(f.requestLog)
			expectedPlatform := "linux/amd64"
			if platform.os == "Darwin" {
				expectedPlatform = "darwin/arm64"
			}
			if err != nil || string(requests) != "https://hub.example/install/cli/"+expectedPlatform+"\nhttps://hub.example/install/cli/"+expectedPlatform+"/sha256\n" {
				t.Fatalf("incorrect platform/checksum downloads: %v %s", err, requests)
			}
		})
	}
}
