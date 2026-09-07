package server

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"text/template"

	"github.com/wyiu/veyport/hub"
)

// headerContentType names the Content-Type header once for this file's
// three hand-set responses (binary, checksum, install script) — go:S1192.
const headerContentType = "Content-Type"

// cliAllowedOS and cliAllowedArch define the platform matrix the `vey` CLI is
// built for (specs/004-cli-connector/contracts/rest-api.md, Distribution
// section). Unlike the agent binary allowlist (linux-only, see
// handleAgentBinary in handlers_servers.go), the CLI also ships for darwin.
var cliAllowedOS = map[string]bool{
	"linux":  true,
	"darwin": true,
}

var cliAllowedArch = map[string]bool{
	"amd64": true,
	"arm64": true,
}

// isValidBinaryPlatform reports whether osName/arch are both present in the
// given allowlists. It is the shared "binary-family" validation used by both
// the agent binary routes and the CLI binary routes below: an explicit
// allowlist check (rather than trying to sanitize the input) is what
// prevents path-traversal values (e.g. "..", "../../etc") from ever reaching
// filepath.Join, since such values simply never match an allowed entry.
func isValidBinaryPlatform(osName, arch string, allowedOS, allowedArch map[string]bool) bool {
	return allowedOS[osName] && allowedArch[arch]
}

// isValidCLIPlatform reports whether os/arch are in the CLI's supported
// allowlist ({linux,darwin} x {amd64,arm64}).
func isValidCLIPlatform(osName, arch string) bool {
	return isValidBinaryPlatform(osName, arch, cliAllowedOS, cliAllowedArch)
}

// handleCLIBinary serves the `vey` CLI binary for GET /install/cli/{os}/{arch}.
// It mirrors handleAgentBinary's validation/serving logic exactly, but reads
// from the CLI allowlist (which additionally permits darwin) and looks up
// vey-{os}-{arch} filenames instead of veyport-agent-{os}-{arch}.
func (s *Server) handleCLIBinary(w http.ResponseWriter, r *http.Request) {
	osName := r.PathValue("os")
	arch := r.PathValue("arch")
	if !isValidCLIPlatform(osName, arch) {
		respondError(w, http.StatusNotFound, "unsupported platform")
		return
	}
	s.serveBinaryFile(w, r, fmt.Sprintf("vey-%s-%s", osName, arch), "cli binary not found")
}

// handleInstall3rdSegmentDispatch handles the 4-path-segment "/install/{a}/{b}/{c}"
// space, which covers two distinct routes that net/http's ServeMux cannot be
// given as separate static patterns (see the NOTE in router.go):
//
//   - Agent checksum: GET /install/{os}/{arch}/sha256  (c == "sha256")
//   - CLI binary:      GET /install/cli/{os}/{arch}     (a == "cli")
//
// These two interpretations only collide (both conditions true) when
// a == "cli" and c == "sha256" simultaneously — e.g. "/install/cli/X/sha256".
// In that case neither interpretation can ever succeed: the agent-checksum
// reading requires os == "linux" (a == "cli" fails that), and the CLI-binary
// reading requires arch to be an allowed CLI arch (c == "sha256" fails that).
// So picking the agent-checksum interpretation first for any c == "sha256"
// path is safe — it never masks a valid CLI binary request.
func (s *Server) handleInstall3rdSegmentDispatch(w http.ResponseWriter, r *http.Request) {
	a := r.PathValue("a")
	b := r.PathValue("b")
	c := r.PathValue("c")

	if c == "sha256" {
		r.SetPathValue("os", a)
		r.SetPathValue("arch", b)
		s.handleAgentBinaryChecksum(w, r)
		return
	}
	if a == "cli" {
		r.SetPathValue("os", b)
		r.SetPathValue("arch", c)
		s.handleCLIBinary(w, r)
		return
	}
	respondError(w, http.StatusNotFound, "not found")
}

// handleCLIBinaryChecksum serves the SHA-256 checksum for the `vey` CLI
// binary at GET /install/cli/{os}/{arch}/sha256, mirroring
// handleAgentBinaryChecksum.
func (s *Server) handleCLIBinaryChecksum(w http.ResponseWriter, r *http.Request) {
	osName := r.PathValue("os")
	arch := r.PathValue("arch")
	if !isValidCLIPlatform(osName, arch) {
		respondError(w, http.StatusNotFound, "unsupported platform")
		return
	}
	s.serveChecksumFile(w, fmt.Sprintf("vey-%s-%s.sha256", osName, arch), "cli checksum write failed")
}

// installCLIScriptTemplate is parsed at init via template.Must: the script
// is an embedded asset, so a parse failure is a build defect that should
// fail startup loudly, not a runtime condition to limp past per-request.
var installCLIScriptTemplate = template.Must(
	template.New("install-cli.sh").Parse(string(hub.InstallCLIScript)))

// handleInstallCLIScript serves the templated `vey` CLI install one-liner at
// GET /install/cli.sh (specs/006-cli-install-script/proposal.md). Unlike the
// static agent installer (install.sh), this script is rendered through
// text/template so the hub injects its own public base URL and the
// one-liner needs zero arguments: `curl -fsSL <hub>/install/cli.sh | sh`.
// Rendered into a buffer first so a template error never ships a partial
// script with a 200 status.
func (s *Server) handleInstallCLIScript(w http.ResponseWriter, r *http.Request) {
	baseURL, err := s.resolvePublicBaseURL(r)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "public hub address is not configured")
		return
	}

	var buf bytes.Buffer
	if err := installCLIScriptTemplate.Execute(&buf, struct{ BaseURL string }{BaseURL: baseURL}); err != nil {
		log.Printf("install-cli.sh template execute failed: %v", err)
		respondError(w, http.StatusInternalServerError, "install script is not available")
		return
	}

	w.Header().Set(headerContentType, "text/x-shellscript; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Printf("install-cli.sh write failed: %v", err)
	}
}
