package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/server"
	"github.com/wyiu/veyport/hub/internal/store"
)

// startCLIInstallHarness spins up a minimal, real (TCP-listening) hub HTTP
// server with a custom --agent-bin-dir, so the GET /install/cli/{os}/{arch}
// routes can be exercised end-to-end (real listener, real net/http mux,
// real filesystem lookups) rather than via httptest's in-process handler
// invocation used by the server package's unit tests.
//
// The GRPC server, CA, and full StartHarness setup are intentionally
// skipped: the CLI install routes are unauthenticated and don't touch the
// store, gRPC, or CA at all, so a full TestHarness (see testhelpers.go)
// would be unnecessary overhead for this route.
func startCLIInstallHarness(t *testing.T, binDir string) (baseURL string) {
	t.Helper()

	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	jwtSecret, err := server.InitJWTSecret(st)
	if err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}

	httpPort := freePort(t)
	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

	hs := server.New(server.Config{
		Addr:        httpAddr,
		Store:       st,
		JWTSecret:   jwtSecret,
		IsDev:       true,
		AgentBinDir: binDir,
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- hs.Start()
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	})

	waitForPort(t, httpAddr, 5*time.Second)

	select {
	case err := <-errCh:
		t.Fatalf("HTTP server failed to start: %v", err)
	default:
	}

	return "http://" + httpAddr
}

// writeCLIBinaryFixture writes a fake vey-{os}-{arch} binary plus matching
// .sha256 checksum file into dir.
func writeCLIBinaryFixture(t *testing.T, dir, osName, arch string) (content, checksum string) {
	t.Helper()
	content = fmt.Sprintf("fake-vey-cli-%s-%s-integration", osName, arch)
	checksum = fmt.Sprintf("checksum-%s-%s-integration", osName, arch)

	name := fmt.Sprintf("vey-%s-%s", osName, arch)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0755); err != nil {
		t.Fatalf("write fake vey binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".sha256"), []byte(checksum+"\n"), 0644); err != nil {
		t.Fatalf("write vey checksum file: %v", err)
	}
	return content, checksum
}

// TestCLIInstallRoute_FullStack exercises GET /install/cli/{os}/{arch} and
// its /sha256 counterpart against a real, listening hub HTTP server backed
// by a real temp --agent-bin-dir, covering the full router -> dispatcher ->
// handler -> filesystem path (not just the in-process httptest path already
// covered by the server package's unit tests).
func TestCLIInstallRoute_FullStack(t *testing.T) {
	binDir := t.TempDir()
	content, checksum := writeCLIBinaryFixture(t, binDir, "linux", "amd64")

	baseURL := startCLIInstallHarness(t, binDir)

	t.Run("serves the binary", func(t *testing.T) {
		assertCLIBinaryServed(t, baseURL, content)
	})

	t.Run("serves the checksum", func(t *testing.T) {
		assertCLIChecksumServed(t, baseURL, checksum)
	})

	t.Run("rejects an out-of-allowlist platform", func(t *testing.T) {
		assertCLIInstallStatus(t, baseURL+"/install/cli/windows/amd64", http.StatusNotFound, "unsupported platform")
	})

	t.Run("404s for an allowlisted but unbuilt platform", func(t *testing.T) {
		// darwin/arm64 is allowlisted but no fixture was written for it.
		assertCLIInstallStatus(t, baseURL+"/install/cli/darwin/arm64", http.StatusNotFound, "unbuilt platform")
	})

	t.Run("existing agent binary route is unaffected", func(t *testing.T) {
		// Regression guard at the full-stack level: the agent route must
		// still work standalone even though it now shares the 4-segment
		// dispatcher with the CLI checksum route for /sha256 paths.
		assertAgentBinaryRouteUnaffected(t, binDir, baseURL)
	})
}

// assertCLIBinaryServed asserts that GET /install/cli/linux/amd64 returns
// the fixture binary content with a 200 and the expected download headers.
func assertCLIBinaryServed(t *testing.T, baseURL, wantContent string) {
	t.Helper()

	resp, err := http.Get(baseURL + "/install/cli/linux/amd64")
	if err != nil {
		t.Fatalf("GET /install/cli/linux/amd64: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != wantContent {
		t.Fatalf("expected body %q, got %q", wantContent, body)
	}
	wantDisposition := `attachment; filename="vey-linux-amd64"`
	if cd := resp.Header.Get("Content-Disposition"); cd != wantDisposition {
		t.Fatalf("expected Content-Disposition %q, got %q", wantDisposition, cd)
	}
}

// assertCLIChecksumServed asserts that GET /install/cli/linux/amd64/sha256
// returns the fixture checksum content with a 200.
func assertCLIChecksumServed(t *testing.T, baseURL, wantChecksum string) {
	t.Helper()

	resp, err := http.Get(baseURL + "/install/cli/linux/amd64/sha256")
	if err != nil {
		t.Fatalf("GET /install/cli/linux/amd64/sha256: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != wantChecksum {
		t.Fatalf("expected checksum %q, got %q", wantChecksum, body)
	}
}

// assertCLIInstallStatus asserts that GET url returns wantStatus, using
// wantDesc only to make the failure message identify which case failed.
func assertCLIInstallStatus(t *testing.T, url string, wantStatus int, wantDesc string) {
	t.Helper()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != wantStatus {
		t.Fatalf("expected %d for %s, got %d", wantStatus, wantDesc, resp.StatusCode)
	}
}

// assertAgentBinaryRouteUnaffected writes a fake agent binary into binDir
// and asserts that GET /install/linux/amd64 still serves it with a 200.
func assertAgentBinaryRouteUnaffected(t *testing.T, binDir, baseURL string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(binDir, "veyport-agent-linux-amd64"), []byte("agent-binary"), 0755); err != nil {
		t.Fatalf("write fake agent binary: %v", err)
	}
	resp, err := http.Get(baseURL + "/install/linux/amd64")
	if err != nil {
		t.Fatalf("GET /install/linux/amd64: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}
