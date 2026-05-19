package integration

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// agentBinaryPath is the path to the coverage-instrumented agent binary,
// built once in TestMain and used by subprocess-based integration tests.
var agentBinaryPath string

// agentCovDir is the directory where the agent binary writes coverage data
// (via the GOCOVERDIR env var). Converted to text format after tests complete.
var agentCovDir string

func TestMain(m *testing.M) {
	// Build coverage-instrumented agent binary
	tmpDir, err := os.MkdirTemp("", "agent-covtest-*")
	if err != nil {
		log.Fatalf("create temp dir: %v", err)
	}
	agentCovDir = filepath.Join(tmpDir, "covdata")
	if err := os.MkdirAll(agentCovDir, 0755); err != nil {
		log.Fatalf("create covdata dir: %v", err)
	}

	agentBinaryPath = filepath.Join(tmpDir, "veyport-agent")

	// Build from the agent directory (hub/internal/integration → repo root → agent)
	agentDir := filepath.Join("..", "..", "..", "agent")
	cmd := exec.Command("go", "build", "-cover", "-o", agentBinaryPath, "./cmd/veyport-agent/")
	cmd.Dir = agentDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("failed to build coverage-instrumented agent: %s: %v", string(out), err)
	}
	log.Printf("built coverage-instrumented agent at %s", agentBinaryPath)

	// Run tests
	code := m.Run()

	// Convert binary coverage data to text format (best-effort)
	covOut := filepath.Join("..", "..", "..", "coverage-agent-integration.out")
	convertCmd := exec.Command("go", "tool", "covdata", "textfmt", "-i="+agentCovDir, "-o="+covOut)
	if convertOut, convertErr := convertCmd.CombinedOutput(); convertErr != nil {
		log.Printf("warning: covdata conversion: %s: %v", string(convertOut), convertErr)
	} else {
		log.Printf("agent integration coverage written to %s", covOut)
	}

	// Cleanup
	os.RemoveAll(tmpDir)

	os.Exit(code)
}
