package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/agentclient"
)

func TestFileListThroughGRPC(t *testing.T) {
	h := StartHarness(t)
	token := h.SetupAdmin(t)
	serverID, regToken := h.CreateServer(t, token, "filelist-server")

	// Start agent
	agentClient := agentclient.New(agentclient.Config{
		HubAddr:      h.GRPCAddr,
		ServerID:     "",
		Token:        regToken,
		CertDir:      t.TempDir(),
		Hostname:     "test-host",
		IPAddress:    "10.0.0.1",
		OS:           "linux",
		AgentVersion: "0.0.0-test",
		HubCAPin:     h.HubCAPin,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go agentClient.Run(ctx)

	// Wait for agent to connect
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, id := range h.ConnMgr.ActiveServerIDs() {
			if id == serverID {
				goto connected
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("agent did not connect within 5s")
connected:

	// Create a temp directory with a test file
	tmpDir := t.TempDir()
	testFilename := "hello.txt"
	testFilePath := filepath.Join(tmpDir, testFilename)
	if err := os.WriteFile(testFilePath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// List files via HTTP → gRPC round-trip
	path := fmt.Sprintf("/api/servers/%s/files?path=%s", serverID, tmpDir)
	resp := h.HTTPGet(t, path, token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("list files: status=%d body=%s", resp.StatusCode, body)
	}

	var result struct {
		Files []struct {
			Name string `json:"name"`
		} `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	found := false
	for _, f := range result.Files {
		if f.Name == testFilename {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find %q in file list, got %+v", testFilename, result.Files)
	}
	t.Logf("file list round-trip verified: found %q in %s", testFilename, tmpDir)
}
