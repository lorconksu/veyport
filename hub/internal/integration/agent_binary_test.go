package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitForAgentConnect polls ConnMgr until the given serverID appears or the timeout expires.
func waitForAgentConnect(h *TestHarness, serverID string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if isServerConnected(h, serverID) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// isServerConnected checks whether a server ID is present in the ConnMgr's active list.
func isServerConnected(h *TestHarness, serverID string) bool {
	for _, id := range h.ConnMgr.ActiveServerIDs() {
		if id == serverID {
			return true
		}
	}
	return false
}

// assertServerStatus verifies the server's status in the store matches the expected value.
func assertServerStatus(t *testing.T, h *TestHarness, serverID, expected string) {
	t.Helper()
	srv, err := h.Store.GetServerByID(serverID)
	if err != nil {
		t.Fatalf("get server %s: %v", serverID, err)
	}
	if srv.Status != expected {
		t.Fatalf("expected server status %q, got %q", expected, srv.Status)
	}
}

// createTestFiles writes test files into the given directory and returns the file names.
func createTestFiles(t *testing.T, dir string) []string {
	t.Helper()
	names := []string{"readme.txt", "config.yaml", "data.json"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("test content"), 0o644); err != nil {
			t.Fatalf("write test file %s: %v", name, err)
		}
	}
	return names
}

// assertFileListContains verifies that the HTTP file-list response contains all expected files.
func assertFileListContains(t *testing.T, resp *http.Response, expectedFiles []string) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("file list: status=%d body=%s", resp.StatusCode, body)
	}

	var result struct {
		Files []struct {
			Name string `json:"name"`
		} `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode file list: %v", err)
	}

	nameSet := make(map[string]bool)
	for _, f := range result.Files {
		nameSet[f.Name] = true
	}
	for _, expected := range expectedFiles {
		if !nameSet[expected] {
			t.Fatalf("expected %q in file list, got %+v", expected, result.Files)
		}
	}
}

// TestAgentBinaryConnectAndFileList exercises the full agent binary (main -> Run ->
// connectAndStream -> dialHub) as a subprocess, producing cross-module coverage
// via GOCOVERDIR.
func TestAgentBinaryConnectAndFileList(t *testing.T) {
	h := StartHarness(t)
	token := h.SetupAdmin(t)
	serverID, regToken := h.CreateServer(t, token, "binary-test-server")
	t.Logf("created server: id=%s", serverID)

	cancelAgent := h.StartAgentProcess(t, regToken)

	if !waitForAgentConnect(h, serverID, 10*time.Second) {
		cancelAgent()
		t.Fatal("agent binary did not connect within 10s")
	}
	t.Log("agent binary connected to hub")

	assertServerStatus(t, h, serverID, "online")
	srv, err := h.Store.GetServerByID(serverID)
	if err != nil || srv.AgentVersion == nil || *srv.AgentVersion != agentBinaryVersion {
		t.Fatalf("registered agent did not advertise its linker-stamped version: %+v, %v", srv, err)
	}

	tmpDir := t.TempDir()
	testFiles := createTestFiles(t, tmpDir)

	path := fmt.Sprintf("/api/servers/%s/files?path=%s", serverID, tmpDir)
	resp := h.HTTPGet(t, path, token)
	assertFileListContains(t, resp, testFiles)
	t.Logf("file list round-trip verified: found all %d test files", len(testFiles))

	cancelAgent()
	time.Sleep(500 * time.Millisecond)

	if isServerConnected(h, serverID) {
		t.Fatal("agent still in ConnMgr after shutdown")
	}
	t.Log("agent binary disconnected successfully")

	assertServerStatus(t, h, serverID, "offline")
	t.Log("server status is offline after agent binary shutdown")
}
