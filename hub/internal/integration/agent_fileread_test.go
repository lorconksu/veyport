package integration

import (
	"context"
	"encoding/base64"
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

func TestFileReadThroughGRPC(t *testing.T) {
	h := StartHarness(t)
	token := h.SetupAdmin(t)
	serverID, regToken := h.CreateServer(t, token, "fileread-server")

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

	// Create a temp file with known content
	tmpDir := t.TempDir()
	wantContent := "hello integration test"
	testFilePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFilePath, []byte(wantContent), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Read file via HTTP → gRPC round-trip
	path := fmt.Sprintf("/api/servers/%s/files/read?path=%s", serverID, testFilePath)
	resp := h.HTTPGet(t, path, token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("read file: status=%d body=%s", resp.StatusCode, body)
	}

	var result struct {
		Data      string `json:"data"`
		TotalSize int64  `json:"total_size"`
		MimeType  string `json:"mime_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if result.Data == "" {
		t.Fatal("expected non-empty data field")
	}

	decoded, err := base64.StdEncoding.DecodeString(result.Data)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	if string(decoded) != wantContent {
		t.Fatalf("content mismatch: got %q, want %q", string(decoded), wantContent)
	}

	if result.TotalSize <= 0 {
		t.Fatalf("expected positive total_size, got %d", result.TotalSize)
	}

	t.Logf("file read round-trip verified: content=%q mime_type=%s total_size=%d",
		string(decoded), result.MimeType, result.TotalSize)
}
