package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/agentclient"
)

// startTestAgent creates and starts an agent client, returning the cancel func and error channel.
func startTestAgent(t *testing.T, h *TestHarness, regToken string) (context.CancelFunc, <-chan error) {
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
	agentErrCh := make(chan error, 1)
	go func() {
		agentErrCh <- agentClient.Run(ctx)
	}()
	return cancel, agentErrCh
}

// waitForAgentDisconnect polls ConnMgr until the given serverID disappears or the timeout expires.
func waitForAgentDisconnect(h *TestHarness, serverID string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isServerConnected(h, serverID) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func TestServerUnregister(t *testing.T) {
	h := StartHarness(t)
	token := h.SetupAdmin(t)
	serverID, regToken := h.CreateServer(t, token, "unregister-server")

	cancel, agentErrCh := startTestAgent(t, h, regToken)
	defer cancel()

	if !waitForAgentConnect(h, serverID, 5*time.Second) {
		t.Fatal("agent did not connect within 5s")
	}
	t.Log("agent connected")

	// Send DELETE /api/servers/{id}/unregister
	unregURL := fmt.Sprintf("http://%s/api/servers/%s/unregister", h.HTTPAddr, serverID)
	req, err := http.NewRequest("DELETE", unregURL, nil)
	if err != nil {
		t.Fatalf("create unregister request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unregister request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unregister: status=%d body=%s", resp.StatusCode, body)
	}
	t.Log("unregister response: 200 OK")

	// Cancel the agent context immediately to prevent the agent's selfCleanup()
	// from calling syscall.Exec (which would replace the test process).
	cancel()

	select {
	case <-agentErrCh:
		t.Log("agent goroutine exited")
	case <-time.After(5 * time.Second):
		t.Fatal("agent goroutine did not exit within 5s")
	}

	if !waitForAgentDisconnect(h, serverID, 5*time.Second) {
		t.Fatal("agent did not disconnect from ConnMgr within 5s after unregister")
	}
	t.Log("agent disconnected from ConnMgr")

	// Verify server no longer exists in store
	_, err = h.Store.GetServerByID(serverID)
	if err == nil {
		t.Fatal("server still exists in store after unregister")
	}
	t.Logf("server %s verified deleted from store", serverID)
}
