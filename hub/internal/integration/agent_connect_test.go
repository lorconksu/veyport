package integration

import (
	"context"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/agentclient"
)

// newTestAgentClient creates an agent client configured for testing.
func newTestAgentClient(h *TestHarness, regToken, certDir string) *agentclient.Client {
	return agentclient.New(agentclient.Config{
		HubAddr:      h.GRPCAddr,
		ServerID:     "",
		Token:        regToken,
		CertDir:      certDir,
		Hostname:     "test-host",
		IPAddress:    "10.0.0.1",
		OS:           "linux",
		AgentVersion: "0.0.0-test",
		HubCAPin:     h.HubCAPin,
	})
}

// runAgentInBackground starts the agent in a goroutine and returns the error channel.
func runAgentInBackground(agentClient *agentclient.Client, ctx context.Context) <-chan error {
	ch := make(chan error, 1)
	go func() {
		ch <- agentClient.Run(ctx)
	}()
	return ch
}

// waitForAgentExit waits for the agent goroutine to exit within the timeout.
func waitForAgentExit(t *testing.T, agentErrCh <-chan error, timeout time.Duration) {
	t.Helper()
	select {
	case <-agentErrCh:
		// Agent returned (expected: context canceled)
	case <-time.After(timeout):
		t.Fatal("agent did not exit within timeout after context cancel")
	}
}

// assertServerDisconnected verifies the server is no longer in ConnMgr and has offline status.
func assertServerDisconnected(t *testing.T, h *TestHarness, serverID string) {
	t.Helper()
	if isServerConnected(h, serverID) {
		t.Fatal("agent still in ConnMgr after disconnect")
	}
	assertServerStatus(t, h, serverID, "offline")
}

func TestAgentConnectAndHeartbeat(t *testing.T) {
	h := StartHarness(t)
	token := h.SetupAdmin(t)
	serverID, regToken := h.CreateServer(t, token, "test-server")
	t.Logf("created server: id=%s", serverID)

	agentClient := newTestAgentClient(h, regToken, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentErrCh := runAgentInBackground(agentClient, ctx)

	if !waitForAgentConnect(h, serverID, 5*time.Second) {
		t.Fatal("agent did not appear in ConnMgr within 5s")
	}
	t.Log("agent connected to hub")

	assertServerStatus(t, h, serverID, "online")
	t.Log("server status is online")

	// Record initial last_seen_at for heartbeat verification
	srv, err := h.Store.GetServerByID(serverID)
	if err != nil {
		t.Fatalf("get server: %v", err)
	}
	initialLastSeen := srv.LastSeenAt

	// Wait 12s for heartbeat to update last_seen_at (agent interval is 10s)
	t.Log("waiting 12s for heartbeat...")
	time.Sleep(12 * time.Second)

	srv2, err := h.Store.GetServerByID(serverID)
	if err != nil {
		t.Fatalf("get server after heartbeat: %v", err)
	}
	if srv2.LastSeenAt == nil {
		t.Fatal("last_seen_at is nil after heartbeat")
	}
	if initialLastSeen != nil && *srv2.LastSeenAt == *initialLastSeen {
		t.Fatal("last_seen_at did not change after heartbeat")
	}
	t.Logf("heartbeat verified: last_seen_at=%s", *srv2.LastSeenAt)

	if agentClient.ServerID() != serverID {
		t.Fatalf("agent server ID mismatch: got %q, want %q", agentClient.ServerID(), serverID)
	}

	cancel()
	waitForAgentExit(t, agentErrCh, 3*time.Second)
	time.Sleep(500 * time.Millisecond)

	assertServerDisconnected(t, h, serverID)
	t.Log("agent disconnected successfully, server status is offline")
}
