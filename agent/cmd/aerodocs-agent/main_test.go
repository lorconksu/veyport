package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const (
	testAgentConf     = "agent.conf"
	testHubAddr       = "localhost:9090"
	testLoadConfigFmt = "loadConfig: %v"
	testVarLogPath    = "/var/log"
	testHomeAppPath   = "/home/app"
)

// TestRunSelfUnregister_ReadsTokenFromConfigOnly verifies that runSelfUnregister
// reads the unregister token from the config file, not from the environment variable.
func TestRunSelfUnregister_ReadsTokenFromConfigOnly(t *testing.T) {
	// Create a temporary config file with an unregister token
	dir := t.TempDir()
	configPath := filepath.Join(dir, testAgentConf)

	cfg := agentConfig{
		ServerID:        "test-server-id",
		HubURL:          testHubAddr,
		HubCAPin:        "abcd",
		UnregisterToken: "config-file-token",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Verify loadConfig reads the token correctly
	loaded, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf(testLoadConfigFmt, err)
	}
	if loaded.UnregisterToken != "config-file-token" {
		t.Errorf("expected unregister_token 'config-file-token', got %q", loaded.UnregisterToken)
	}
	if loaded.HubCAPin != "abcd" {
		t.Errorf("expected hub_ca_pin 'abcd', got %q", loaded.HubCAPin)
	}
}

// TestRunSelfUnregister_MissingTokenFails verifies that runSelfUnregister fails
// with a clear error when the config file has no unregister token, even if the
// env var is set (proving the env var is not used as fallback).
func TestRunSelfUnregister_MissingTokenFailsEvenWithEnvVar(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, testAgentConf)

	// Write config WITHOUT unregister token
	cfg := agentConfig{
		ServerID: "test-server-id",
		HubURL:   testHubAddr,
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Set env var — it should NOT be used as fallback
	t.Setenv("AERODOCS_UNREGISTER_TOKEN", "env-var-token")

	// Load config and verify token is empty (env var not consulted)
	loaded, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf(testLoadConfigFmt, err)
	}
	if loaded.UnregisterToken != "" {
		t.Errorf("expected empty unregister_token from config, got %q", loaded.UnregisterToken)
	}
}

// TestSaveNewConfig_PersistsUnregisterToken verifies that saveNewConfig writes
// the unregister token to the config file.
func TestSaveNewConfig_PersistsUnregisterToken(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, testAgentConf)

	saveNewConfig(configPath, testHubAddr, "srv-123", "deadbeef", "my-unreg-token")

	loaded, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig after save: %v", err)
	}
	if loaded.UnregisterToken != "my-unreg-token" {
		t.Errorf("expected unregister_token 'my-unreg-token', got %q", loaded.UnregisterToken)
	}
	if loaded.ServerID != "srv-123" {
		t.Errorf("expected server_id 'srv-123', got %q", loaded.ServerID)
	}
	if loaded.HubURL != testHubAddr {
		t.Errorf("expected hub_url '%s', got %q", testHubAddr, loaded.HubURL)
	}
	if loaded.HubCAPin != "deadbeef" {
		t.Errorf("expected hub_ca_pin 'deadbeef', got %q", loaded.HubCAPin)
	}
}

func TestResolveConfig_PrefersSavedConfigOverBootstrapToken(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, testAgentConf)

	saved := agentConfig{
		ServerID:        "srv-existing",
		HubURL:          "saved.example.com:443",
		HubCAPin:        "cafebabe",
		UnregisterToken: "saved-unreg-token",
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, hubAddr, serverID, regToken, hubCAPin := resolveConfig(
		configPath,
		"new.example.com:443",
		"new-bootstrap-token",
		"deadbeef",
	)

	if cfg == nil {
		t.Fatal("expected saved config to be loaded")
	}
	if hubAddr != saved.HubURL {
		t.Fatalf("expected hubAddr %q, got %q", saved.HubURL, hubAddr)
	}
	if serverID != saved.ServerID {
		t.Fatalf("expected serverID %q, got %q", saved.ServerID, serverID)
	}
	if regToken != "" {
		t.Fatalf("expected bootstrap token to be ignored, got %q", regToken)
	}
	if hubCAPin != saved.HubCAPin {
		t.Fatalf("expected hubCAPin %q, got %q", saved.HubCAPin, hubCAPin)
	}
}

func TestParseAllowedPaths(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{testVarLogPath, []string{testVarLogPath}},
		{testVarLogPath + "," + testHomeAppPath, []string{testVarLogPath, testHomeAppPath}},
		{testVarLogPath + ", " + testHomeAppPath + " , /tmp", []string{testVarLogPath, testHomeAppPath, "/tmp"}},
		{",,,", nil},
	}
	for _, tt := range tests {
		got := parseAllowedPaths(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("parseAllowedPaths(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseAllowedPaths(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestLoadConfig_WithAllowedPaths(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, testAgentConf)

	cfg := agentConfig{
		ServerID:     "srv-1",
		HubURL:       testHubAddr,
		AllowedPaths: []string{testVarLogPath, testHomeAppPath},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	loaded, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf(testLoadConfigFmt, err)
	}
	if len(loaded.AllowedPaths) != 2 {
		t.Fatalf("expected 2 allowed paths, got %d", len(loaded.AllowedPaths))
	}
	if loaded.AllowedPaths[0] != testVarLogPath {
		t.Fatalf("expected '%s', got '%s'", testVarLogPath, loaded.AllowedPaths[0])
	}
}
