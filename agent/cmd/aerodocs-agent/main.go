package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wyiu/aerodocs/agent/internal/client"
	"github.com/wyiu/aerodocs/agent/internal/sysinfo"
)

const version = "0.1.0"
const defaultConfigPath = "/etc/aerodocs/agent.conf"
const defaultCertDir = "/etc/aerodocs/tls/"
const defaultDropzoneDir = "/tmp/aerodocs-dropzone"

type agentConfig struct {
	ServerID        string   `json:"server_id"`
	HubURL          string   `json:"hub_url"`
	HubCAPin        string   `json:"hub_ca_pin,omitempty"`
	UnregisterToken string   `json:"unregister_token,omitempty"`
	AllowedPaths    []string `json:"allowed_paths,omitempty"`
}

func main() {
	hub := flag.String("hub", "", "Hub gRPC address (e.g., hub.example.com:9090)")
	token := flag.String("token", "", "one-time registration token")
	caPin := flag.String("ca-pin", "", "SHA-256 fingerprint of the Hub CA certificate")
	configPath := flag.String("config", defaultConfigPath, "path to config file")
	certDir := flag.String("cert-dir", "", "directory for mTLS client certificates")
	dropzoneDir := flag.String("dropzone-dir", "", "directory for staged uploads")
	selfUnregister := flag.Bool("self-unregister", false, "connect to Hub, request deletion of this server, then exit")
	insecureFlag := flag.Bool("insecure", false, "disable TLS (for development only)")
	allowedPathsFlag := flag.String("allowed-paths", "", "comma-separated list of allowed filesystem paths")
	flag.Parse()

	if *selfUnregister {
		runSelfUnregister(*configPath)
		return
	}

	cfg, hubAddr, serverID, regToken, hubCAPin := resolveConfig(*configPath, *hub, *token, *caPin)

	// Merge allowed paths from config and CLI flag
	allowedPaths := parseAllowedPaths(*allowedPathsFlag)
	if cfg != nil && len(cfg.AllowedPaths) > 0 && len(allowedPaths) == 0 {
		allowedPaths = cfg.AllowedPaths
	}

	hostname := sysinfo.Hostname()
	osInfo := sysinfo.OSInfo()

	c := client.New(client.Config{
		HubAddr:      hubAddr,
		ServerID:     serverID,
		Token:        regToken,
		CertDir:      resolveCertDir(*configPath, *certDir),
		DropzoneDir:  resolveDropzoneDir(*configPath, *dropzoneDir),
		HubCAPin:     hubCAPin,
		Hostname:     hostname,
		IPAddress:    "",
		OS:           osInfo,
		AgentVersion: version,
		Insecure:     *insecureFlag,
		AllowedPaths: allowedPaths,
		OnRegistered: func(serverID string) {
			if cfg != nil || serverID == "" {
				return
			}
			unregToken := os.Getenv("AERODOCS_UNREGISTER_TOKEN")
			saveNewConfig(*configPath, hubAddr, serverID, hubCAPin, unregToken)
		},
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("AeroDocs Agent v%s starting — hub=%s", version, hubAddr)

	err := c.Run(ctx)
	if err != nil && ctx.Err() == nil {
		log.Fatalf("agent error: %v", err)
	}

	if cfg == nil && c.ServerID() != "" {
		unregToken := os.Getenv("AERODOCS_UNREGISTER_TOKEN")
		saveNewConfig(*configPath, hubAddr, c.ServerID(), hubCAPin, unregToken)
	}

	log.Println("agent stopped")
}

func resolveCertDir(configPath, certDirFlag string) string {
	if certDirFlag != "" {
		return certDirFlag
	}
	if configPath != defaultConfigPath {
		return filepath.Join(filepath.Dir(configPath), "tls")
	}
	return defaultCertDir
}

func resolveDropzoneDir(configPath, dropzoneDirFlag string) string {
	if dropzoneDirFlag != "" {
		return dropzoneDirFlag
	}
	if configPath != defaultConfigPath {
		return filepath.Join(filepath.Dir(configPath), "dropzone")
	}
	return defaultDropzoneDir
}

// runSelfUnregister loads the config, sends an unregister request to the Hub, removes the config
// file, then exits. If no config is found, it exits immediately with no error.
func runSelfUnregister(configPath string) {
	cfg, err := loadConfig(configPath)
	if err != nil || cfg == nil {
		log.Printf("no config found at %s — nothing to unregister", configPath)
		os.Exit(0)
	}
	log.Printf("self-unregistering server_id=%s from hub=%s", cfg.ServerID, cfg.HubURL)
	c := client.New(client.Config{
		HubAddr:         cfg.HubURL,
		ServerID:        cfg.ServerID,
		AgentVersion:    version,
		UnregisterToken: cfg.UnregisterToken,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.SelfUnregister(ctx); err != nil {
		log.Printf("self-unregister failed: %v (continuing anyway)", err)
	} else {
		log.Printf("self-unregister successful — server removed from Hub")
	}
	os.Remove(configPath)
	os.Exit(0)
}

// resolveConfig determines the effective hub address, server ID, and registration token
// from the saved config file and CLI flags. Saved config takes precedence over bootstrap
// flags so service restarts reconnect with the persisted server ID.
func resolveConfig(configPath, hubFlag, tokenFlag, caPinFlag string) (cfg *agentConfig, hubAddr, serverID, regToken, hubCAPin string) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		cfg = nil
	}

	if cfg != nil {
		hubAddr = cfg.HubURL
		serverID = cfg.ServerID
		regToken = ""
		hubCAPin = cfg.HubCAPin
		log.Printf("loaded config: server_id=%s hub=%s", serverID, hubAddr)
		if tokenFlag != "" {
			log.Printf("saved config present; ignoring bootstrap token and reusing server_id=%s", serverID)
		}
		return cfg, hubAddr, serverID, regToken, hubCAPin
	}

	if tokenFlag == "" {
		fmt.Fprintf(os.Stderr, "first run: --hub and --token are required\n")
		flag.Usage()
		os.Exit(1)
	}
	if hubFlag == "" {
		fmt.Fprintf(os.Stderr, "--hub is required when using --token\n")
		flag.Usage()
		os.Exit(1)
	}
	if caPinFlag == "" {
		fmt.Fprintf(os.Stderr, "--ca-pin is required when using --token\n")
		flag.Usage()
		os.Exit(1)
	}

	hubAddr = hubFlag
	regToken = tokenFlag
	hubCAPin = caPinFlag

	return cfg, hubAddr, serverID, regToken, hubCAPin
}

// saveNewConfig persists the server ID and hub URL returned after a successful first registration.
func saveNewConfig(configPath, hubAddr, serverID, hubCAPin, unregisterToken string) {
	newCfg := agentConfig{
		ServerID:        serverID,
		HubURL:          hubAddr,
		HubCAPin:        hubCAPin,
		UnregisterToken: unregisterToken,
	}
	if err := saveConfig(configPath, newCfg); err != nil {
		log.Printf("warning: failed to save config: %v", err)
	} else {
		log.Printf("config saved to %s", configPath)
	}
}

func loadConfig(path string) (*agentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg agentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func parseAllowedPaths(s string) []string {
	if s == "" {
		return nil
	}
	var paths []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

func saveConfig(path string, cfg agentConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
