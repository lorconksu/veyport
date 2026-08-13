package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	hub "github.com/wyiu/veyport/hub"
	"github.com/wyiu/veyport/hub/internal/ca"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/notify"
	"github.com/wyiu/veyport/hub/internal/server"
	"github.com/wyiu/veyport/hub/internal/sshconfig"
	"github.com/wyiu/veyport/hub/internal/sshgw"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
)

const legacyDBName = "aerodocs.db"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		if err := runAdmin(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := runServer(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runServer() error {
	addr := flag.String("addr", ":8080", "listen address")
	dbPath := flag.String("db", "veyport.db", "SQLite database path")
	dev := flag.Bool("dev", false, "enable development mode (CORS)")
	grpcAddr := flag.String("grpc-addr", ":9090", "gRPC listen address")
	grpcExternalAddr := flag.String("grpc-external-addr", "", "external gRPC address for agent install commands (e.g. hub.example.com:9443)")
	agentBinDir := flag.String("agent-bin-dir", "./bin", "directory containing agent binaries")
	sshAddr := flag.String("ssh-addr", sshconfig.DefaultAddr, "SSH gateway listen address")
	flag.Parse()

	// Detect legacy aerodocs.db when the configured veyport.db doesn't exist on the
	// same volume; refuse to start rather than silently presenting the fresh-install
	// wizard against an empty DB while the populated legacy file sits beside it.
	if err := checkLegacyDB(*dbPath); err != nil {
		return err
	}

	st, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	// Effective SSH gateway configuration; consumed by both the REST handlers
	// (certificate issuance) and the gateway listener below.
	sshCfg := sshconfig.Load(st, *sshAddr)

	jwtSecret, err := server.InitJWTSecret(st)
	if err != nil {
		return fmt.Errorf("init JWT secret: %w", err)
	}

	storageKey, err := server.InitStorageKey(st)
	if err != nil {
		return fmt.Errorf("init storage key: %w", err)
	}

	notifier := notify.New(st, storageKey)
	defer notifier.Close()

	caCert, caKey, err := ca.InitCA(st, storageKey)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}
	grpcCAPin := fmt.Sprintf("%x", sha256.Sum256(caCert.Raw))

	// SSH trust material. Corrupt or undecryptable key material disables only
	// the SSH plane: the hub keeps serving REST and gRPC, and the stored value
	// is left untouched for an operator to restore or clear deliberately
	// (FR-006). Any other failure is an init failure like the ones above.
	userCA, hostKey, err := initSSHTrust(st, storageKey)
	if err != nil {
		return err
	}

	cm := connmgr.New()
	pending := grpcserver.NewPendingRequests()
	logSessions := grpcserver.NewLogSessions()
	terminalSessions := grpcserver.NewTerminalSessions()

	srv := server.New(server.Config{
		Addr:             *addr,
		Store:            st,
		JWTSecret:        jwtSecret,
		StorageKey:       storageKey,
		IsDev:            *dev,
		FrontendFS:       &hub.FrontendFS,
		AgentBinDir:      *agentBinDir,
		GRPCAddr:         *grpcAddr,
		GRPCExternalAddr: *grpcExternalAddr,
		GRPCCACertSHA256: grpcCAPin,
		ConnMgr:          cm,
		Pending:          pending,
		LogSessions:      logSessions,
		TerminalSessions: terminalSessions,
		Notifier:         notifier,
		UserCA:           userCA,
		SSHHostKey:       hostKey,
		SSHConfig:        sshCfg,
	})

	// Extract hostname from external gRPC address for TLS SAN
	grpcExternalHost := resolveGRPCExternalHost(*grpcExternalAddr)

	grpcSrv := grpcserver.New(grpcserver.Config{
		Addr:             *grpcAddr,
		ExternalHostname: grpcExternalHost,
		Store:            st,
		ConnMgr:          cm,
		Pending:          pending,
		LogSessions:      logSessions,
		TerminalSessions: terminalSessions,
		CACert:           caCert,
		CAKey:            caKey,
		Notifier:         notifier,
		StorageKey:       storageKey,
	})

	// The gateway shares the CA, host key and terminal machinery with the HTTP
	// and gRPC servers: certificates the hub issues must verify against the key
	// the gateway presents, and an SSH session must land in the same terminal
	// registry the web terminal uses.
	sshSrv := sshgw.New(sshgw.Config{
		Store:     st,
		UserCA:    userCA,
		HostKey:   hostKey,
		Terminals: terminalSessions,
		ConnMgr:   cm,
		Pending:   pending,
		Addr:      sshCfg.Addr,
		Enabled:   sshCfg.Enabled,
	})

	// Wire the gRPC handler into the HTTP server so the re-enroll approve
	// endpoint can call ReleaseKEK without a global or import cycle.
	srv.SetReEnrollReleaser(grpcSrv.Handler())

	// Start heartbeat monitor
	stopHeartbeat := make(chan struct{})
	grpcSrv.StartHeartbeatMonitor(stopHeartbeat)

	startServers(grpcSrv, sshSrv)

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	installShutdownHandler(ctx, stopHeartbeat, sshSrv, grpcSrv, srv)

	return srv.Start()
}

// checkLegacyDB detects a legacy aerodocs.db sitting beside a not-yet-created
// dbPath and refuses to start, rather than silently presenting the
// fresh-install wizard against an empty DB while the populated legacy file
// sits unused. Extracted from runServer to keep its cognitive complexity down
// (go:S3776); the behavior is unchanged.
func checkLegacyDB(dbPath string) error {
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		return nil
	}
	if filepath.Base(dbPath) == legacyDBName {
		return nil
	}
	legacy := filepath.Join(filepath.Dir(dbPath), legacyDBName)
	if _, err := os.Stat(legacy); err != nil {
		return nil
	}
	return fmt.Errorf("legacy database %s detected but --db points at %s; "+
		"rename %s to %s or pass --db %s to preserve data", legacy, dbPath, legacy, dbPath, legacy)
}

// initSSHTrust initializes the SSH user CA and host key, applying the FR-006
// degradation policy: corrupt or undecryptable key material disables only the
// SSH plane (logged, key returned as nil, hub keeps serving REST and gRPC),
// while any other error is fatal like the other init* calls in runServer.
// Extracted from runServer to keep its cognitive complexity down (go:S3776);
// the boot order (user CA before host key) and the policy are unchanged.
func initSSHTrust(st *store.Store, storageKey string) (*userca.UserCA, ssh.Signer, error) {
	userCA, err := userca.InitUserCA(st, storageKey)
	if err != nil {
		if !errors.Is(err, userca.ErrCorruptKey) {
			return nil, nil, fmt.Errorf("init SSH user CA: %w", err)
		}
		log.Printf("SSH GATEWAY DEGRADED: init SSH user CA: %v. "+
			"SSH access is disabled until the stored key is restored or cleared; "+
			"the hub continues to serve REST and gRPC.", err)
		userCA = nil
	}

	hostKey, err := userca.InitHostKey(st, storageKey)
	if err != nil {
		if !errors.Is(err, userca.ErrCorruptKey) {
			return nil, nil, fmt.Errorf("init SSH host key: %w", err)
		}
		log.Printf("SSH GATEWAY DEGRADED: init SSH host key: %v. "+
			"SSH access is disabled until the stored key is restored or cleared; "+
			"the hub continues to serve REST and gRPC.", err)
		hostKey = nil
	}

	return userCA, hostKey, nil
}

// resolveGRPCExternalHost extracts the hostname portion of grpcExternalAddr
// for use as the gRPC server's TLS SAN, falling back to the address as-is
// when it isn't in host:port form (or is empty).
func resolveGRPCExternalHost(grpcExternalAddr string) string {
	if grpcExternalAddr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(grpcExternalAddr); err == nil {
		return h
	}
	return grpcExternalAddr
}

// startServers starts the gRPC and SSH gateway listeners in background
// goroutines, exactly as runServer did inline. gRPC's error is captured on an
// unread, single-buffered channel (as before extraction — nothing consumes
// it); the SSH gateway logs its own errors and never stops the hub, since
// Start returns nil without listening when the gateway is disabled or its key
// material is unusable.
func startServers(grpcSrv *grpcserver.Server, sshSrv *sshgw.Server) {
	grpcErrCh := make(chan error, 1)
	go func() {
		grpcErrCh <- grpcSrv.Start()
	}()

	go func() {
		if err := sshSrv.Start(); err != nil {
			log.Printf("SSH gateway stopped: %v", err)
		}
	}()
}

// installShutdownHandler starts the goroutine that performs graceful shutdown
// once ctx is done, in the same order runServer used inline: stop the
// heartbeat monitor, stop the SSH gateway, stop gRPC, then shut down the HTTP
// server.
func installShutdownHandler(ctx context.Context, stopHeartbeat chan struct{}, sshSrv *sshgw.Server, grpcSrv *grpcserver.Server, srv *server.Server) {
	go func() {
		<-ctx.Done()
		fmt.Println("\nShutting down...")
		close(stopHeartbeat)
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := sshSrv.Stop(shutdownCtx); err != nil {
			log.Printf("SSH gateway shutdown: %v", err)
		}
		grpcSrv.Stop()
		srv.Shutdown(shutdownCtx)
	}()
}
