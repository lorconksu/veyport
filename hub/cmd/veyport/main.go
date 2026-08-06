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
	if _, err := os.Stat(*dbPath); os.IsNotExist(err) {
		legacy := filepath.Join(filepath.Dir(*dbPath), legacyDBName)
		if filepath.Base(*dbPath) != legacyDBName {
			if _, lerr := os.Stat(legacy); lerr == nil {
				return fmt.Errorf("legacy database %s detected but --db points at %s; "+
					"rename %s to %s or pass --db %s to preserve data", legacy, *dbPath, legacy, *dbPath, legacy)
			}
		}
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
	userCA, err := userca.InitUserCA(st, storageKey)
	if err != nil {
		if !errors.Is(err, userca.ErrCorruptKey) {
			return fmt.Errorf("init SSH user CA: %w", err)
		}
		log.Printf("SSH GATEWAY DEGRADED: init SSH user CA: %v. "+
			"SSH access is disabled until the stored key is restored or cleared; "+
			"the hub continues to serve REST and gRPC.", err)
		userCA = nil
	}

	hostKey, err := userca.InitHostKey(st, storageKey)
	if err != nil {
		if !errors.Is(err, userca.ErrCorruptKey) {
			return fmt.Errorf("init SSH host key: %w", err)
		}
		log.Printf("SSH GATEWAY DEGRADED: init SSH host key: %v. "+
			"SSH access is disabled until the stored key is restored or cleared; "+
			"the hub continues to serve REST and gRPC.", err)
		hostKey = nil
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
	var grpcExternalHost string
	if *grpcExternalAddr != "" {
		if h, _, err := net.SplitHostPort(*grpcExternalAddr); err == nil {
			grpcExternalHost = h
		} else {
			grpcExternalHost = *grpcExternalAddr
		}
	}

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

	// Start gRPC server in background
	grpcErrCh := make(chan error, 1)
	go func() {
		grpcErrCh <- grpcSrv.Start()
	}()

	// Start the SSH gateway in background. Start returns nil without listening
	// when the gateway is disabled or its key material is unusable, so only a
	// genuine bind failure is reported here — and it never stops the hub.
	go func() {
		if err := sshSrv.Start(); err != nil {
			log.Printf("SSH gateway stopped: %v", err)
		}
	}()

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	return srv.Start()
}
