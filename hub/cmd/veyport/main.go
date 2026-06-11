package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
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
	"github.com/wyiu/veyport/hub/internal/store"
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

	jwtSecret, err := server.InitJWTSecret(st)
	if err != nil {
		return fmt.Errorf("init JWT secret: %w", err)
	}

	notifier := notify.New(st, jwtSecret)
	defer notifier.Close()

	caCert, caKey, err := ca.InitCA(st, jwtSecret)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}
	grpcCAPin := fmt.Sprintf("%x", sha256.Sum256(caCert.Raw))

	cm := connmgr.New()
	pending := grpcserver.NewPendingRequests()
	logSessions := grpcserver.NewLogSessions()
	terminalSessions := grpcserver.NewTerminalSessions()

	srv := server.New(server.Config{
		Addr:             *addr,
		Store:            st,
		JWTSecret:        jwtSecret,
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
	})

	// Start heartbeat monitor
	stopHeartbeat := make(chan struct{})
	grpcSrv.StartHeartbeatMonitor(stopHeartbeat)

	// Start gRPC server in background
	grpcErrCh := make(chan error, 1)
	go func() {
		grpcErrCh <- grpcSrv.Start()
	}()

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		fmt.Println("\nShutting down...")
		close(stopHeartbeat)
		grpcSrv.Stop()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		srv.Shutdown(shutdownCtx)
	}()

	return srv.Start()
}
