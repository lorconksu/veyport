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
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	hub "github.com/wyiu/veyport/hub"
	"github.com/wyiu/veyport/hub/internal/auditruntime"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/ca"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/notify"
	"github.com/wyiu/veyport/hub/internal/server"
	"github.com/wyiu/veyport/hub/internal/sshconfig"
	"github.com/wyiu/veyport/hub/internal/sshgw"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
	"github.com/wyiu/veyport/proto/protectedinput"
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
	securityStateDir := flag.String("security-state-dir", "", "private persistent security state directory (default beside database)")
	auditRuntimePath := flag.String("audit-runtime-config", "", "private operator-pinned audit runtime configuration (optional in Standard)")
	executionSpoolDir := flag.String("execution-spool-dir", "", "private pre-provisioned encrypted filesystem directory for protected execution input")
	applicationDomain := flag.String("application-domain", "", "exact application hostname namespace (e.g. apps.yiucloud.com)")
	applicationControlDenyAuthorities := flag.String("application-control-deny-authorities", "", "CSV of additional protected Hub host:port authorities (published/private control mappings)")
	applicationPortalOrigin := flag.String("application-portal-origin", "", "fixed HTTPS portal origin for application login")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(server.Version)
		return nil
	}

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
	if *securityStateDir == "" {
		*securityStateDir = filepath.Join(filepath.Dir(*dbPath), ".veyport-security")
	}
	installationID, err := authorization.InitInstallation(*securityStateDir)
	if err != nil {
		return fmt.Errorf("initialize durable security state: %w", err)
	}

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
	executionSessions := grpcserver.NewExecutionSessions(terminalSessions, cm)
	agentUpdates, err := grpcserver.NewAgentUpdates(st, cm, terminalSessions)
	if err != nil {
		return fmt.Errorf("initialize agent update reconciliation: %w", err)
	}
	transition := authorization.TransitionConfig{InstallationID: installationID, EnrollmentPath: filepath.Join(*securityStateDir, "enhanced-enrollment.json")}
	var auditRuntime *auditruntime.Runtime
	var protectedExecution *sshgw.ProtectedExecutionConfig
	var gatewayState atomic.Pointer[sshgw.Server]
	if *auditRuntimePath != "" {
		var spool protectedinput.Store
		manager, spoolErr := protectedinput.New(*executionSpoolDir)
		if spoolErr != nil {
			log.Printf("Protected execution unavailable: encrypted input storage is not ready")
		} else {
			spool = manager
		}
		auditRuntime, err = auditruntime.Load(*auditRuntimePath, auditruntime.Options{
			Store: st, Spool: spool,
			GatewayReady:      func() bool { gateway := gatewayState.Load(); return gateway != nil && gateway.Ready() },
			SupportsProtected: executionSessions.SupportsProtected,
			ResolveSecret:     func(ref string) (string, string, error) { return server.ResolveSecuritySecret(st, storageKey, ref) },
		})
		if err != nil {
			return fmt.Errorf("load protected audit runtime: %w", err)
		}
		defer auditRuntime.Close()
		transition.Evidence = auditRuntime.Evidence()
		protectedExecution = &sshgw.ProtectedExecutionConfig{Spool: spool, ResolveArchive: auditRuntime.ResolveArchive}
	}
	var destinationTester server.SecurityDestinationTester
	var allowedAuditHosts []string
	var originalAccess server.OriginalAccessConfig
	if auditRuntime != nil {
		destinationTester = auditRuntime
		allowedAuditHosts = auditRuntime.AllowedHosts()
		originalAccess.ResolveArchive = auditRuntime.ResolveOriginalArchive
	}

	srv := server.New(server.Config{
		ApplicationDomain:         *applicationDomain,
		ApplicationPortalOrigin:   *applicationPortalOrigin,
		SecurityTransition:        transition,
		SecurityDestinationTester: destinationTester,
		SecurityAllowedHosts:      allowedAuditHosts,
		OriginalAccess:            originalAccess,
		Addr:                      *addr,
		Store:                     st,
		JWTSecret:                 jwtSecret,
		StorageKey:                storageKey,
		IsDev:                     *dev,
		FrontendFS:                &hub.FrontendFS,
		AgentBinDir:               *agentBinDir,
		GRPCAddr:                  *grpcAddr,
		GRPCExternalAddr:          *grpcExternalAddr,
		GRPCCACertSHA256:          grpcCAPin,
		ConnMgr:                   cm,
		Pending:                   pending,
		LogSessions:               logSessions,
		TerminalSessions:          terminalSessions,
		AgentUpdates:              agentUpdates,
		Notifier:                  notifier,
		UserCA:                    userCA,
		SSHHostKey:                hostKey,
		SSHConfig:                 sshCfg,
	})

	// Extract hostname from external gRPC address for TLS SAN
	agentUpdates.SetArtifactResolver(srv.ResolveAgentArtifact)
	grpcExternalHost := resolveGRPCExternalHost(*grpcExternalAddr)

	applicationTunnels := grpcserver.NewApplicationTunnels(st, cm, srv.ValidateApplicationTarget)
	defer applicationTunnels.Close()
	forbiddenEndpoints, endpointErr := applicationProtectedEndpoints([]string{*addr, *grpcAddr, *sshAddr}, *applicationPortalOrigin)
	if endpointErr != nil {
		return fmt.Errorf("application listener policy: %w", endpointErr)
	}
	applicationTunnels.SetForbiddenEndpoints(forbiddenEndpoints)
	applicationTunnels.SetForbiddenAuthorities(applicationProtectedAuthorities(*applicationPortalOrigin, *grpcExternalAddr, *applicationControlDenyAuthorities))
	srv.SetApplicationDialer(applicationTunnels)
	grpcSrv := grpcserver.New(grpcserver.Config{
		ApplicationTunnels: applicationTunnels,
		Addr:               *grpcAddr,
		ExternalHostname:   grpcExternalHost,
		Store:              st,
		ConnMgr:            cm,
		Pending:            pending,
		LogSessions:        logSessions,
		TerminalSessions:   terminalSessions,
		ExecutionSessions:  executionSessions,
		AgentUpdates:       agentUpdates,
		CACert:             caCert,
		CAKey:              caKey,
		Notifier:           notifier,
		StorageKey:         storageKey,
	})

	// The gateway shares the CA, host key and terminal machinery with the HTTP
	// and gRPC servers: certificates the hub issues must verify against the key
	// the gateway presents, and an SSH session must land in the same terminal
	// registry the web terminal uses.
	sshSrv := sshgw.New(sshgw.Config{
		SecurityTransition: authorization.TransitionConfig{InstallationID: transition.InstallationID, EnrollmentPath: transition.EnrollmentPath},
		ProtectedExecution: protectedExecution,
		Store:              st,
		UserCA:             userCA,
		HostKey:            hostKey,
		Terminals:          terminalSessions,
		ConnMgr:            cm,
		Pending:            pending,
		Executions:         executionSessions,
		Addr:               sshCfg.Addr,
		Enabled:            sshCfg.Enabled,
	})
	gatewayState.Store(sshSrv)

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

	shutdownDone := installShutdownHandler(ctx, stopHeartbeat, sshSrv, grpcSrv, srv)

	startErr := srv.Start()
	// ListenAndServe can fail before an operator signal (for example, an
	// invalid or already-bound address). Cancel and wait for the same complete
	// shutdown path before runServer's deferred database close runs. Without
	// this join, background server workers can race the closed store and leave
	// files behind after runServer has returned.
	stop()
	<-shutdownDone
	return startErr
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

func installShutdownHandler(ctx context.Context, stopHeartbeat chan struct{}, sshSrv *sshgw.Server, grpcSrv *grpcserver.Server, srv *server.Server) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
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
	return done
}
