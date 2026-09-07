package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/notify"
	"github.com/wyiu/veyport/hub/internal/sshconfig"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// ReEnrollReleaser is the minimal interface the HTTP server needs from the gRPC
// handler to approve a re-enrollment request. The concrete type is
// *grpcserver.Handler, but the interface prevents a direct import cycle and
// keeps the test surface small.
type ReEnrollReleaser interface {
	ReleaseKEK(serverID, decidedBy string) error
}

type Server struct {
	httpServer        *http.Server
	store             *store.Store
	jwtSecret         string
	storageKey        string
	isDev             bool
	frontendFS        *embed.FS
	agentBinDir       string
	grpcAddr          string
	grpcExternalAddr  string
	grpcCACertSHA256  string
	connMgr           *connmgr.ConnManager
	pending           *grpcserver.PendingRequests
	logSessions       *grpcserver.LogSessions
	terminalSessions  *grpcserver.TerminalSessions
	reEnrollReleaser  ReEnrollReleaser
	logTailMu         sync.Mutex
	logTailSessions   map[string]int
	totpCache         *auth.TOTPUsedCodes
	tokenBlacklist    *auth.TokenBlacklist
	notifier          *notify.Notifier
	ldapAuthenticator LDAPAuthenticator
	ldapDial          func(LDAPConfig) (LDAPConnection, error)
	// SSH gateway material. userCA signs short-lived user certificates,
	// sshHostKey is the gateway's stable host identity, and sshConfig is the
	// effective gateway configuration. All three are nil/zero when the gateway
	// is not wired up, which the SSH handlers treat as "unavailable".
	userCA     *userca.UserCA
	sshHostKey ssh.Signer
	sshConfig  sshconfig.Config
	// nowFn is the server's clock. It defaults to the real UTC clock and
	// exists so account-lockout tests can advance time deterministically
	// without sleeping; override it in tests with SetClock. Access goes
	// through the now() method and nowMu: the session pruner's background
	// goroutine (session_prune.go) reads the clock concurrently with any
	// test that calls SetClock after construction, since New starts that
	// goroutine immediately.
	nowMu sync.RWMutex
	nowFn func() time.Time
	// sessionPruneStop, sessionPruneStopOnce and sessionPruneWG coordinate the
	// background goroutine started by startSessionPruner (see
	// session_prune.go), which periodically removes ended session rows older
	// than the retention window (FR-013).
	sessionPruneStop     chan struct{}
	sessionPruneStopOnce *sync.Once
	sessionPruneWG       sync.WaitGroup
}

// now returns the current time via the server's clock (real UTC time by
// default, overridable in tests via SetClock). Guarded by nowMu so the
// session pruner's background goroutine can read it safely while a test
// calls SetClock concurrently.
func (s *Server) now() time.Time {
	s.nowMu.RLock()
	defer s.nowMu.RUnlock()
	return s.nowFn()
}

type Config struct {
	Addr              string
	Store             *store.Store
	JWTSecret         string
	StorageKey        string
	IsDev             bool
	FrontendFS        *embed.FS
	AgentBinDir       string
	GRPCAddr          string
	GRPCExternalAddr  string
	GRPCCACertSHA256  string
	ConnMgr           *connmgr.ConnManager
	Pending           *grpcserver.PendingRequests
	LogSessions       *grpcserver.LogSessions
	TerminalSessions  *grpcserver.TerminalSessions
	ReEnrollReleaser  ReEnrollReleaser
	Notifier          *notify.Notifier
	LDAPAuthenticator LDAPAuthenticator
	// UserCA, SSHHostKey and SSHConfig wire the SSH gateway. Leave them unset
	// to run the hub without SSH certificate issuance.
	UserCA     *userca.UserCA
	SSHHostKey ssh.Signer
	SSHConfig  sshconfig.Config
}

func New(cfg Config) *Server {
	// storageKey is used for all at-rest encryption (TOTP, SMTP, LDAP, CA).
	// Fall back to JWTSecret when StorageKey is not provided so that in-package
	// unit tests that construct a Server without InitStorageKey continue to work.
	storageKey := cfg.StorageKey
	if storageKey == "" {
		storageKey = cfg.JWTSecret
	}

	s := &Server{
		store:             cfg.Store,
		jwtSecret:         cfg.JWTSecret,
		storageKey:        storageKey,
		isDev:             cfg.IsDev,
		frontendFS:        cfg.FrontendFS,
		agentBinDir:       cfg.AgentBinDir,
		grpcAddr:          cfg.GRPCAddr,
		grpcExternalAddr:  cfg.GRPCExternalAddr,
		grpcCACertSHA256:  cfg.GRPCCACertSHA256,
		connMgr:           cfg.ConnMgr,
		pending:           cfg.Pending,
		logSessions:       cfg.LogSessions,
		terminalSessions:  cfg.TerminalSessions,
		reEnrollReleaser:  cfg.ReEnrollReleaser,
		logTailSessions:   make(map[string]int),
		totpCache:         auth.NewTOTPUsedCodes(),
		tokenBlacklist:    auth.NewTokenBlacklist(cfg.Store.DB()),
		notifier:          cfg.Notifier,
		ldapAuthenticator: cfg.LDAPAuthenticator,
		userCA:            cfg.UserCA,
		sshHostKey:        cfg.SSHHostKey,
		sshConfig:         cfg.SSHConfig,
		nowFn:             func() time.Time { return time.Now().UTC() },
	}

	s.installAuditObservers()

	mux := s.routes()

	s.httpServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	s.startSessionPruner(sessionPruneInterval, sessionPruneRetention)

	return s
}

func (s *Server) installAuditObservers() {
	if s.store == nil {
		return
	}
	s.store.SetAuditObservers(func(health model.AuditHealth) {
		if s.notifier == nil {
			return
		}
		context := map[string]string{
			"failure_count": strconv.Itoa(health.FailureCount),
		}
		if health.LastFailureAt != nil {
			context["last_failure_at"] = *health.LastFailureAt
		}
		if health.LastFailureReason != nil {
			context["last_failure_reason"] = *health.LastFailureReason
		}
		s.notifier.Notify(model.NotifyAuditDegraded, context)
	}, func(health model.AuditHealth) {
		if s.notifier == nil {
			return
		}
		context := map[string]string{
			"failure_count": strconv.Itoa(health.FailureCount),
		}
		if health.LastRecoveredAt != nil {
			context["last_recovered_at"] = *health.LastRecoveredAt
		}
		s.notifier.Notify(model.NotifyAuditRecovered, context)
	})
}

// SetReEnrollReleaser wires the gRPC handler into the HTTP server after both
// are constructed (since grpcSrv is built after srv in main).
func (s *Server) SetReEnrollReleaser(r ReEnrollReleaser) {
	s.reEnrollReleaser = r
}

func (s *Server) Start() error {
	fmt.Printf("Veyport Hub listening on %s\n", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.stopSessionPruner()
	return s.httpServer.Shutdown(ctx)
}

// ClearTOTPCache removes all tracked TOTP codes from the replay cache.
// Intended for use in tests where the same TOTP code may be reused across steps.
func (s *Server) ClearTOTPCache() {
	s.totpCache.Clear()
}

// SetClock overrides the server's clock. Intended for use in tests that need
// to advance time deterministically (e.g. to observe a lockout window elapse
// or a lock expire) without sleeping.
func (s *Server) SetClock(now func() time.Time) {
	s.nowMu.Lock()
	defer s.nowMu.Unlock()
	s.nowFn = now
}

// DecryptTOTPSecret decrypts an encrypted TOTP secret (with "enc:" prefix).
// Returns the raw secret for test use. If the secret is not encrypted, returns it as-is.
func (s *Server) DecryptTOTPSecret(encrypted string) (string, error) {
	return s.decryptTOTPSecret(encrypted)
}

// spaHandler serves the embedded frontend SPA. In dev mode, it returns a
// helpful error since the frontend is served by the Vite dev server. In
// production it serves static files from the embedded FS and falls back to
// index.html for any path that doesn't match a real file (React Router).
func (s *Server) spaHandler() http.Handler {
	if s.isDev || s.frontendFS == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "frontend not embedded — run Vite dev server on :5173", http.StatusServiceUnavailable)
		})
	}

	sub, err := fs.Sub(*s.frontendFS, "web/dist")
	if err != nil {
		panic("spaHandler: failed to sub web/dist from embedded FS: " + err.Error())
	}

	fileServer := http.FileServer(http.FS(sub))

	// Pre-read index.html once at startup instead of on every fallback request
	indexHTML, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("spaHandler: index.html not found in embedded FS: " + err.Error())
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to open the requested file.
		f, openErr := sub.Open(r.URL.Path[1:]) // strip leading /
		if openErr == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}

		// File not found — serve cached index.html for client-side routing.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(indexHTML)
	})
}

// InitStorageKey initialises the at-rest encryption key used by all four
// encryption consumers (TOTP secret, SMTP password, LDAP bind password,
// CA private key). Three paths:
//  1. storage_key already exists → return it (idempotent, no writes, no audit).
//  2. jwt_signing_key exists (legacy install) → copy its value into storage_key,
//     write one auth.storage_key_separated audit entry, return the value.
//     The derived AES key is bit-identical so every existing ciphertext decrypts
//     unchanged — zero re-encryption needed.
//  3. Neither exists (fresh install) → generate 32 random bytes, hex-encode, persist.
func InitStorageKey(st *store.Store) (string, error) {
	// Path 1: storage_key already set — return it unchanged.
	if existing, err := st.GetConfig("storage_key"); err == nil && existing != "" {
		return existing, nil
	}

	// Path 2: legacy install — adopt the jwt_signing_key value.
	if jwtKey, err := st.GetConfig("jwt_signing_key"); err == nil && jwtKey != "" {
		if err := st.SetConfig("storage_key", jwtKey); err != nil {
			return "", fmt.Errorf("store storage key (legacy adopt): %w", err)
		}

		// Write exactly one audit entry recording the migration source.
		detail := `{"migrated_from": "jwt_signing_key"}`
		_ = st.LogAudit(model.AuditEntry{
			ID:        uuid.NewString(),
			Action:    model.AuditStorageKeySeparated,
			Outcome:   model.AuditOutcomeSuccess,
			ActorType: model.AuditActorTypeSystem,
			Detail:    &detail,
		})

		return jwtKey, nil
	}

	// Path 3: fresh install — generate an independent random storage key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate random storage key: %w", err)
	}
	secret := hex.EncodeToString(key)

	if err := st.SetConfig("storage_key", secret); err != nil {
		return "", fmt.Errorf("store storage key: %w", err)
	}

	// Re-read to protect against TOCTOU race (mirrors InitJWTSecret pattern).
	stored, err := st.GetConfig("storage_key")
	if err != nil {
		return "", fmt.Errorf("re-read storage key: %w", err)
	}

	return stored, nil
}

// InitJWTSecret generates a random JWT signing key on first run,
// or retrieves the existing one from the database.
func InitJWTSecret(st *store.Store) (string, error) {
	secret, err := st.GetConfig("jwt_signing_key")
	if err == nil && secret != "" {
		return secret, nil
	}

	// Generate new 256-bit key using crypto/rand
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate random key: %w", err)
	}
	secret = hex.EncodeToString(key)

	if err := st.SetConfig("jwt_signing_key", secret); err != nil {
		return "", fmt.Errorf("store jwt key: %w", err)
	}

	// Re-read to protect against TOCTOU race
	stored, err := st.GetConfig("jwt_signing_key")
	if err != nil {
		return "", fmt.Errorf("re-read jwt key: %w", err)
	}

	return stored, nil
}
