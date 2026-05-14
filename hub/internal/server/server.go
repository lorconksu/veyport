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

	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/connmgr"
	"github.com/wyiu/aerodocs/hub/internal/grpcserver"
	"github.com/wyiu/aerodocs/hub/internal/model"
	"github.com/wyiu/aerodocs/hub/internal/notify"
	"github.com/wyiu/aerodocs/hub/internal/store"
)

// Version is set at build time via -ldflags.
var Version = "dev"

type Server struct {
	httpServer        *http.Server
	store             *store.Store
	jwtSecret         string
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
	logTailMu         sync.Mutex
	logTailSessions   map[string]int
	totpCache         *auth.TOTPUsedCodes
	tokenBlacklist    *auth.TokenBlacklist
	notifier          *notify.Notifier
	ldapAuthenticator LDAPAuthenticator
}

type Config struct {
	Addr              string
	Store             *store.Store
	JWTSecret         string
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
	Notifier          *notify.Notifier
	LDAPAuthenticator LDAPAuthenticator
}

func New(cfg Config) *Server {
	s := &Server{
		store:             cfg.Store,
		jwtSecret:         cfg.JWTSecret,
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
		logTailSessions:   make(map[string]int),
		totpCache:         auth.NewTOTPUsedCodes(),
		tokenBlacklist:    auth.NewTokenBlacklist(cfg.Store.DB()),
		notifier:          cfg.Notifier,
		ldapAuthenticator: cfg.LDAPAuthenticator,
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

func (s *Server) Start() error {
	fmt.Printf("AeroDocs Hub listening on %s\n", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// ClearTOTPCache removes all tracked TOTP codes from the replay cache.
// Intended for use in tests where the same TOTP code may be reused across steps.
func (s *Server) ClearTOTPCache() {
	s.totpCache.Clear()
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
