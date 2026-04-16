package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
)

type contextKey string

const (
	ctxUserID    contextKey = "user_id"
	ctxUserRole  contextKey = "user_role"
	ctxTokenType contextKey = "token_type"
	ctxRequestID contextKey = "request_id"
)

func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxUserID).(string)
	return v
}

func UserRoleFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxUserRole).(string)
	return v
}

func TokenTypeFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxTokenType).(string)
	return v
}

func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxRequestID).(string)
	return v
}

// authMiddleware validates JWT from Authorization header and enforces token type.
func (s *Server) authMiddleware(requiredType string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := readAccessToken(r)
		if tokenStr == "" {
			respondError(w, http.StatusUnauthorized, "missing authorization token")
			return
		}

		userID, role, tokenType, err := s.authenticateRequestToken(tokenStr)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		if !isAllowedTokenType(requiredType, tokenType) {
			respondError(w, http.StatusForbidden, "invalid token type for this endpoint")
			return
		}

		ctx := context.WithValue(r.Context(), ctxUserID, userID)
		ctx = context.WithValue(ctx, ctxUserRole, role)
		ctx = context.WithValue(ctx, ctxTokenType, tokenType)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) authenticateRequestToken(tokenStr string) (userID, role, tokenType string, err error) {
	claims, err := auth.ValidateToken(s.jwtSecret, tokenStr)
	if err == nil {
		if claims.ID != "" && s.tokenBlacklist != nil && s.tokenBlacklist.IsBlacklisted(claims.ID) {
			return "", "", "", fmt.Errorf("token has been revoked")
		}
		if claims.TokenType == auth.TokenTypeAccess {
			user, err := s.store.GetUserByID(claims.Subject)
			if err != nil || claims.TokenGeneration != user.TokenGeneration {
				return "", "", "", fmt.Errorf("token has been revoked")
			}
		}
		return claims.Subject, claims.Role, claims.TokenType, nil
	}

	if !auth.LooksLikeAPIToken(tokenStr) {
		return "", "", "", err
	}

	apiToken, err := s.store.GetActiveAPITokenByHash(auth.HashAPIToken(tokenStr))
	if err != nil {
		return "", "", "", err
	}

	user, err := s.store.GetUserByID(apiToken.UserID)
	if err != nil {
		return "", "", "", err
	}

	_ = s.store.UpdateAPITokenLastUsed(apiToken.ID, time.Now().UTC())
	return user.ID, string(user.Role), auth.TokenTypeAPIToken, nil
}

func isAllowedTokenType(requiredType, tokenType string) bool {
	if requiredType == auth.TokenTypeAccess && tokenType == auth.TokenTypeAPIToken {
		return true
	}
	return requiredType == tokenType
}

func (s *Server) interactiveOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if TokenTypeFromContext(r.Context()) != auth.TokenTypeAccess {
			respondError(w, http.StatusForbidden, "interactive login required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminOnly wraps a handler to require admin role.
func (s *Server) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserRoleFromContext(r.Context()) != string(model.RoleAdmin) {
			respondError(w, http.StatusForbidden, "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auditAccessOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := UserRoleFromContext(r.Context())
		if role != string(model.RoleAdmin) && role != string(model.RoleAuditor) {
			respondError(w, http.StatusForbidden, "audit access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each request.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s request_id=%s", r.Method, r.URL.Path, time.Since(start), RequestIDFromContext(r.Context()))
	})
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if !isValidRequestID(requestID) {
			requestID = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), ctxRequestID, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isValidRequestID checks that a client-supplied request ID is safe to reflect
// in headers and logs: alphanumeric plus hyphens/underscores, max 128 chars.
func isValidRequestID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// corsMiddleware adds CORS headers for development.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isDev {
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimiter tracks login attempts per IP.
type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

const maxTrackedIPs = 100000

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// evictOldest removes the entry with the oldest last attempt from the rate
// limiter map, skipping skipIP so its history is preserved.
func (rl *rateLimiter) evictOldest(skipIP string) {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, attempts := range rl.attempts {
		if k == skipIP {
			continue
		}
		last := attempts[len(attempts)-1]
		if first || last.Before(oldestTime) {
			oldestKey = k
			oldestTime = last
			first = false
		}
	}
	if oldestKey != "" {
		delete(rl.attempts, oldestKey)
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Filter expired entries
	valid := rl.attempts[ip][:0]
	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	// Clean up empty entries to prevent memory leak
	if len(valid) == 0 {
		delete(rl.attempts, ip)
	} else {
		rl.attempts[ip] = valid
	}

	if len(valid) >= rl.limit {
		return false
	}

	// Cap total tracked IPs to prevent memory exhaustion from IP rotation attacks.
	// Evict the entry with the oldest last attempt to avoid removing active attackers.
	// Skip the current IP to prevent resetting its rate limit history.
	if len(rl.attempts) >= maxTrackedIPs {
		rl.evictOldest(ip)
	}

	rl.attempts[ip] = append(valid, now)
	return true
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always use RemoteAddr for rate limiting - never trust X-Forwarded-For
		// When behind Traefik, RemoteAddr is set to the real client IP
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr // fallback if no port
		}

		if !rl.allow(ip) {
			w.Header().Set("Retry-After", "60")
			respondError(w, http.StatusTooManyRequests, "too many login attempts")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// securityHeaders adds standard security headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.URL.Path == "/" || !strings.HasPrefix(r.URL.Path, "/api/") {
			// CSP for HTML pages only, not API responses
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		}
		next.ServeHTTP(w, r)
	})
}

// apiCacheControl sets Cache-Control headers on API responses to prevent
// browsers from caching authenticated data.
func apiCacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the direct peer IP from RemoteAddr.
// Forwarded headers are not trusted here because the hub may be reachable
// without a proxy, and audit/security signals should not be spoofable.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
