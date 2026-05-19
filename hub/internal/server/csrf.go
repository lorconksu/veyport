package server

import (
	"net"
	"net/http"
	"net/url"
)

// csrfExemptPaths lists public auth endpoints that must work before a CSRF cookie exists.
var csrfExemptPaths = []string{
	"/api/auth/login",
	"/api/auth/register",
	"/api/auth/refresh",
	"/api/auth/logout",
	"/api/auth/login/totp",
}

// isMutationMethod returns true for HTTP methods that modify server state.
func isMutationMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

// isCSRFExemptPath returns true if the request path is a public auth endpoint
// that must work before a CSRF cookie exists.
func isCSRFExemptPath(path string) bool {
	for _, p := range csrfExemptPaths {
		if path == p {
			return true
		}
	}
	return false
}

// csrfTokensMatch returns true if the cookie and header CSRF tokens are both
// non-empty and equal.
func csrfTokensMatch(r *http.Request) bool {
	cookie := readCSRFCookie(r)
	header := readCSRFToken(r)
	return cookie != "" && header != "" && cookie == header
}

// csrfMiddleware enforces the double-submit cookie pattern for mutating requests.
// Safe methods (GET, HEAD, OPTIONS) are exempt. Requests using Bearer authentication
// are also exempt since they originate from non-browser clients.
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isMutationMethod(r.Method) || isUsingBearerAuth(r) || isCSRFExemptPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Origin header validation — reject cross-origin mutations
		if origin := r.Header.Get("Origin"); origin != "" {
			if !isValidOrigin(r, origin, s.requestScheme(r)) {
				respondError(w, http.StatusForbidden, "origin not allowed")
				return
			}
		}

		// No cookie-based session means no CSRF risk.
		// If neither the access cookie nor the CSRF cookie is present, this
		// request is not using cookie auth, so skip CSRF validation.
		if readCSRFCookie(r) == "" && readAccessToken(r) == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Validate CSRF: X-CSRF-Token header must match veyport_csrf cookie.
		if !csrfTokensMatch(r) {
			respondError(w, http.StatusForbidden, "CSRF validation failed")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if isLoopbackHost(r.Host) {
		return "http"
	}
	if !s.isDev {
		return "https"
	}
	return "http"
}

func isLoopbackHost(hostport string) bool {
	host := hostport
	if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsedHost
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizedOriginAuthority(hostport, scheme string) string {
	host := hostport
	port := ""
	if parsedHost, parsedPort, err := net.SplitHostPort(hostport); err == nil {
		host = parsedHost
		port = parsedPort
	}
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}

// isValidOrigin checks that the Origin header exactly matches the effective
// request origin, including scheme and port after default-port normalization.
func isValidOrigin(r *http.Request, origin, scheme string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != scheme {
		return false
	}
	return normalizedOriginAuthority(u.Host, u.Scheme) == normalizedOriginAuthority(r.Host, scheme)
}
