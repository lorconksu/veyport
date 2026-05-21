package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

const (
	cookieAccess  = "veyport_access"
	cookieRefresh = "veyport_refresh"
	cookieCSRF    = "veyport_csrf"
	bearerPrefix  = "Bearer "

	// Legacy v1.x cookie names — cleared on logout for one release so browsers
	// that retain them from a pre-v2 session drop them on next sign-out.
	legacyCookieAccess  = "aerodocs_access"
	legacyCookieRefresh = "aerodocs_refresh"
	legacyCookieCSRF    = "aerodocs_csrf"
)

// setAuthCookies sets the access, refresh, and CSRF cookies on the response.
// Secure is set because the app is always accessed over HTTPS (TLS terminated
// at Traefik). This tells browsers to never send cookies over plain HTTP.
func setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAccess,
		Value:    accessToken,
		Path:     "/",
		MaxAge:   900, // 15 minutes
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     cookieRefresh,
		Value:    refreshToken,
		Path:     "/api/auth/refresh",
		MaxAge:   604800, // 7 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	csrfToken := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRF,
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   604800, // 7 days
		HttpOnly: false,  // NOSONAR — intentionally not HttpOnly; double-submit CSRF pattern requires JS access to read the cookie value
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearAuthCookies clears all auth cookies by setting MaxAge to -1. Also clears
// the legacy v1.x cookie names so browsers that still carry them from a pre-v2
// session drop them on logout.
func clearAuthCookies(w http.ResponseWriter) {
	for _, name := range []string{cookieAccess, legacyCookieAccess} {
		http.SetCookie(w, &http.Cookie{ // NOSONAR — clearing cookie (MaxAge=-1); HttpOnly not relevant for deletion
			Name:     name,
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	for _, name := range []string{cookieRefresh, legacyCookieRefresh} {
		http.SetCookie(w, &http.Cookie{ // NOSONAR — clearing cookie (MaxAge=-1); HttpOnly not relevant for deletion
			Name:     name,
			Path:     "/api/auth/refresh",
			MaxAge:   -1,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	for _, name := range []string{cookieCSRF, legacyCookieCSRF} {
		http.SetCookie(w, &http.Cookie{ // NOSONAR — clearing cookie (MaxAge=-1); CSRF cookie intentionally not HttpOnly (double-submit pattern)
			Name:     name,
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

// readAccessToken reads the access token from the cookie first, falling back
// to the Authorization: Bearer header.
func readAccessToken(r *http.Request) string {
	if c, err := r.Cookie(cookieAccess); err == nil && c.Value != "" {
		return c.Value
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, bearerPrefix) {
		return strings.TrimPrefix(auth, bearerPrefix)
	}
	return ""
}

// generateCSRFToken returns a 32-byte random hex string.
func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// readCSRFToken reads the CSRF token from the X-CSRF-Token header.
func readCSRFToken(r *http.Request) string {
	return r.Header.Get("X-CSRF-Token")
}

// readCSRFCookie reads the CSRF cookie value from the request.
func readCSRFCookie(r *http.Request) string {
	if c, err := r.Cookie(cookieCSRF); err == nil {
		return c.Value
	}
	return ""
}

// isUsingBearerAuth returns true if the request has an Authorization: Bearer header.
func isUsingBearerAuth(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), bearerPrefix)
}
