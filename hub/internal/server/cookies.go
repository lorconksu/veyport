package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

const (
	cookieAccess  = "__Host-veyport_access"
	cookieRefresh = "__Host-veyport_refresh"
	cookieCSRF    = "__Host-veyport_csrf"
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
		Path:     "/",
		MaxAge:   604800, // 7 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	csrfToken := generateCSRFToken()
	// The double-submit CSRF token must be readable by the browser. Access and
	// refresh cookies remain HttpOnly; cookies_test.go checks both distinctions.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-httponly.cookie-missing-httponly
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
	for _, name := range []string{cookieAccess, "veyport_access", legacyCookieAccess} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	for _, name := range []string{cookieRefresh, "veyport_refresh", legacyCookieRefresh} {
		path := "/api/auth/refresh"
		if name == cookieRefresh {
			path = "/"
		}
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Path:     path,
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	for _, name := range []string{cookieCSRF, "veyport_csrf", legacyCookieCSRF} {
		// Clear the intentionally browser-readable CSRF cookie, matching issuance.
		// nosemgrep: go.lang.security.audit.net.cookie-missing-httponly.cookie-missing-httponly
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

func uniquePortalCookie(r *http.Request, name string) string {
	value := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			count++
			value = c.Value
		}
	}
	if count != 1 {
		return ""
	}
	return value
}

// readAccessToken reads the access token from the cookie first, falling back
// to the Authorization: Bearer header.
func readAccessToken(r *http.Request) string {
	if value := uniquePortalCookie(r, cookieAccess); value != "" {
		return value
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
	if value := uniquePortalCookie(r, cookieCSRF); value != "" {
		return value
	}
	return ""
}

// isUsingBearerAuth returns true if the request has an Authorization: Bearer header.
func isUsingBearerAuth(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), bearerPrefix)
}
