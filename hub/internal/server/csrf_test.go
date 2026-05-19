package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ok200 is a simple handler that returns 200 OK for use as the "next" handler.
var ok200 = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

const (
	testExpected403       = "expected 403, got %d"
	testExampleHost       = "example.com"
	testExampleOrigin     = "https://example.com"
	testExampleAPI        = "https://example.com/api/test"
	testExampleHTTPAPI    = "http://example.com/api/test"
	testExamplePortHost   = "example.com:8080"
	testExamplePortAPI    = "https://example.com:8080/api/test"
	testExamplePortOrigin = "https://example.com:8080"
	testExamplePortSSE    = "https://example.com:8080/api/something"
)

func TestCSRFMiddleware_BlocksMutationWithoutToken(t *testing.T) {
	handler := testServer(t).csrfMiddleware(ok200)

	req := httptest.NewRequest(http.MethodPost, testAPISomething, nil)
	req.AddCookie(&http.Cookie{Name: "veyport_csrf", Value: "tok123"})
	// No X-CSRF-Token header.

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf(testExpected403, rr.Code)
	}
}

func TestCSRFMiddleware_AllowsMatchingToken(t *testing.T) {
	handler := testServer(t).csrfMiddleware(ok200)

	req := httptest.NewRequest(http.MethodPost, testAPISomething, nil)
	req.AddCookie(&http.Cookie{Name: "veyport_csrf", Value: "tok123"})
	req.Header.Set(testCSRFTokenHdr, "tok123")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf(testExpected200, rr.Code)
	}
}

func TestCSRFMiddleware_MismatchToken(t *testing.T) {
	handler := testServer(t).csrfMiddleware(ok200)

	req := httptest.NewRequest(http.MethodPost, testAPISomething, nil)
	req.AddCookie(&http.Cookie{Name: "veyport_csrf", Value: "tok123"})
	req.Header.Set(testCSRFTokenHdr, "different-value")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf(testExpected403, rr.Code)
	}
}

func TestCSRFMiddleware_AllowsGET(t *testing.T) {
	handler := testServer(t).csrfMiddleware(ok200)

	req := httptest.NewRequest(http.MethodGet, testAPISomething, nil)
	// No CSRF tokens at all.

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf(testExpected200, rr.Code)
	}
}

func TestCSRFMiddleware_AllowsHEAD(t *testing.T) {
	handler := testServer(t).csrfMiddleware(ok200)

	req := httptest.NewRequest(http.MethodHead, testAPISomething, nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf(testExpected200, rr.Code)
	}
}

func TestCSRFMiddleware_AllowsBearerAuth(t *testing.T) {
	handler := testServer(t).csrfMiddleware(ok200)

	req := httptest.NewRequest(http.MethodPost, testAPISomething, nil)
	req.Header.Set("Authorization", "Bearer some-api-token")
	// No CSRF tokens.

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf(testExpected200, rr.Code)
	}
}

func TestCSRFMiddleware_NoCookies_SkipsValidation(t *testing.T) {
	handler := testServer(t).csrfMiddleware(ok200)

	// No cookies at all = not a cookie-based session (e.g., login/register).
	// CSRF validation should be skipped.
	req := httptest.NewRequest(http.MethodPost, testAPISomething, nil)
	req.Header.Set(testCSRFTokenHdr, "tok123")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (CSRF skipped for non-cookie session), got %d", rr.Code)
	}
}

func TestRequestScheme(t *testing.T) {
	const secureExampleAPI = testExampleAPI
	s := testServer(t)
	req := httptest.NewRequest(http.MethodPost, secureExampleAPI, nil)
	if got := s.requestScheme(req); got != "https" {
		t.Fatalf("requestScheme() = %q, want https", got)
	}

	s.isDev = false
	req = httptest.NewRequest(http.MethodPost, testExampleHTTPAPI, nil)
	if got := s.requestScheme(req); got != "https" {
		t.Fatalf("requestScheme() in production = %q, want https", got)
	}

	req = httptest.NewRequest(http.MethodPost, "http://localhost:8081/api/test", nil)
	req.Host = "localhost:8081"
	if got := s.requestScheme(req); got != "http" {
		t.Fatalf("requestScheme() on loopback = %q, want http", got)
	}
}

func TestIsValidOrigin(t *testing.T) {
	const (
		secureExampleAPI    = testExampleAPI
		secureExampleHost   = testExampleHost
		secureExampleOrigin = testExampleOrigin
		examplePortHost     = testExamplePortHost
		examplePortAPI      = testExamplePortAPI
		localhost5173Origin = "http://localhost:5173"
		localhost5173API    = "http://localhost:5173/api/test"
		localhost3000API    = "http://localhost:3000/api/test"
		loopback3000API     = "http://127.0.0.1:3000/api/test"
	)
	tests := []struct {
		name     string
		url      string
		host     string
		origin   string
		expected bool
	}{
		{"same host no port", secureExampleAPI, secureExampleHost, secureExampleOrigin, true},
		{"same host different port", examplePortAPI, examplePortHost, secureExampleOrigin, false},
		{"same host both ports", examplePortAPI, examplePortHost, testExamplePortOrigin, true},
		{"different host", secureExampleAPI, secureExampleHost, "https://evil.com", false},
		{"invalid origin URL", secureExampleAPI, secureExampleHost, "://bad-url", false},
		{"localhost exact match", localhost5173API, "localhost:5173", localhost5173Origin, true},
		{"localhost different port", localhost3000API, "localhost:3000", localhost5173Origin, false},
		{"localhost vs 127.0.0.1", loopback3000API, "127.0.0.1:3000", localhost5173Origin, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.url, nil)
			req.Host = tt.host
			scheme := "http"
			if strings.HasPrefix(tt.url, "https://") {
				scheme = "https"
			}
			result := isValidOrigin(req, tt.origin, scheme)
			if result != tt.expected {
				t.Errorf("isValidOrigin(host=%q, origin=%q) = %v, want %v",
					tt.host, tt.origin, result, tt.expected)
			}
		})
	}
}

func TestCSRFMiddleware_RejectsInvalidOrigin(t *testing.T) {
	const secureExampleHost = testExampleHost
	s := testServer(t)
	s.isDev = false
	handler := s.csrfMiddleware(ok200)

	req := httptest.NewRequest(http.MethodPost, testAPISomething, nil)
	req.Host = secureExampleHost
	req.Header.Set("Origin", "https://evil.com")
	req.AddCookie(&http.Cookie{Name: "veyport_csrf", Value: "tok123"})
	req.Header.Set(testCSRFTokenHdr, "tok123")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for cross-origin request, got %d", rr.Code)
	}
}

func TestCSRFMiddleware_AllowsMatchingOrigin(t *testing.T) {
	const (
		secureExampleOrigin = testExampleOrigin
		secureExampleHost   = testExampleHost
	)
	s := testServer(t)
	s.isDev = false
	handler := s.csrfMiddleware(ok200)

	req := httptest.NewRequest(http.MethodPost, secureExampleOrigin+"/api/something", nil)
	req.Host = secureExampleHost
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Origin", secureExampleOrigin)
	req.AddCookie(&http.Cookie{Name: "veyport_csrf", Value: "tok123"})
	req.Header.Set(testCSRFTokenHdr, "tok123")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf(testExpected200, rr.Code)
	}
}

func TestCSRFMiddleware_AllowsLoopbackHTTPOriginInProduction(t *testing.T) {
	const localhostOrigin = "http://localhost:8081"
	s := testServer(t)
	s.isDev = false
	handler := s.csrfMiddleware(ok200)

	req := httptest.NewRequest(http.MethodPost, localhostOrigin+"/api/something", nil)
	req.Host = "localhost:8081"
	req.Header.Set("Origin", localhostOrigin)
	req.AddCookie(&http.Cookie{Name: "veyport_csrf", Value: "tok123"})
	req.Header.Set(testCSRFTokenHdr, "tok123")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf(testExpected200, rr.Code)
	}
}

func TestCSRFMiddleware_RejectsMismatchedPortOrigin(t *testing.T) {
	const (
		secureExampleOrigin = testExampleOrigin
		examplePortHost     = testExamplePortHost
		examplePortAPI      = testExamplePortSSE
	)
	s := testServer(t)
	s.isDev = false
	handler := s.csrfMiddleware(ok200)

	req := httptest.NewRequest(http.MethodPost, examplePortAPI, nil)
	req.Host = examplePortHost
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Origin", secureExampleOrigin)
	req.AddCookie(&http.Cookie{Name: "veyport_csrf", Value: "tok123"})
	req.Header.Set(testCSRFTokenHdr, "tok123")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf(testExpected403, rr.Code)
	}
}

func TestCSRFMiddleware_AccessCookiePresent_RequiresCSRF(t *testing.T) {
	handler := testServer(t).csrfMiddleware(ok200)

	// Access cookie present but no CSRF cookie/header = should be blocked.
	req := httptest.NewRequest(http.MethodPost, testAPISomething, nil)
	req.AddCookie(&http.Cookie{Name: "veyport_access", Value: "some-token"})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf(testExpected403, rr.Code)
	}
}
