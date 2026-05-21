package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// cookieExpectation describes expected properties of a cookie for assertion.
type cookieExpectation struct {
	name     string
	value    string // empty means skip value check
	httpOnly bool
	sameSite http.SameSite
	path     string
	maxAge   int
	valueLen int // if >0, check Value length instead of exact value
}

// assertCookie verifies a cookie matches the expected properties.
func assertCookie(t *testing.T, cookies []*http.Cookie, exp cookieExpectation) {
	t.Helper()
	c := findCookie(cookies, exp.name)
	if c == nil {
		t.Fatalf("missing %s cookie", exp.name)
	}
	if exp.value != "" && c.Value != exp.value {
		t.Errorf("%s value = %q, want %q", exp.name, c.Value, exp.value)
	}
	if exp.valueLen > 0 && len(c.Value) != exp.valueLen {
		t.Errorf("%s token length = %d, want %d", exp.name, len(c.Value), exp.valueLen)
	}
	if c.HttpOnly != exp.httpOnly {
		t.Errorf("%s HttpOnly = %v, want %v", exp.name, c.HttpOnly, exp.httpOnly)
	}
	if exp.sameSite != 0 && c.SameSite != exp.sameSite {
		t.Errorf("%s SameSite = %v, want %v", exp.name, c.SameSite, exp.sameSite)
	}
	if exp.path != "" && c.Path != exp.path {
		t.Errorf("%s path = %q, want %q", exp.name, c.Path, exp.path)
	}
	if c.MaxAge != exp.maxAge {
		t.Errorf("%s MaxAge = %d, want %d", exp.name, c.MaxAge, exp.maxAge)
	}
}

func TestSetAuthCookies(t *testing.T) {
	w := httptest.NewRecorder()
	setAuthCookies(w, "access123", "refresh456")

	cookies := w.Result().Cookies()
	if len(cookies) != 3 {
		t.Fatalf("expected 3 cookies, got %d", len(cookies))
	}

	assertCookie(t, cookies, cookieExpectation{
		name: cookieAccess, value: "access123", httpOnly: true,
		sameSite: http.SameSiteStrictMode, path: "/", maxAge: 900,
	})
	assertCookie(t, cookies, cookieExpectation{
		name: cookieRefresh, value: "refresh456", httpOnly: true,
		path: testRefreshPath, maxAge: 604800,
	})
	assertCookie(t, cookies, cookieExpectation{
		name: cookieCSRF, httpOnly: false,
		sameSite: http.SameSiteStrictMode, maxAge: 604800, valueLen: 64,
	})
}

func TestClearAuthCookies(t *testing.T) {
	w := httptest.NewRecorder()
	clearAuthCookies(w)

	cookies := w.Result().Cookies()
	// 3 current cookies + 3 legacy v1.x cookies cleared in the same response.
	if len(cookies) != 6 {
		t.Fatalf("expected 6 cookies, got %d", len(cookies))
	}

	for _, c := range cookies {
		if c.MaxAge != -1 {
			t.Errorf("cookie %q MaxAge = %d, want -1", c.Name, c.MaxAge)
		}
	}

	// Each cookie name we expect to clear should be present exactly once.
	expectedNames := []string{
		cookieAccess, cookieRefresh, cookieCSRF,
		legacyCookieAccess, legacyCookieRefresh, legacyCookieCSRF,
	}
	for _, name := range expectedNames {
		if findCookie(cookies, name) == nil {
			t.Errorf("missing %s cookie in clear response", name)
		}
	}
}

func TestReadAccessToken_FromCookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieAccess, Value: testFromCookie})

	got := readAccessToken(r)
	if got != testFromCookie {
		t.Errorf("readAccessToken = %q, want %q", got, testFromCookie)
	}
}

func TestReadAccessToken_FallbackToBearer(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer from-header")

	got := readAccessToken(r)
	if got != "from-header" {
		t.Errorf("readAccessToken = %q, want %q", got, "from-header")
	}
}

func TestReadAccessToken_CookiePriority(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieAccess, Value: testFromCookie})
	r.Header.Set("Authorization", "Bearer from-header")

	got := readAccessToken(r)
	if got != testFromCookie {
		t.Errorf("readAccessToken = %q, want %q (cookie should take priority)", got, testFromCookie)
	}
}

func TestIsUsingBearerAuth(t *testing.T) {
	t.Run("with bearer header", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer some-token")
		if !isUsingBearerAuth(r) {
			t.Error("expected true with Bearer header")
		}
	})

	t.Run("without bearer header", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		if isUsingBearerAuth(r) {
			t.Error("expected false without Bearer header")
		}
	})

	t.Run("with non-bearer auth", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Basic abc123")
		if isUsingBearerAuth(r) {
			t.Error("expected false with Basic auth header")
		}
	})
}
