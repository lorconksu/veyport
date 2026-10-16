package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestApplicationMappedRedirectCannotBecomeExternalAuthority(t *testing.T) {
	backend, _ := url.Parse("https://backend.example.test/base")
	app := &model.Application{PublicHostname: "native.apps.example.test"}
	for _, location := range []string{"/base//evil.test", "/base/%2fevil.test", "/base/%5cevil.test", "/base/%2f%5cevil.test", "/base/%00evil.test", "/base/%0devil.test", "/base/../outside", "/base/%2e%2e/outside", "https://backend.example.test/base//evil.test"} {
		t.Run(location, func(t *testing.T) {
			response := &http.Response{Header: make(http.Header)}
			response.Header.Set("Location", location)
			if err := rewriteApplicationResponse(response, app, backend); err == nil {
				t.Fatalf("unsafe mapped redirect accepted: %s", response.Header.Get("Location"))
			}
		})
	}
	for _, pair := range [][2]string{
		{"/base/login?next=https%3A%2F%2Fnative.example#section", "/login?next=https%3A%2F%2Fnative.example#section"},
		{"/base?empty=#section", "/?empty=#section"},
		{"https://backend.example.test/base/login#section", "https://native.apps.example.test/login#section"},
		{"https://identity.example.test/native#section", "https://identity.example.test/native#section"},
	} {
		response := &http.Response{Header: make(http.Header)}
		response.Header.Set("Location", pair[0])
		if err := rewriteApplicationResponse(response, app, backend); err != nil || response.Header.Get("Location") != pair[1] {
			t.Fatalf("native redirect semantics changed: %q %v", response.Header.Get("Location"), err)
		}
	}
}

func TestApplicationProxyRejectsUnsafeMappedRedirectBeforeBrowserFollows(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/base//evil.test")
		w.WriteHeader(http.StatusFound)
	}))
	defer backend.Close()
	s, app, cookie := applicationFixture(t, backend.URL+"/base")
	gateway := httptest.NewServer(s.routes())
	defer gateway.Close()
	r, err := http.NewRequest(http.MethodGet, gateway.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = app.PublicHostname
	r.AddCookie(&http.Cookie{Name: applicationCookie, Value: cookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || strings.TrimSpace(response.Header.Get("Location")) != "" {
		t.Fatalf("browser could follow unsafe mapped Location: %d %q", response.StatusCode, response.Header.Get("Location"))
	}
}
