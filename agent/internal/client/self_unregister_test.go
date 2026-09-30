package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type unregisterTransport func(*http.Request) (*http.Response, error)

func (f unregisterTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestSelfUnregisterTransport(t *testing.T) {
	for _, tc := range []struct {
		name, hub, scheme, host string
		insecure                bool
	}{
		{"hostname", "hub.example.com:9090", "https", "hub.example.com:443", false},
		{"ipv4", "192.0.2.1:9090", "https", "192.0.2.1:443", false},
		{"ipv6", "[2001:db8::1]:9090", "https", "[2001:db8::1]:443", false},
		{"bare hostname", "localhost", "https", "localhost:443", false},
		{"development", "127.0.0.1:9090", "http", "127.0.0.1:8081", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := http.DefaultClient
			t.Cleanup(func() { http.DefaultClient = previous })
			http.DefaultClient = &http.Client{Transport: unregisterTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme != tc.scheme || r.URL.Host != tc.host {
					t.Fatalf("unexpected endpoint: %s", r.URL)
				}
				if r.Method != http.MethodDelete || r.URL.Path != "/api/servers/srv-1/self-unregister" {
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
				}
				if r.Header.Get("X-Unregister-Token") != "unregister-secret" {
					t.Fatal("missing unregister credential")
				}
				return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: r}, nil
			})}
			c := &Client{hubAddr: tc.hub, serverID: "srv-1", unregisterToken: "unregister-secret", insecure: tc.insecure}
			if err := c.SelfUnregister(context.Background()); err != nil {
				t.Fatalf("SelfUnregister: %v", err)
			}
		})
	}
}

func TestSelfUnregisterRefusesRedirect(t *testing.T) {
	previous := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = previous })
	calls := 0
	http.DefaultClient = &http.Client{Transport: unregisterTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": {"http://hub.example.com:8081/redirect"}},
			Body:       io.NopCloser(strings.NewReader("")), Request: r,
		}, nil
	})}
	c := &Client{hubAddr: "hub.example.com:443", serverID: "srv-1", unregisterToken: "unregister-secret"}
	if err := c.SelfUnregister(context.Background()); err == nil {
		t.Fatal("expected redirect refusal")
	}
	if calls != 1 {
		t.Fatalf("credential forwarded to redirect target: %d requests", calls)
	}
}

func TestSelfUnregisterDoesNotFallBackAfterTLSFailure(t *testing.T) {
	previous := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = previous })
	wantErr := errors.New("untrusted certificate")
	calls := 0
	http.DefaultClient = &http.Client{Transport: unregisterTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" {
			t.Fatal("plaintext fallback after TLS failure")
		}
		return nil, wantErr
	})}
	c := &Client{hubAddr: "192.0.2.1:9090", serverID: "srv-1"}
	if err := c.SelfUnregister(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("expected original transport failure, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected one request, got %d", calls)
	}
}
