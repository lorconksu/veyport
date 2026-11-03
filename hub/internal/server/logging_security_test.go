package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoggingMiddleware_EscapesUntrustedRequestPath(t *testing.T) {
	s := testServer(t)
	handler := s.routes()
	var captured bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(previous) })

	for _, path := range []string{
		"/api/servers/server%0d%0aFORGED",
		"/api/servers/server%1b%5b2JFORGED",
	} {
		t.Run(path, func(t *testing.T) {
			captured.Reset()
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("expected routed request to require authentication, got %d", response.Code)
			}
			output := captured.String()
			if strings.Count(output, "\n") != 1 || strings.ContainsAny(output, "\r\x1b") {
				t.Fatalf("request path injected log control characters: %q", output)
			}
			if !strings.Contains(output, "FORGED") || !strings.Contains(output, "request_id=") {
				t.Fatalf("request evidence missing from log: %q", output)
			}
		})
	}
}
