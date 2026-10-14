package server

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func applicationPortalRequest(t *testing.T, s *Server, endpoint, token, method, path string, body io.Reader) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, endpoint+path, body)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = s.applicationPortalHost()
	r.Header.Set("Authorization", testBearerPrefix+token)
	r.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func TestApplicationRoutingPreservesPortalTerminalStreaming(t *testing.T) {
	s, token, node := testServerWithAgent(t)
	s.applicationDomain = "apps.example.test"
	s.applicationPortalOrigin = "https://portal.example.test"
	gateway := httptest.NewServer(s.routes())
	defer gateway.Close()

	created := applicationPortalRequest(t, s, gateway.URL, token, http.MethodPost, testServersPrefix+node+testTerminalSessionsSuffix, strings.NewReader(`{"cols":80,"rows":24}`))
	if created.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(created.Body)
		t.Fatalf("terminal creation failed: %d %s", created.StatusCode, data)
	}
	var session struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(created.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	response := applicationPortalRequest(t, s, gateway.URL, token, http.MethodGet, testServersPrefix+node+testTerminalSessionsSuffix+"/"+session.SessionID+"/stream", nil)
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("terminal streaming unavailable: %d %s", response.StatusCode, response.Header.Get("Content-Type"))
	}
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "bW9jayQg") {
		t.Fatalf("live terminal output not flushed: %q %v", line, err)
	}
	if !s.terminalSessions.End(node, session.SessionID, 0, "") {
		t.Fatal("terminal end refused")
	}
	data, err := io.ReadAll(reader)
	if err != nil || !strings.Contains(string(data), "event: exit") {
		t.Fatalf("terminal exit not streamed: %s %v", data, err)
	}
}

func TestApplicationRoutingPreservesPortalLogStreaming(t *testing.T) {
	s, token, node := testServerWithAgentAndLog(t)
	s.applicationDomain = "apps.example.test"
	s.applicationPortalOrigin = "https://portal.example.test"
	gateway := httptest.NewServer(s.routes())
	defer gateway.Close()
	response := applicationPortalRequest(t, s, gateway.URL, token, http.MethodGet, testServersPrefix+node+testLogsTailQuery, nil)
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("log streaming unavailable: %d %s", response.StatusCode, response.Header.Get("Content-Type"))
	}
	data, err := io.ReadAll(response.Body)
	if err != nil || !strings.Contains(string(data), base64.StdEncoding.EncodeToString([]byte("2026-01-01 hello world\n"))) {
		t.Fatalf("log data not flushed: %s %v", data, err)
	}
}

func TestApplicationPortalAPIPreservesWriterAndHandlerPolicy(t *testing.T) {
	s := testServer(t)
	s.applicationDomain = "apps.example.test"
	s.applicationPortalOrigin = "https://portal.example.test"
	recorder := httptest.NewRecorder()
	portal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if w != recorder {
			t.Fatal("API response writer was replaced")
		}
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
	})
	s.applicationHostRouter(portal).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, s.applicationPortalOrigin+"/api/audit-logs/originals/synthetic", nil))
	if recorder.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("API's stronger referrer policy was overwritten")
	}
}

func TestApplicationPortalDocumentFlushPreservesHeadersAndErrors(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &applicationPortalDocumentWriter{ResponseWriter: recorder, launch: true}
	if err := writer.FlushError(); err != nil {
		t.Fatal(err)
	}
	if !recorder.Flushed || recorder.Header().Get("Referrer-Policy") != "strict-origin" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("document flush did not apply launch headers")
	}
	recorder = httptest.NewRecorder()
	recorder.Header().Set("Referrer-Policy", "no-referrer")
	writer = &applicationPortalDocumentWriter{ResponseWriter: recorder}
	writer.Flush()
	if recorder.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("stronger document policy was overwritten")
	}
	writer = &applicationPortalDocumentWriter{ResponseWriter: &applicationPortalPlainWriter{header: make(http.Header)}}
	if err := writer.FlushError(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("unsupported flush error lost: %v", err)
	}
}

type applicationPortalPlainWriter struct{ header http.Header }

func (w *applicationPortalPlainWriter) Header() http.Header       { return w.header }
func (*applicationPortalPlainWriter) WriteHeader(int)             {}
func (*applicationPortalPlainWriter) Write(b []byte) (int, error) { return len(b), nil }
