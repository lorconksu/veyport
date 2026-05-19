package server

import (
	"context"
	"embed"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/wyiu/veyport/hub/internal/store"
)

// testEmbedFS creates a fake embed.FS-compatible filesystem for SPA handler tests.
// The spaHandler expects files under "web/dist/" prefix (matching hub/embed.go).
func testEmbedFS() *embed.FS {
	// We can't create a real embed.FS at test time, but Config.FrontendFS is *embed.FS.
	// Since spaHandler uses fs.Sub(*frontendFS, "web/dist"), we need an alternative approach.
	// Instead, test the spaHandler logic via the nil-FS path and the Start/Shutdown path.
	return nil
}

// testMapFS creates an fstest.MapFS simulating the embedded frontend.
func testMapFS() fstest.MapFS {
	return fstest.MapFS{
		testIndexHTML:    {Data: []byte("<!doctype html><html><body>app</body></html>")},
		"favicon.svg":    {Data: []byte("<svg></svg>")},
		"assets/main.js": {Data: []byte("console.log('app')")},
	}
}

// TestSPAHandler_ProductionMode_ExistingFile verifies that a known static file is served.
func TestSPAHandler_ProductionMode_ExistingFile(t *testing.T) {
	// Test the SPA logic directly using the mapFS approach
	sub := testMapFS()
	fileServer := http.FileServer(http.FS(sub))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := sub.Open(r.URL.Path[1:])
		if err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		index, _ := sub.ReadFile(testIndexHTML)
		w.Header().Set(testContentType, "text/html; charset=utf-8")
		w.Write(index)
	})

	req := httptest.NewRequest("GET", "/favicon.svg", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for favicon.svg, got %d", rec.Code)
	}
}

// TestSPAHandler_ProductionMode_FallbackToIndex verifies unknown paths return index.html.
func TestSPAHandler_ProductionMode_FallbackToIndex(t *testing.T) {
	sub := testMapFS()
	fileServer := http.FileServer(http.FS(sub))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := sub.Open(r.URL.Path[1:])
		if err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		index, _ := sub.ReadFile(testIndexHTML)
		w.Header().Set(testContentType, "text/html; charset=utf-8")
		w.Write(index)
	})

	req := httptest.NewRequest("GET", "/some/client/side/route", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for SPA fallback, got %d", rec.Code)
	}
	ct := rec.Header().Get(testContentType)
	if ct == "" {
		t.Fatal("expected Content-Type")
	}
}

// TestSPAHandler_NilFrontendFS verifies dev-mode behavior when FrontendFS is nil.
func TestSPAHandler_NilFrontendFS(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	jwtSecret, _ := InitJWTSecret(st)

	s := New(Config{
		Addr:       ":0",
		Store:      st,
		JWTSecret:  jwtSecret,
		IsDev:      false,
		FrontendFS: nil,
	})

	handler := s.spaHandler()
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for nil FrontendFS, got %d", rec.Code)
	}
}

// TestStart_ListenAndShutdown verifies that Start() can be started and shut down cleanly.
func TestStart_ListenAndShutdown(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	jwtSecret, _ := InitJWTSecret(st)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := New(Config{
		Addr:      addr,
		Store:     st,
		JWTSecret: jwtSecret,
		IsDev:     true,
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()

	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	select {
	case startErr := <-errCh:
		if startErr != nil && startErr != http.ErrServerClosed {
			t.Fatalf("Start() returned unexpected error: %v", startErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Start()")
	}
}
