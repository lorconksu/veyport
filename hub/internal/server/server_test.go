package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/store"
)

func TestNew_CreatesServer(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	jwtSecret, err := InitJWTSecret(st)
	if err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}

	s := New(Config{
		Addr:      ":0",
		Store:     st,
		JWTSecret: jwtSecret,
		IsDev:     true,
	})

	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if s.store == nil {
		t.Fatal("expected non-nil store")
	}
	if s.jwtSecret != jwtSecret {
		t.Fatalf("expected jwtSecret '%s', got '%s'", jwtSecret, s.jwtSecret)
	}
	if s.httpServer.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("expected ReadHeaderTimeout 5s, got %s", s.httpServer.ReadHeaderTimeout)
	}
	if s.httpServer.MaxHeaderBytes != 1<<20 {
		t.Fatalf("expected MaxHeaderBytes %d, got %d", 1<<20, s.httpServer.MaxHeaderBytes)
	}
}

func TestInitJWTSecret_CreatesNew(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	secret, err := InitJWTSecret(st)
	if err != nil {
		t.Fatalf("init jwt secret: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
}

func TestInitJWTSecret_ReusesExisting(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	secret1, _ := InitJWTSecret(st)
	secret2, _ := InitJWTSecret(st)

	if secret1 != secret2 {
		t.Fatalf("expected same secret on second call, got different: '%s' vs '%s'", secret1, secret2)
	}
}

func TestSPAHandler_DevMode(t *testing.T) {
	s := testServer(t)

	handler := s.spaHandler()
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 in dev mode, got %d", rec.Code)
	}
}

func TestShutdown(t *testing.T) {
	st, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStoreErr, err)
	}
	defer st.Close()

	jwtSecret, _ := InitJWTSecret(st)
	s := New(Config{
		Addr:      ":0",
		Store:     st,
		JWTSecret: jwtSecret,
		IsDev:     true,
	})

	// Shutdown should succeed even without a running server (it just closes idle conns)
	ctx := context.Background()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}
