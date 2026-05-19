package store_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/store"
)

const (
	testMemoryDB    = ":memory:"
	testCreateStore = "create store: %v"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStore, err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNew_InMemory(t *testing.T) {
	s, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	defer s.Close()

	if s.DB() == nil {
		t.Fatal("expected non-nil DB")
	}
}

func TestClose(t *testing.T) {
	s, err := store.New(testMemoryDB)
	if err != nil {
		t.Fatalf(testCreateStore, err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
}
