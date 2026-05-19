package store_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/store"
)

// TestNew_InvalidPath verifies that opening a DB at an unwritable path returns an error.
func TestNew_InvalidPath(t *testing.T) {
	// /dev/null/noexist is an invalid path — the parent is /dev/null (not a dir)
	_, err := store.New("/dev/null/nope/veyport.db")
	if err == nil {
		t.Fatal("expected error for invalid DB path")
	}
}

// TestNew_MigrationFailure verifies that migrations run on a fresh in-memory DB without error.
func TestNew_Success(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	defer s.Close()

	if s.DB() == nil {
		t.Fatal("expected non-nil DB after successful open")
	}
}

// TestNew_DiskDB verifies that opening a disk-based DB (temp file) works.
func TestNew_DiskDB(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/disk.db"

	s, err := store.New(path)
	if err != nil {
		t.Fatalf("expected success for temp db, got: %v", err)
	}
	defer s.Close()

	if s.DB() == nil {
		t.Fatal("expected non-nil DB")
	}
}
