package grpcserver

import (
	"bytes"
	"strings"
	"testing"
)

func TestKEKSealOpen(t *testing.T) {
	h := &Handler{storageKey: "test-storage-key-0123456789"}
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	sealed, err := h.sealKEK(kek)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := h.openKEK(sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, kek) {
		t.Fatal("KEK round-trip mismatch")
	}
}

// TestSealKEK_NoStorageKey: h.storageKey="" → error "storageKey not configured"
func TestSealKEK_NoStorageKey(t *testing.T) {
	h := &Handler{storageKey: ""}
	kek := make([]byte, 32)
	_, err := h.sealKEK(kek)
	if err == nil {
		t.Fatal("expected error when storageKey is empty")
	}
	if !strings.Contains(err.Error(), "storageKey not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestOpenKEK_NoStorageKey: h.storageKey="" → error "storageKey not configured"
func TestOpenKEK_NoStorageKey(t *testing.T) {
	h := &Handler{storageKey: ""}
	_, err := h.openKEK("deadbeef")
	if err == nil {
		t.Fatal("expected error when storageKey is empty")
	}
	if !strings.Contains(err.Error(), "storageKey not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestOpenKEK_BadHex: valid storageKey but invalid hex input → decode error
func TestOpenKEK_BadHex(t *testing.T) {
	h := &Handler{storageKey: "test-storage-key-0123456789"}
	_, err := h.openKEK("not-valid-hex!!!")
	if err == nil {
		t.Fatal("expected error for invalid hex input")
	}
	if !strings.Contains(err.Error(), "decode KEK hex") {
		t.Fatalf("unexpected error: %v", err)
	}
}
