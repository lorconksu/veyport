package grpcserver

import (
	"bytes"
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
