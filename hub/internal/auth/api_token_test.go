package auth_test

import (
	"testing"

	"github.com/wyiu/aerodocs/hub/internal/auth"
)

func TestGenerateAPIToken(t *testing.T) {
	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if !auth.LooksLikeAPIToken(raw) {
		t.Fatalf("expected api token prefix, got %q", raw)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if hash != auth.HashAPIToken(raw) {
		t.Fatal("hash mismatch")
	}
	if prefix == "" || len(prefix) > 16 {
		t.Fatalf("unexpected display prefix %q", prefix)
	}
}
