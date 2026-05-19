package auth_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/auth"
)

const testPassword = "MyP@ssw0rd!23" // NOSONAR — test fixture

func TestHashAndCompare(t *testing.T) {
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if !auth.ComparePassword(hash, testPassword) {
		t.Fatal("expected password to match")
	}

	if auth.ComparePassword(hash, "wrong-password") {
		t.Fatal("expected password to NOT match")
	}
}

func TestValidatePasswordPolicy(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{"valid", testPassword, false},
		{"too short", "Short!1a", true},
		{"no uppercase", "myp@ssw0rd!23", true},
		{"no lowercase", "MYP@SSW0RD!23", true},
		{"no digit", "MyP@ssword!AB", true},
		{"no special", "MyPassw0rd123", true},
		{"exactly 12 chars", "MyP@ssw0rd!2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.ValidatePasswordPolicy(tt.pw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePasswordPolicy(%q) = %v, wantErr = %v", tt.pw, err, tt.wantErr)
			}
		})
	}
}

func TestGenerateTemporaryPassword(t *testing.T) {
	pw := auth.GenerateTemporaryPassword()

	if len(pw) != 20 {
		t.Fatalf("expected 20 chars, got %d", len(pw))
	}

	if err := auth.ValidatePasswordPolicy(pw); err != nil {
		t.Fatalf("generated password should pass policy: %v", err)
	}
}
