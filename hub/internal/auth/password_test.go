package auth_test

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

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
		{"exactly 11 bytes", "Aa1!" + strings.Repeat("x", 7), true},
		{"exactly 12 bytes", "Aa1!" + strings.Repeat("x", 8), false},
		{"exactly 256 bytes", "Aa1!" + strings.Repeat("x", 252), false},
		{"exactly 257 bytes", "Aa1!" + strings.Repeat("x", 253), true},
		{"unicode categories", "Ää１€" + strings.Repeat("x", 8), false},
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

func TestHashPasswordBcryptLengthBoundary(t *testing.T) {
	password := "Aa1!" + strings.Repeat("x", 68)
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil || cost < 12 {
		t.Fatalf("bcrypt cost = %d, error = %v", cost, err)
	}
	if !auth.ComparePassword(hash, password) {
		t.Fatal("72-byte password did not match")
	}
	hash, err = auth.HashPassword(password + "x")
	if !errors.Is(err, bcrypt.ErrPasswordTooLong) || hash != "" {
		t.Fatalf("73-byte hash = %q, error = %v", hash, err)
	}
	if auth.ComparePassword("invalid hash", password) {
		t.Fatal("invalid hash matched")
	}
}
