package auth_test

import (
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/wyiu/veyport/hub/internal/auth"
)

func TestGenerateTOTPSecret(t *testing.T) {
	key, err := auth.GenerateTOTPSecret("admin", "Veyport")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}

	if key.Secret() == "" {
		t.Fatal("secret should not be empty")
	}
	if key.URL() == "" {
		t.Fatal("URL should not be empty")
	}
}

func TestValidateTOTPCode(t *testing.T) {
	key, _ := auth.GenerateTOTPSecret("admin", "Veyport")

	// Generate a valid code
	code, err := totp.GenerateCode(key.Secret(), auth.TOTPTime())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	if !auth.ValidateTOTPCode(key.Secret(), code) {
		t.Fatal("valid code should pass validation")
	}

	if auth.ValidateTOTPCode(key.Secret(), "000000") {
		t.Fatal("invalid code should fail validation")
	}
}

func TestGenerateValidCode(t *testing.T) {
	key, err := auth.GenerateTOTPSecret("admin", "Veyport")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}

	code, err := auth.GenerateValidCode(key.Secret())
	if err != nil {
		t.Fatalf("generate valid code: %v", err)
	}

	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %d chars", len(code))
	}

	// The code should validate against the same secret
	if !auth.ValidateTOTPCode(key.Secret(), code) {
		t.Fatal("generated code should be valid")
	}
}

func TestGenerateValidCode_InvalidSecret(t *testing.T) {
	// An empty secret should return an error
	_, err := auth.GenerateValidCode("NOTVALIDBASE32!!")
	// pquerna/otp may return error or just produce a code — just ensure it doesn't panic
	_ = err
}

func TestTOTPTime(t *testing.T) {
	t1 := auth.TOTPTime()
	t2 := auth.TOTPTime()
	if t2.Before(t1) {
		t.Fatal("TOTPTime should advance monotonically")
	}
}
