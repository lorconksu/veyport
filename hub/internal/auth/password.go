package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

func ComparePassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func ValidatePasswordPolicy(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	if len(password) > 256 {
		return fmt.Errorf("password must be at most 256 characters")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must include at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must include at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must include at least one digit")
	}
	if !hasSpecial {
		return fmt.Errorf("password must include at least one special character")
	}

	return nil
}

func GenerateTemporaryPassword() string {
	const (
		length  = 20
		upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower   = "abcdefghijklmnopqrstuvwxyz"
		digits  = "0123456789"
		special = "!@#$%^&*"
		all     = upper + lower + digits + special
	)

	// Guarantee at least one of each required type
	pw := make([]byte, length)
	pw[0] = randChar(upper)
	pw[1] = randChar(lower)
	pw[2] = randChar(digits)
	pw[3] = randChar(special)

	for i := 4; i < length; i++ {
		pw[i] = randChar(all)
	}

	// Shuffle
	for i := length - 1; i > 0; i-- {
		j := randInt(i + 1)
		pw[i], pw[j] = pw[j], pw[i]
	}

	return string(pw)
}

func randChar(charset string) byte {
	n := randInt(len(charset))
	return charset[n]
}

func randInt(upperBound int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(upperBound)))
	return int(n.Int64())
}
