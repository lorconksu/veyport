package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const APITokenPrefix = "adt_"

func GenerateAPIToken() (raw, hash, displayPrefix string, err error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", "", fmt.Errorf("generate api token: %w", err)
	}

	raw = APITokenPrefix + hex.EncodeToString(secret)
	hash = HashAPIToken(raw)
	displayPrefix = raw
	if len(displayPrefix) > 16 {
		displayPrefix = displayPrefix[:16]
	}
	return raw, hash, displayPrefix, nil
}

func HashAPIToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func LooksLikeAPIToken(raw string) bool {
	return strings.HasPrefix(raw, APITokenPrefix)
}
