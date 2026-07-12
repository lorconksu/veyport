package grpcserver

import (
	"encoding/hex"
	"fmt"

	"github.com/wyiu/veyport/hub/internal/auth"
)

// sealKEK encrypts the given KEK bytes using the handler's storage key and returns
// a hex-encoded ciphertext string suitable for storage.
func (h *Handler) sealKEK(kek []byte) (string, error) {
	if h.storageKey == "" {
		return "", fmt.Errorf("storageKey not configured")
	}
	enc, err := auth.Encrypt(kek, auth.DeriveKey(h.storageKey))
	if err != nil {
		return "", fmt.Errorf("encrypt KEK: %w", err)
	}
	return hex.EncodeToString(enc), nil
}

// openKEK decrypts a hex-encoded KEK ciphertext produced by sealKEK and returns
// the raw KEK bytes.
func (h *Handler) openKEK(hexStr string) ([]byte, error) {
	if h.storageKey == "" {
		return nil, fmt.Errorf("storageKey not configured")
	}
	enc, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode KEK hex: %w", err)
	}
	kek, err := auth.Decrypt(enc, auth.DeriveKey(h.storageKey))
	if err != nil {
		return nil, fmt.Errorf("decrypt KEK: %w", err)
	}
	return kek, nil
}
