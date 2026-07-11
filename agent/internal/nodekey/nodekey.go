// Package nodekey manages a durable Ed25519 node keypair for the agent.
// The private key is sealed under a KEK using AES-256-GCM (nonce prepended),
// providing clone protection: opening with the wrong KEK fails GCM authentication.
package nodekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// Generate creates a new Ed25519 keypair.
// It returns the private key (which embeds the public key), the base64-encoded
// public key, and any error.
func Generate() (ed25519.PrivateKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	return priv, pubB64, nil
}

// Seal encrypts the private key under kek using AES-256-GCM.
// The AES key is derived as sha256(kek). The returned hex string contains the
// nonce prepended to the ciphertext (mirroring the hub's auth.Encrypt shape).
func Seal(priv ed25519.PrivateKey, kek []byte) (string, error) {
	aesKey := sha256.Sum256(kek)

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends ciphertext+tag to nonce — resulting in nonce‖ct‖tag.
	ct := gcm.Seal(nonce, nonce, priv, nil)
	return hex.EncodeToString(ct), nil
}

// Open decrypts a ciphertext produced by Seal using kek.
// Returns an error if the KEK is wrong (GCM authentication failure) or if the
// ciphertext is malformed. This is the clone-protection property.
func Open(ciphertextHex string, kek []byte) (ed25519.PrivateKey, error) {
	ct, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}

	aesKey := sha256.Sum256(kek)

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ct) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ct[:nonceSize]
	plaintext, err := gcm.Open(nil, nonce, ct[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return ed25519.PrivateKey(plaintext), nil
}

// Sign signs challenge with priv and returns the signature bytes.
func Sign(priv ed25519.PrivateKey, challenge []byte) []byte {
	return ed25519.Sign(priv, challenge)
}

// DecodePub decodes a base64-encoded Ed25519 public key produced by Generate.
func DecodePub(pubB64 string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, fmt.Errorf("decode base64 public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// Fingerprint returns the Proxmox VM's product UUID from the DMI subsystem,
// trimmed of whitespace. Returns "" if the file is absent or unreadable
// (e.g., on non-Proxmox hosts or in test environments).
func Fingerprint() string {
	data, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
