package nodekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const kekTransportLabel = "veyport-kek-transport-v1"

// GenerateTransport generates a fresh X25519 transport keypair.
// Returns privBytes (32 bytes) and pubBytes (32 bytes).
func GenerateTransport() (privBytes, pubBytes []byte, err error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate X25519 key: %w", err)
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

// OpenKEK decrypts a sealed KEK produced by the hub's sealKEKToNode.
//
// transportPrivBytes is the node's 32-byte X25519 private key.
// ephemeralPubBytes is the hub's 32-byte ephemeral X25519 public key.
// encryptedKek is nonce (12 bytes) || ciphertext || GCM tag.
//
// Returns the 32-byte KEK or an error on decryption failure / bad inputs.
func OpenKEK(transportPrivBytes, ephemeralPubBytes, encryptedKek []byte) ([]byte, error) {
	if len(encryptedKek) < 12+1 {
		return nil, fmt.Errorf("encryptedKek too short: %d bytes", len(encryptedKek))
	}

	curve := ecdh.X25519()

	tPriv, err := curve.NewPrivateKey(transportPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("parse transport private key: %w", err)
	}
	tPub := tPriv.PublicKey().Bytes()

	ePub, err := curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	shared, err := tPriv.ECDH(ePub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// info = "veyport-kek-transport-v1" || ePub (32 bytes) || tPub (32 bytes)
	info := kekTransportLabel + string(ephemeralPubBytes) + string(tPub)

	key, err := hkdf.Key(sha256.New, shared, nil, info, 32)
	if err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}

	nonce := encryptedKek[:12]
	ct := encryptedKek[12:]

	kek, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM open: %w", err)
	}
	return kek, nil
}
