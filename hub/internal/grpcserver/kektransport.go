package grpcserver

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

const kekTransportLabel = "veyport-kek-transport-v1"

// sealKEKToNode encrypts kek for the node identified by transportPubBytes (32-byte X25519 public key).
// Returns ephemeralPub (32 bytes) and encryptedKek (12-byte nonce || ciphertext || GCM tag).
func sealKEKToNode(transportPubBytes, kek []byte) (ephemeralPub, encryptedKek []byte, err error) {
	curve := ecdh.X25519()
	ePriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	return sealKEKToNodeCore(transportPubBytes, kek, ePriv.Bytes(), nonce)
}

// sealKEKToNodeCore is the deterministic core of sealKEKToNode, exposed for testing.
// ephemeralPrivBytes is the 32-byte X25519 private key scalar.
// nonce must be exactly 12 bytes.
func sealKEKToNodeCore(transportPubBytes, kek, ephemeralPrivBytes, nonce []byte) (ephemeralPub, encryptedKek []byte, err error) {
	if len(nonce) != 12 {
		return nil, nil, fmt.Errorf("nonce must be 12 bytes, got %d", len(nonce))
	}

	curve := ecdh.X25519()

	ePriv, err := curve.NewPrivateKey(ephemeralPrivBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ephemeral private key: %w", err)
	}
	ePubBytes := ePriv.PublicKey().Bytes()

	tPub, err := curve.NewPublicKey(transportPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse transport public key: %w", err)
	}

	shared, err := ePriv.ECDH(tPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}

	// info = "veyport-kek-transport-v1" || ePub (32 bytes) || tPub (32 bytes)
	info := kekTransportLabel + string(ePubBytes) + string(transportPubBytes)

	key, err := hkdf.Key(sha256.New, shared, nil, info, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("HKDF: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("GCM: %w", err)
	}

	// Seal appends: nonce || ciphertext || tag
	sealed := gcm.Seal(nonce, nonce, kek, nil)

	return ePubBytes, sealed, nil
}
