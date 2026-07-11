package grpcserver

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// Known-Answer Vector (KAT) — shared verbatim with agent/internal/nodekey/transport_test.go.
// These constants pin the sealed-box construction byte-for-byte; any divergence
// between the hub and agent implementations causes one of the KAT assertions to fail.
const (
	katTransportPrivHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	katTransportPubHex  = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
	katEphemeralPrivHex = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	katEphemeralPubHex  = "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b"
	katKEKHex           = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"
	katNonceHex         = "0102030405060708090a0b0c"
	katEncryptedKEKHex  = "0102030405060708090a0b0c5f451aec84ee7397921e38e178386ebe3d70cdc053230e6d1bba780e527eb1e4cee04ad259ca65699ecb7818da9837c4"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// openKEKInline mirrors agent/internal/nodekey.OpenKEK byte-for-byte.
// Used for hub-side round-trip tests without importing the agent package
// (cross-module internal import is not permitted).
func openKEKInline(transportPrivBytes, ephemeralPubBytes, encryptedKek []byte) ([]byte, error) {
	if len(encryptedKek) < 12+1 {
		return nil, fmt.Errorf("encryptedKek too short: %d bytes", len(encryptedKek))
	}

	curve := ecdh.X25519()

	tPriv, err := curve.NewPrivateKey(transportPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("parse transport private key: %w", err)
	}
	tPubBytes := tPriv.PublicKey().Bytes()

	ePub, err := curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	shared, err := tPriv.ECDH(ePub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// info = "veyport-kek-transport-v1" || ePub (32 bytes) || tPub (32 bytes)
	info := kekTransportLabel + string(ephemeralPubBytes) + string(tPubBytes)

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

// TestSealKEKToNodeCore_KAT verifies that sealKEKToNodeCore with fixed inputs produces
// the exact (ephemeralPub, encryptedKek) constants shared with the agent-side KAT.
func TestSealKEKToNodeCore_KAT(t *testing.T) {
	transportPub  := mustDecodeHex(t, katTransportPubHex)
	ephemeralPriv := mustDecodeHex(t, katEphemeralPrivHex)
	kek           := mustDecodeHex(t, katKEKHex)
	nonce         := mustDecodeHex(t, katNonceHex)

	wantEphemeralPub := mustDecodeHex(t, katEphemeralPubHex)
	wantEncryptedKEK := mustDecodeHex(t, katEncryptedKEKHex)

	gotEphPub, gotEncKEK, err := sealKEKToNodeCore(transportPub, kek, ephemeralPriv, nonce)
	if err != nil {
		t.Fatalf("sealKEKToNodeCore KAT: %v", err)
	}
	if !bytes.Equal(gotEphPub, wantEphemeralPub) {
		t.Fatalf("KAT ephemeralPub mismatch:\n  got  %x\n  want %x", gotEphPub, wantEphemeralPub)
	}
	if !bytes.Equal(gotEncKEK, wantEncryptedKEK) {
		t.Fatalf("KAT encryptedKek mismatch:\n  got  %x\n  want %x", gotEncKEK, wantEncryptedKEK)
	}
}

// TestSealKEKToNode_RoundTrip verifies sealKEKToNode (random ephemeral+nonce) produces
// output that openKEKInline (the agent mirror) can decrypt to recover the original KEK.
func TestSealKEKToNode_RoundTrip(t *testing.T) {
	transportPriv := mustDecodeHex(t, katTransportPrivHex)
	transportPub  := mustDecodeHex(t, katTransportPubHex)
	kek           := mustDecodeHex(t, katKEKHex)

	ephPub, encKEK, err := sealKEKToNode(transportPub, kek)
	if err != nil {
		t.Fatalf("sealKEKToNode: %v", err)
	}

	got, err := openKEKInline(transportPriv, ephPub, encKEK)
	if err != nil {
		t.Fatalf("openKEKInline: %v", err)
	}
	if !bytes.Equal(got, kek) {
		t.Fatalf("round-trip KEK mismatch: got %x, want %x", got, kek)
	}
}

// TestSealKEKToNode_WrongKeyFails verifies that decryption with the wrong transport
// private key fails (GCM authentication rejects it).
func TestSealKEKToNode_WrongKeyFails(t *testing.T) {
	transportPub := mustDecodeHex(t, katTransportPubHex)
	kek          := mustDecodeHex(t, katKEKHex)

	ephPub, encKEK, err := sealKEKToNode(transportPub, kek)
	if err != nil {
		t.Fatalf("sealKEKToNode: %v", err)
	}

	// A different private key (won't correspond to the transport pub used for sealing).
	wrongPriv := mustDecodeHex(t, "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")

	_, err = openKEKInline(wrongPriv, ephPub, encKEK)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong transport key (GCM auth failure)")
	}
}
