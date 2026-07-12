package nodekey

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Known-Answer Vector (KAT) — shared verbatim with hub/internal/grpcserver/kektransport_test.go.
// These constants pin the sealed-box construction byte-for-byte; any divergence
// between the agent and hub implementations causes one of the KAT assertions to fail.
const (
	katTransportPrivHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	katTransportPubHex  = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
	katEphemeralPubHex  = "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b"
	katKEKHex           = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"
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

// TestOpenKEK_KAT is the Known-Answer Test: OpenKEK must decrypt the fixed ciphertext
// produced by the hub's sealKEKToNodeCore with the same fixed inputs.
func TestOpenKEK_KAT(t *testing.T) {
	transportPriv := mustDecodeHex(t, katTransportPrivHex)
	ephemeralPub  := mustDecodeHex(t, katEphemeralPubHex)
	encryptedKEK  := mustDecodeHex(t, katEncryptedKEKHex)
	wantKEK       := mustDecodeHex(t, katKEKHex)

	got, err := OpenKEK(transportPriv, ephemeralPub, encryptedKEK)
	if err != nil {
		t.Fatalf("OpenKEK KAT: %v", err)
	}
	if !bytes.Equal(got, wantKEK) {
		t.Fatalf("OpenKEK KAT: got %x, want %x", got, wantKEK)
	}
}

// TestOpenKEK_WrongKeyFails verifies that GCM authentication rejects decryption
// with the wrong transport private key (clone-protection property).
func TestOpenKEK_WrongKeyFails(t *testing.T) {
	ephemeralPub := mustDecodeHex(t, katEphemeralPubHex)
	encryptedKEK := mustDecodeHex(t, katEncryptedKEKHex)

	// A different 32-byte private key (not the one used for sealing).
	wrongPrivHex := "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"
	wrongPriv    := mustDecodeHex(t, wrongPrivHex)

	_, err := OpenKEK(wrongPriv, ephemeralPub, encryptedKEK)
	if err == nil {
		t.Fatal("OpenKEK should have failed with wrong transport key (GCM auth failure expected)")
	}
}

// TestGenerateTransport_RoundTrip generates a fresh transport keypair, uses an inline
// seal (mirroring the hub's sealKEKToNodeCore logic) and verifies OpenKEK recovers the KEK.
func TestGenerateTransport_RoundTrip(t *testing.T) {
	privBytes, pubBytes, err := GenerateTransport()
	if err != nil {
		t.Fatalf("GenerateTransport: %v", err)
	}
	if len(privBytes) != 32 {
		t.Fatalf("privBytes len: got %d, want 32", len(privBytes))
	}
	if len(pubBytes) != 32 {
		t.Fatalf("pubBytes len: got %d, want 32", len(pubBytes))
	}

	// Inline seal (mirrors hub sealKEKToNodeCore).
	kek := []byte("test-kek-32-bytes-padddddddddddd")
	ephemeralPub, encryptedKEK := inlineSeal(t, pubBytes, kek)

	got, err := OpenKEK(privBytes, ephemeralPub, encryptedKEK)
	if err != nil {
		t.Fatalf("OpenKEK round-trip: %v", err)
	}
	if !bytes.Equal(got, kek) {
		t.Fatalf("round-trip KEK mismatch: got %x, want %x", got, kek)
	}
}

// TestOpenKEK_TooShort exercises the encryptedKek length guard.
func TestOpenKEK_TooShort(t *testing.T) {
	priv := mustDecodeHex(t, katTransportPrivHex)
	ePub := mustDecodeHex(t, katEphemeralPubHex)

	// Only 12 bytes — the guard requires > 12 bytes (nonce + at least 1 byte payload).
	short := make([]byte, 12)
	_, err := OpenKEK(priv, ePub, short)
	if err == nil {
		t.Fatal("expected error for encryptedKek that is too short")
	}
}

// TestOpenKEK_BadPrivateKey exercises the NewPrivateKey error branch.
// X25519 private keys must be exactly 32 bytes.
func TestOpenKEK_BadPrivateKey(t *testing.T) {
	ePub := mustDecodeHex(t, katEphemeralPubHex)
	encKEK := mustDecodeHex(t, katEncryptedKEKHex)

	badPriv := []byte("tooshort") // not 32 bytes
	_, err := OpenKEK(badPriv, ePub, encKEK)
	if err == nil {
		t.Fatal("expected error for bad transport private key (wrong length)")
	}
}

// TestOpenKEK_BadEphemeralPub exercises the NewPublicKey error branch.
// X25519 public keys must be exactly 32 bytes.
func TestOpenKEK_BadEphemeralPub(t *testing.T) {
	priv := mustDecodeHex(t, katTransportPrivHex)
	encKEK := mustDecodeHex(t, katEncryptedKEKHex)

	badPub := []byte("tooshort") // not 32 bytes
	_, err := OpenKEK(priv, badPub, encKEK)
	if err == nil {
		t.Fatal("expected error for bad ephemeral public key (wrong length)")
	}
}

// TestOpenKEK_LowOrderEphemeralPub exercises the ECDH error branch.
// The all-zeros public key is a low-order point that X25519 ECDH explicitly rejects.
func TestOpenKEK_LowOrderEphemeralPub(t *testing.T) {
	priv := mustDecodeHex(t, katTransportPrivHex)
	encKEK := mustDecodeHex(t, katEncryptedKEKHex)

	// All-zero public key is a low-order point; X25519 ECDH rejects it.
	zeroPub := make([]byte, 32)

	_, err := OpenKEK(priv, zeroPub, encKEK)
	if err == nil {
		t.Fatal("expected ECDH error for low-order (zero) ephemeral public key")
	}
}

// TestOpenKEK_TamperedCiphertext exercises the GCM open failure branch.
func TestOpenKEK_TamperedCiphertext(t *testing.T) {
	privBytes, pubBytes, err := GenerateTransport()
	if err != nil {
		t.Fatalf("GenerateTransport: %v", err)
	}

	kek := []byte("test-kek-32-bytes-padddddddddddd")
	ephemeralPub, encryptedKEK := inlineSeal(t, pubBytes, kek)

	// Tamper with the ciphertext (flip last byte to break GCM auth tag).
	tampered := make([]byte, len(encryptedKEK))
	copy(tampered, encryptedKEK)
	tampered[len(tampered)-1] ^= 0xff

	_, err = OpenKEK(privBytes, ephemeralPub, tampered)
	if err == nil {
		t.Fatal("expected GCM decryption error for tampered ciphertext")
	}
}

// inlineSeal is a minimal copy of the hub's seal logic for round-trip testing.
// It must remain byte-for-byte identical to sealKEKToNodeCore.
func inlineSeal(t *testing.T, transportPubBytes, kek []byte) (ephemeralPub, encryptedKek []byte) {
	t.Helper()

	curve := ecdh.X25519()
	ePriv, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}
	ePubBytes := ePriv.PublicKey().Bytes()

	tPub, err := curve.NewPublicKey(transportPubBytes)
	if err != nil {
		t.Fatalf("parse transport pub: %v", err)
	}

	shared, err := ePriv.ECDH(tPub)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	info := kekTransportLabel + string(ePubBytes) + string(transportPubBytes)
	key, err := hkdf.Key(sha256.New, shared, nil, info, 32)
	if err != nil {
		t.Fatalf("HKDF: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("AES: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("GCM: %v", err)
	}

	nonce := make([]byte, 12)
	// Use a fixed nonce for test determinism; rand is fine too — just need 12 bytes.
	// Here we re-derive from block (anything deterministic for the test).
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	sealed := gcm.Seal(nonce, nonce, kek, nil)
	return ePubBytes, sealed
}
