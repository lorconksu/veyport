package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	key := DeriveKey("test-secret")
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
	// Same input produces same output
	key2 := DeriveKey("test-secret")
	if !bytes.Equal(key, key2) {
		t.Error("DeriveKey should be deterministic")
	}
	// Different input produces different output
	key3 := DeriveKey("other-secret")
	if bytes.Equal(key, key3) {
		t.Error("different secrets should produce different keys")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := DeriveKey("my-jwt-secret")
	plaintext := []byte("hello world sensitive data")

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted %q != original %q", decrypted, plaintext)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := DeriveKey("secret-1")
	key2 := DeriveKey("secret-2")

	ciphertext, err := Encrypt([]byte("data"), key1)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	_, err = Decrypt(ciphertext, key2)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := DeriveKey("secret")
	_, err := Decrypt([]byte("short"), key)
	if err == nil {
		t.Error("Decrypt with too-short ciphertext should fail")
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := DeriveKey("secret")
	plaintext := []byte("same data")

	ct1, _ := Encrypt(plaintext, key)
	ct2, _ := Encrypt(plaintext, key)

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of the same data should produce different ciphertexts (random nonce)")
	}
}

func TestEncryptionInvalidKeyLengths(t *testing.T) {
	for _, size := range []int{0, 1, 15, 17, 23, 25, 31, 33} {
		key := make([]byte, size)
		if output, err := Encrypt([]byte("secret"), key); err == nil || output != nil {
			t.Errorf("Encrypt key length %d: output = %x, error = %v", size, output, err)
		}
		if output, err := Decrypt(make([]byte, 32), key); err == nil || output != nil {
			t.Errorf("Decrypt key length %d: output = %x, error = %v", size, output, err)
		}
	}
}

func TestEncryptionAuthenticatedEnvelope(t *testing.T) {
	key := DeriveKey("storage-secret")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range [][]byte{nil, {}, []byte("secret payload")} {
		encrypted, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatal(err)
		}
		if len(encrypted) != gcm.NonceSize()+len(plaintext)+gcm.Overhead() {
			t.Fatalf("unexpected envelope length %d", len(encrypted))
		}
		decrypted, err := Decrypt(encrypted, key)
		if err != nil || !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("round trip = %x, %v", decrypted, err)
		}
		for _, offset := range []int{0, len(encrypted) - 1} {
			tampered := bytes.Clone(encrypted)
			tampered[offset] ^= 1
			if output, err := Decrypt(tampered, key); err == nil || output != nil {
				t.Fatalf("tampered offset %d accepted", offset)
			}
		}
		for _, size := range []int{0, gcm.NonceSize() - 1, gcm.NonceSize(), len(encrypted) - 1} {
			if output, err := Decrypt(encrypted[:size], key); err == nil || output != nil {
				t.Fatalf("truncated envelope length %d accepted", size)
			}
		}
	}
}

type failingNonceReader struct{}

func (failingNonceReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestEncryptNonceReadFailure(t *testing.T) {
	// Encrypt reads the nonce explicitly through io.ReadFull. No tests in this
	// package run in parallel; restore the process-global reader before returning.
	original := rand.Reader
	rand.Reader = failingNonceReader{}
	t.Cleanup(func() { rand.Reader = original })
	output, err := Encrypt([]byte("secret"), DeriveKey("storage-secret"))
	if !errors.Is(err, io.ErrUnexpectedEOF) || output != nil {
		t.Fatalf("nonce failure: output = %x, error = %v", output, err)
	}
}

func TestEncryptionRejectsFIPSOnlyMode(t *testing.T) {
	if os.Getenv("VEYPORT_TEST_FIPS_ONLY") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(executable, "-test.run=^TestEncryptionRejectsFIPSOnlyMode$")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only", "VEYPORT_TEST_FIPS_ONLY=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("FIPS-only subprocess: %v: %s", err, output)
		}
		return
	}
	key := DeriveKey("storage-secret")
	if output, err := Encrypt([]byte("secret"), key); err == nil || output != nil || !strings.Contains(err.Error(), "FIPS 140-only") {
		t.Fatalf("FIPS Encrypt = %x, %v", output, err)
	}
	if output, err := Decrypt(make([]byte, 32), key); err == nil || output != nil || !strings.Contains(err.Error(), "FIPS 140-only") {
		t.Fatalf("FIPS Decrypt = %x, %v", output, err)
	}
}
