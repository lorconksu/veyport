package userca

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Internal helpers whose failure modes cannot be provoked through the exported
// API, because the exported API always supplies a well-formed derived key.

// TestGenerateSignerRejectsAnUnusableEncryptionKey pins that a derived key of
// the wrong size fails the generation outright. The alternative — a key
// persisted unencrypted, or a signer returned without its at-rest form — would
// be far worse than a startup error.
func TestGenerateSignerRejectsAnUnusableEncryptionKey(t *testing.T) {
	for _, encKey := range [][]byte{nil, []byte("too-short"), make([]byte, 31)} {
		signer, encoded, err := generateSigner(encKey)
		if err == nil {
			t.Fatalf("generateSigner(%d-byte key) succeeded, want an error", len(encKey))
		}
		if signer != nil || encoded != "" {
			t.Errorf("generateSigner() returned signer=%v encoded=%q alongside an error", signer, encoded)
		}
	}
}

// TestGenerateSignerRoundTripsThroughDecodeSigner pins the at-rest encoding: a
// freshly generated key must be recoverable by the load path and no other.
func TestGenerateSignerRoundTripsThroughDecodeSigner(t *testing.T) {
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatalf("rand.Read() error: %v", err)
	}

	signer, encoded, err := generateSigner(encKey)
	if err != nil {
		t.Fatalf("generateSigner() error: %v", err)
	}

	reloaded, err := decodeSigner(encoded, encKey)
	if err != nil {
		t.Fatalf("decodeSigner() error: %v", err)
	}
	if ssh.FingerprintSHA256(reloaded.PublicKey()) != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Error("decodeSigner() recovered a different key than generateSigner() produced")
	}

	other := make([]byte, 32)
	if _, err := decodeSigner(encoded, other); err == nil {
		t.Error("decodeSigner() accepted the wrong encryption key")
	}
}

// unwillingSigner has a usable public key but refuses to sign. A signer only
// fails once its backing key material is broken, which a CA loaded from the
// store cannot reproduce.
type unwillingSigner struct{ ssh.Signer }

var errSigningUnavailable = errors.New("signing key is unavailable")

func (unwillingSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errSigningUnavailable
}

// TestSignUserCertReportsASigningFailure pins that a failed signature surfaces
// as an error rather than an unsigned certificate: a *ssh.Certificate whose
// Signature is nil would be returned as if it were issuable.
func TestSignUserCertReportsASigningFailure(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey() error: %v", err)
	}
	ca := &UserCA{signer: unwillingSigner{Signer: signer}}

	cert, err := ca.SignUserCert(signer.PublicKey(), "alice", time.Hour)
	if err == nil {
		t.Fatal("SignUserCert() returned a certificate the CA could not sign")
	}
	if cert != nil {
		t.Error("SignUserCert() returned a certificate alongside an error")
	}
	if !strings.Contains(err.Error(), "sign user cert") {
		t.Errorf("SignUserCert() error = %v, want it to name the operation", err)
	}
}

// TestRandomSerialIsNonZero pins the certificate serial contract: zero means
// "unset" in the SSH certificate format, so it must never be issued.
func TestRandomSerialIsNonZero(t *testing.T) {
	seen := make(map[uint64]struct{}, 32)
	for i := 0; i < 32; i++ {
		serial, err := randomSerial()
		if err != nil {
			t.Fatalf("randomSerial() error: %v", err)
		}
		if serial == 0 {
			t.Fatal("randomSerial() returned 0")
		}
		seen[serial] = struct{}{}
	}
	if len(seen) != 32 {
		t.Errorf("randomSerial() produced %d distinct values in 32 draws", len(seen))
	}
}

// TestAuthorizedKeyStringHasNoTrailingNewline pins the published form: the value
// is concatenated into authorized_keys files and config, where a stray newline
// would silently split the entry.
func TestAuthorizedKeyStringHasNoTrailingNewline(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey() error: %v", err)
	}

	line := authorizedKeyString(sshPub)
	if strings.ContainsAny(line, "\r\n") {
		t.Errorf("authorizedKeyString() = %q, want a single line", line)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Errorf("authorizedKeyString() = %q, want an ssh-ed25519 authorized_keys line", line)
	}
}
