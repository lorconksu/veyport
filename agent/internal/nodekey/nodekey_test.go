package nodekey

import (
	"crypto/ed25519"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	priv, _, err := Generate()
	if err != nil { t.Fatalf("gen: %v", err) }
	kek := []byte("0123456789abcdef0123456789abcdef")
	ct, err := Seal(priv, kek)
	if err != nil { t.Fatalf("seal: %v", err) }
	got, err := Open(ct, kek)
	if err != nil { t.Fatalf("open: %v", err) }
	if !got.Equal(priv) { t.Fatal("round-trip key mismatch") }
}

func TestOpenWrongKEKFails(t *testing.T) {
	priv, _, _ := Generate()
	ct, _ := Seal(priv, []byte("0123456789abcdef0123456789abcdef"))
	if _, err := Open(ct, []byte("WRONGWRONGWRONGWRONGWRONGWRONGWR")); err == nil {
		t.Fatal("expected open to fail with wrong KEK (clone protection)")
	}
}

func TestSignVerify(t *testing.T) {
	priv, pubB64, _ := Generate()
	sig := Sign(priv, []byte("challenge"))
	pub, err := DecodePub(pubB64)
	if err != nil { t.Fatalf("decode pub: %v", err) }
	if !ed25519.Verify(pub, []byte("challenge"), sig) { t.Fatal("verify failed") }
}
