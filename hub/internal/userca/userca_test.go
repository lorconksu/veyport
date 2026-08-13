package userca_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
)

const (
	testStorageKey    = "test-storage-key-0123456789"
	testPrincipal     = "alice"
	testInitUserCAFmt = "InitUserCA() error: %v"
	testInitHostFmt   = "InitHostKey() error: %v"
	testSignCertFmt   = "SignUserCert() error: %v"
	testNewStoreFmt   = "store.New() error: %v"
	testGenKeyFmt     = "GenerateKey() error: %v"
	keyUserCAKey      = "ssh_user_ca_key"
	keyUserCAPub      = "ssh_user_ca_pub"
	keyHostKey        = "ssh_host_key"
)

// fakeConn is the minimal ssh.ConnMetadata CertChecker.Authenticate needs.
type fakeConn struct{ user string }

func (c fakeConn) User() string          { return c.user }
func (c fakeConn) SessionID() []byte     { return []byte("session") }
func (c fakeConn) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (c fakeConn) ServerVersion() []byte { return []byte("SSH-2.0-veyport") }
func (c fakeConn) RemoteAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222} }
func (c fakeConn) LocalAddr() net.Addr   { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22} }

// authenticate runs the exact path the gateway's PublicKeyCallback uses.
// ssh.CertChecker.CheckCert alone is NOT sufficient: it verifies the signature
// against the certificate's own embedded SignatureKey and never consults
// IsUserAuthority, so a cert from any CA passes it. Authenticate is what
// enforces the trust root.
func authenticate(ca *userca.UserCA, user string, cert *ssh.Certificate) error {
	checker := &ssh.CertChecker{IsUserAuthority: ca.IsUserAuthority}
	_, err := checker.Authenticate(fakeConn{user: user}, cert)
	return err
}

// newStore returns a fresh in-memory store.
func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf(testNewStoreFmt, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// newClientKey returns a throwaway Ed25519 SSH public key standing in for a
// client's key being presented for certification.
func newClientKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(testGenKeyFmt, err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey() error: %v", err)
	}
	return sshPub
}

func newUserCA(t *testing.T) *userca.UserCA {
	t.Helper()
	ca, err := userca.InitUserCA(newStore(t), testStorageKey)
	if err != nil {
		t.Fatalf(testInitUserCAFmt, err)
	}
	return ca
}

func TestSignUserCertVerifiesAgainstIssuingCA(t *testing.T) {
	ca := newUserCA(t)
	clientPub := newClientKey(t)

	cert, err := ca.SignUserCert(clientPub, testPrincipal, time.Hour)
	if err != nil {
		t.Fatalf(testSignCertFmt, err)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want %d (UserCert)", cert.CertType, ssh.UserCert)
	}
	if cert.KeyId != testPrincipal {
		t.Errorf("KeyId = %q, want %q", cert.KeyId, testPrincipal)
	}
	if cert.Serial == 0 {
		t.Error("Serial = 0, want a random non-zero serial")
	}
	if len(cert.CriticalOptions) != 0 {
		t.Errorf("CriticalOptions = %v, want none", cert.CriticalOptions)
	}

	if err := authenticate(ca, testPrincipal, cert); err != nil {
		t.Fatalf("Authenticate() rejected a cert from its own CA: %v", err)
	}
}

// TestCertFromDifferentCARejected is the trust-root confusion guard: a cert
// signed by another CA must never validate against this one.
func TestCertFromDifferentCARejected(t *testing.T) {
	trusted := newUserCA(t)
	rogue := newUserCA(t)
	clientPub := newClientKey(t)

	if string(trusted.PublicKey().Marshal()) == string(rogue.PublicKey().Marshal()) {
		t.Fatal("two independently initialized CAs share a public key")
	}

	cert, err := rogue.SignUserCert(clientPub, testPrincipal, time.Hour)
	if err != nil {
		t.Fatalf(testSignCertFmt, err)
	}

	if err := authenticate(trusted, testPrincipal, cert); err == nil {
		t.Fatal("Authenticate() accepted a cert signed by a different CA")
	}

	// A bare (uncertified) public key must never authenticate either.
	checker := &ssh.CertChecker{IsUserAuthority: trusted.IsUserAuthority}
	if _, err := checker.Authenticate(fakeConn{user: testPrincipal}, clientPub); err == nil {
		t.Error("Authenticate() accepted a bare public key with no certificate")
	}

	if trusted.IsUserAuthority(rogue.PublicKey()) {
		t.Error("IsUserAuthority() accepted a foreign CA key")
	}
	if !trusted.IsUserAuthority(trusted.PublicKey()) {
		t.Error("IsUserAuthority() rejected its own CA key")
	}
}

func TestSignUserCertTTLAndSolePrincipal(t *testing.T) {
	ca := newUserCA(t)
	clientPub := newClientKey(t)

	const ttl = 90 * time.Second
	before := time.Now()
	cert, err := ca.SignUserCert(clientPub, testPrincipal, ttl)
	if err != nil {
		t.Fatalf(testSignCertFmt, err)
	}
	after := time.Now()

	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != testPrincipal {
		t.Fatalf("ValidPrincipals = %v, want exactly [%q]", cert.ValidPrincipals, testPrincipal)
	}

	wantLo := uint64(before.Add(ttl).Unix())
	wantHi := uint64(after.Add(ttl).Unix()) + 2
	if cert.ValidBefore < wantLo || cert.ValidBefore > wantHi {
		t.Errorf("ValidBefore = %d, want within [%d,%d] (now+ttl)", cert.ValidBefore, wantLo, wantHi)
	}
	// ValidAfter is backdated by a small clock skew allowance.
	if cert.ValidAfter >= uint64(before.Unix()) {
		t.Errorf("ValidAfter = %d, want backdated below %d", cert.ValidAfter, uint64(before.Unix()))
	}
	if cert.ValidAfter < uint64(before.Add(-10*time.Minute).Unix()) {
		t.Errorf("ValidAfter = %d, backdated more than 10m before now", cert.ValidAfter)
	}

	if err := authenticate(ca, "bob", cert); err == nil {
		t.Error("Authenticate() accepted a principal not in ValidPrincipals")
	}
}

func TestExpiredCertRejected(t *testing.T) {
	ca := newUserCA(t)
	clientPub := newClientKey(t)

	// A negative TTL puts ValidBefore in the past.
	cert, err := ca.SignUserCert(clientPub, testPrincipal, -time.Hour)
	if err != nil {
		t.Fatalf(testSignCertFmt, err)
	}

	if err := authenticate(ca, testPrincipal, cert); err == nil {
		t.Fatal("Authenticate() accepted an expired cert")
	}
}

// TestHostKeyStable covers SC-007: the gateway host key must survive restarts.
func TestHostKeyStable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "veyport.db")

	first := hostKeyFingerprint(t, dbPath)
	second := hostKeyFingerprint(t, dbPath)

	if first != second {
		t.Fatalf("host key changed across restarts: %s != %s", first, second)
	}
}

func hostKeyFingerprint(t *testing.T, dbPath string) string {
	t.Helper()
	st, err := store.New(dbPath)
	if err != nil {
		t.Fatalf(testNewStoreFmt, err)
	}
	defer func() { _ = st.Close() }()

	signer, err := userca.InitHostKey(st, testStorageKey)
	if err != nil {
		t.Fatalf(testInitHostFmt, err)
	}
	return ssh.FingerprintSHA256(signer.PublicKey())
}

func TestUserCAStable(t *testing.T) {
	st := newStore(t)

	first, err := userca.InitUserCA(st, testStorageKey)
	if err != nil {
		t.Fatalf(testInitUserCAFmt, err)
	}
	storedPub, _, err := st.LookupConfig(keyUserCAPub)
	if err != nil {
		t.Fatalf("LookupConfig(%s) error: %v", keyUserCAPub, err)
	}

	second, err := userca.InitUserCA(st, testStorageKey)
	if err != nil {
		t.Fatalf(testInitUserCAFmt, err)
	}

	if ssh.FingerprintSHA256(first.PublicKey()) != ssh.FingerprintSHA256(second.PublicKey()) {
		t.Fatal("InitUserCA() regenerated the CA key on reload")
	}
	if first.AuthorizedKey() != second.AuthorizedKey() {
		t.Fatalf("AuthorizedKey() changed: %q != %q", first.AuthorizedKey(), second.AuthorizedKey())
	}

	// A cert signed by the reloaded CA must verify against the original.
	cert, err := second.SignUserCert(newClientKey(t), testPrincipal, time.Hour)
	if err != nil {
		t.Fatalf(testSignCertFmt, err)
	}
	if err := authenticate(first, testPrincipal, cert); err != nil {
		t.Fatalf("Authenticate() rejected a cert from the reloaded CA: %v", err)
	}

	// The stored public key must round-trip to the in-memory CA key.
	raw, err := hex.DecodeString(storedPub)
	if err != nil {
		t.Fatalf("stored %s is not hex: %v", keyUserCAPub, err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		t.Fatalf("stored %s is not an authorized_keys line: %v", keyUserCAPub, err)
	}
	if ssh.FingerprintSHA256(parsed) != ssh.FingerprintSHA256(first.PublicKey()) {
		t.Error("stored public key does not match the loaded CA key")
	}
}

// corruptions are the ways a stored key can be unusable. Every one must yield
// ErrCorruptKey and leave the stored value untouched (FR-006).
func corruptions(t *testing.T) map[string]string {
	t.Helper()
	// Valid ciphertext under the right storage key, but the plaintext is not a
	// parseable private key.
	junk := make([]byte, 64)
	if _, err := rand.Read(junk); err != nil {
		t.Fatalf("rand.Read() error: %v", err)
	}
	sealed, err := auth.Encrypt(junk, auth.DeriveKey(testStorageKey))
	if err != nil {
		t.Fatalf("auth.Encrypt() error: %v", err)
	}
	// Valid ciphertext, but sealed under a different storage key.
	wrongKey, err := auth.Encrypt(junk, auth.DeriveKey("some-other-storage-key"))
	if err != nil {
		t.Fatalf("auth.Encrypt() error: %v", err)
	}
	return map[string]string{
		"not hex":           "zzzz-not-hex",
		"hex garbage":       hex.EncodeToString([]byte("garbage garbage garbage garbage")),
		"undecryptable":     hex.EncodeToString(wrongKey),
		"unparseable plain": hex.EncodeToString(sealed),
		"empty-ish":         "00",
	}
}

func TestCorruptUserCAKeyIsTypedErrorAndNotRegenerated(t *testing.T) {
	for name, bad := range corruptions(t) {
		t.Run(name, func(t *testing.T) {
			st := newStore(t)
			if err := st.SetConfig(keyUserCAKey, bad); err != nil {
				t.Fatalf("SetConfig() error: %v", err)
			}

			_, err := userca.InitUserCA(st, testStorageKey)
			if err == nil {
				t.Fatal("InitUserCA() accepted a corrupt stored key")
			}
			if !errors.Is(err, userca.ErrCorruptKey) {
				t.Fatalf("InitUserCA() error = %v, want ErrCorruptKey", err)
			}
			assertConfigUnchanged(t, st, keyUserCAKey, bad)
		})
	}
}

func TestCorruptHostKeyIsTypedErrorAndNotRegenerated(t *testing.T) {
	for name, bad := range corruptions(t) {
		t.Run(name, func(t *testing.T) {
			st := newStore(t)
			if err := st.SetConfig(keyHostKey, bad); err != nil {
				t.Fatalf("SetConfig() error: %v", err)
			}

			_, err := userca.InitHostKey(st, testStorageKey)
			if err == nil {
				t.Fatal("InitHostKey() accepted a corrupt stored key")
			}
			if !errors.Is(err, userca.ErrCorruptKey) {
				t.Fatalf("InitHostKey() error = %v, want ErrCorruptKey", err)
			}
			assertConfigUnchanged(t, st, keyHostKey, bad)
		})
	}
}

func assertConfigUnchanged(t *testing.T, st *store.Store, key, want string) {
	t.Helper()
	got, ok, err := st.LookupConfig(key)
	if err != nil {
		t.Fatalf("LookupConfig(%s) error: %v", key, err)
	}
	if !ok {
		t.Fatalf("%s was deleted; it must be left untouched", key)
	}
	if got != want {
		t.Fatalf("%s was rewritten (silent regeneration): got %q, want %q", key, got, want)
	}
}

// TestErrorsLeakNoKeyMaterial checks that failure paths never echo stored or
// decrypted key bytes into an error string (which lands in logs).
func TestErrorsLeakNoKeyMaterial(t *testing.T) {
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand.Read() error: %v", err)
	}
	sealed, err := auth.Encrypt(secret, auth.DeriveKey(testStorageKey))
	if err != nil {
		t.Fatalf("auth.Encrypt() error: %v", err)
	}
	stored := hex.EncodeToString(sealed)

	st := newStore(t)
	if err := st.SetConfig(keyUserCAKey, stored); err != nil {
		t.Fatalf("SetConfig() error: %v", err)
	}
	if err := st.SetConfig(keyHostKey, stored); err != nil {
		t.Fatalf("SetConfig() error: %v", err)
	}

	_, caErr := userca.InitUserCA(st, testStorageKey)
	_, hostErr := userca.InitHostKey(st, testStorageKey)
	if caErr == nil || hostErr == nil {
		t.Fatal("expected both Init calls to fail on corrupt keys")
	}

	forbidden := []string{
		stored,
		hex.EncodeToString(secret),
		string(secret),
	}
	for _, err := range []error{caErr, hostErr} {
		msg := err.Error()
		for _, f := range forbidden {
			if strings.Contains(msg, f) {
				t.Errorf("error string leaks key material: %q", msg)
			}
		}
	}

	// A healthy CA must not print its private key either.
	good := newUserCA(t)
	if _, err := good.SignUserCert(newClientKey(t), "", time.Hour); err != nil {
		// An empty principal may be rejected; the message must still be clean.
		if strings.Contains(err.Error(), hex.EncodeToString(secret)) {
			t.Errorf("SignUserCert error leaks key material: %v", err)
		}
	}
}
