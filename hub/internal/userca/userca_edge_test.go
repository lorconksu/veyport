package userca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
)

// Argument and trust-root edge cases. IsUserAuthority is the single callback
// standing between the gateway and a forged credential, so every way it can be
// handed something unexpected has to end in "false" rather than a panic or an
// accidental accept.

// mismatchedKey has the same key type as a real Ed25519 key but a wire form of a
// different length. The length check exists precisely so a marshalled blob can
// never be compared past its end.
type mismatchedKey struct{ inner ssh.PublicKey }

func (k mismatchedKey) Type() string    { return k.inner.Type() }
func (k mismatchedKey) Marshal() []byte { return k.inner.Marshal()[:8] }
func (k mismatchedKey) Verify(data []byte, sig *ssh.Signature) error {
	return k.inner.Verify(data, sig)
}

// newECDSAKey returns an SSH public key of a different algorithm to the CA's.
func newECDSAKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error: %v", err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey() error: %v", err)
	}
	return pub
}

func TestIsUserAuthorityRejectsEverythingButItsOwnKey(t *testing.T) {
	ca := newUserCA(t)

	var uninitialized *userca.UserCA
	if uninitialized.IsUserAuthority(newClientKey(t)) {
		t.Error("a nil UserCA claimed authority over a key")
	}
	if ca.IsUserAuthority(nil) {
		t.Error("IsUserAuthority(nil) = true, want false")
	}
	if ca.IsUserAuthority(newECDSAKey(t)) {
		t.Error("IsUserAuthority() accepted a key of a different algorithm")
	}
	if ca.IsUserAuthority(mismatchedKey{inner: ca.PublicKey()}) {
		t.Error("IsUserAuthority() accepted a truncated form of its own key")
	}
	if !ca.IsUserAuthority(ca.PublicKey()) {
		t.Error("IsUserAuthority() rejected its own CA key")
	}
}

// TestSignUserCertRejectsInvalidArguments pins that a certificate is never
// issued without a CA and a bound principal: an empty principal would produce a
// certificate valid for nobody, and a nil key one that certifies nothing.
func TestSignUserCertRejectsInvalidArguments(t *testing.T) {
	ca := newUserCA(t)

	var uninitialized *userca.UserCA
	if _, err := uninitialized.SignUserCert(newClientKey(t), testPrincipal, time.Hour); err == nil {
		t.Error("an uninitialized CA signed a certificate")
	}
	if _, err := ca.SignUserCert(nil, testPrincipal, time.Hour); err == nil {
		t.Error("SignUserCert() accepted a nil client public key")
	}
	if _, err := ca.SignUserCert(newClientKey(t), "", time.Hour); err == nil {
		t.Error("SignUserCert() accepted an empty principal")
	}
}

// TestInitFailsWhenTheStoreIsUnreadable pins FR-006's other half: if the key
// material cannot even be read, both Init calls fail loudly rather than
// returning a CA backed by nothing.
func TestInitFailsWhenTheStoreIsUnreadable(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf(testNewStoreFmt, err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close() error: %v", err)
	}

	if _, err := userca.InitUserCA(st, testStorageKey); err == nil {
		t.Error("InitUserCA() succeeded against an unreadable store")
	}
	if _, err := userca.InitHostKey(st, testStorageKey); err == nil {
		t.Error("InitHostKey() succeeded against an unreadable store")
	}
}

// ---------------------------------------------------------------------------
// datastore failure paths
// ---------------------------------------------------------------------------

// flakyStore is a userca.ConfigStore whose reads and writes fail per key on
// demand. A real *store.Store cannot stand in here: SQLite cannot be opened
// readable-but-not-writable through store.New, so "the key could not be
// persisted" has no other way to be exercised.
type flakyStore struct {
	values   map[string]string
	readErr  map[string]error
	writeErr map[string]error
}

func newFlakyStore() *flakyStore {
	return &flakyStore{
		values:   map[string]string{},
		readErr:  map[string]error{},
		writeErr: map[string]error{},
	}
}

func (s *flakyStore) LookupConfig(key string) (string, bool, error) {
	if err := s.readErr[key]; err != nil {
		return "", false, err
	}
	value, ok := s.values[key]
	return value, ok, nil
}

func (s *flakyStore) SetConfig(key, value string) error {
	if err := s.writeErr[key]; err != nil {
		return err
	}
	s.values[key] = value
	return nil
}

var errDatastoreDown = errors.New("datastore is unavailable")

// healthyFlakyStore returns a store already holding a usable CA keypair, so a
// later failure can be aimed at exactly one operation.
func healthyFlakyStore(t *testing.T) *flakyStore {
	t.Helper()
	st := newFlakyStore()
	if _, err := userca.InitUserCA(st, testStorageKey); err != nil {
		t.Fatalf(testInitUserCAFmt, err)
	}
	return st
}

// TestInitFailsWhenANewKeyCannotBePersisted pins that a key which cannot be
// stored is not handed back anyway: a CA whose private key exists only in
// memory would issue certificates that stop verifying at the next restart.
func TestInitFailsWhenANewKeyCannotBePersisted(t *testing.T) {
	st := newFlakyStore()
	st.writeErr[keyUserCAKey] = errDatastoreDown

	if _, err := userca.InitUserCA(st, testStorageKey); !errors.Is(err, errDatastoreDown) {
		t.Fatalf("InitUserCA() error = %v, want it to carry the store failure", err)
	}
	if _, ok := st.values[keyUserCAKey]; ok {
		t.Error("a CA key was recorded despite the store rejecting the write")
	}
}

// TestInitFailsWhenThePublishedPublicKeyCannotBeRead covers the second store
// round-trip: the private key loaded fine, but the published copy could not be
// checked, so the CA is not returned as healthy.
func TestInitFailsWhenThePublishedPublicKeyCannotBeRead(t *testing.T) {
	st := healthyFlakyStore(t)
	st.readErr[keyUserCAPub] = errDatastoreDown

	if _, err := userca.InitUserCA(st, testStorageKey); !errors.Is(err, errDatastoreDown) {
		t.Fatalf("InitUserCA() error = %v, want it to carry the store failure", err)
	}
}

// TestInitFailsWhenThePublishedPublicKeyCannotBeWritten covers the same
// round-trip failing on the write side, with the private key left untouched:
// the published key is a derived copy, never the source of truth.
func TestInitFailsWhenThePublishedPublicKeyCannotBeWritten(t *testing.T) {
	st := healthyFlakyStore(t)
	storedKey := st.values[keyUserCAKey]
	delete(st.values, keyUserCAPub)
	st.writeErr[keyUserCAPub] = errDatastoreDown

	if _, err := userca.InitUserCA(st, testStorageKey); !errors.Is(err, errDatastoreDown) {
		t.Fatalf("InitUserCA() error = %v, want it to carry the store failure", err)
	}
	if st.values[keyUserCAKey] != storedKey {
		t.Error("the stored private key was rewritten while publishing the public key failed")
	}
}

// TestNonEd25519StoredKeyIsCorrupt covers a stored key that decrypts and parses
// cleanly but is the wrong algorithm — the one corruption shape that survives
// every earlier check. It must still be reported as corrupt and left in place.
func TestNonEd25519StoredKeyIsCorrupt(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error: %v", err)
	}
	sealed, err := auth.Encrypt(der, auth.DeriveKey(testStorageKey))
	if err != nil {
		t.Fatalf("auth.Encrypt() error: %v", err)
	}
	stored := hex.EncodeToString(sealed)

	st := newStore(t)
	if err := st.SetConfig(keyUserCAKey, stored); err != nil {
		t.Fatalf("SetConfig() error: %v", err)
	}

	_, err = userca.InitUserCA(st, testStorageKey)
	if !errors.Is(err, userca.ErrCorruptKey) {
		t.Fatalf("InitUserCA() error = %v, want ErrCorruptKey", err)
	}
	assertConfigUnchanged(t, st, keyUserCAKey, stored)
}
