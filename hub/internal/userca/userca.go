// Package userca provides the SSH user certificate authority and the stable
// gateway host key for the Veyport SSH gateway.
//
// This trust root is deliberately separate from the agent mTLS CA in
// internal/ca: a user SSH credential must never be verifiable by the agent CA,
// and vice versa. Both keys are Ed25519 and live in the _config table,
// encrypted at rest with AES-256-GCM under a key derived from the storage key,
// mirroring ca.InitCA.
package userca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/store"
)

// _config keys holding the SSH gateway key material.
const (
	configUserCAKey = "ssh_user_ca_key"
	configUserCAPub = "ssh_user_ca_pub"
	configHostKey   = "ssh_host_key"
)

// clockSkew backdates ValidAfter so a client whose clock runs slightly ahead of
// the hub still sees a valid certificate.
const clockSkew = 60 * time.Second

// ErrCorruptKey reports that a key exists in _config but could not be decoded,
// decrypted, or parsed. Callers must disable the SSH gateway rather than
// regenerate: a fresh host key would trip "host key changed" on every client,
// and a fresh user CA would silently invalidate every issued certificate
// (FR-006). Errors wrapping ErrCorruptKey never contain key material.
var ErrCorruptKey = errors.New("stored SSH key is corrupt or undecryptable")

// UserCA signs short-lived SSH user certificates for gateway logins.
type UserCA struct {
	signer ssh.Signer
}

// InitUserCA loads the user SSH CA from the store, generating and persisting a
// new Ed25519 keypair on first use. The public key is also stored in
// authorized_keys form (hex, plaintext) under ssh_user_ca_pub for callers that
// need to publish it.
//
// A stored-but-unusable key yields an error wrapping ErrCorruptKey and is left
// untouched on disk.
func InitUserCA(st *store.Store, storageKey string) (*UserCA, error) {
	signer, err := loadOrGenerateSigner(st, configUserCAKey, storageKey, "SSH user CA")
	if err != nil {
		return nil, err
	}

	ca := &UserCA{signer: signer}
	if err := ca.persistPublicKey(st); err != nil {
		return nil, err
	}
	return ca, nil
}

// InitHostKey loads the SSH gateway host key, generating and persisting a new
// Ed25519 keypair on first use. The key is stable across restarts (FR-006).
//
// A stored-but-unusable key yields an error wrapping ErrCorruptKey and is left
// untouched on disk; the caller must disable the gateway rather than serve a
// changed host key.
func InitHostKey(st *store.Store, storageKey string) (ssh.Signer, error) {
	return loadOrGenerateSigner(st, configHostKey, storageKey, "SSH gateway host key")
}

// PublicKey returns the CA public key. Pass IsUserAuthority to
// ssh.CertChecker rather than comparing this directly.
func (c *UserCA) PublicKey() ssh.PublicKey {
	return c.signer.PublicKey()
}

// AuthorizedKey returns the CA public key in authorized_keys form
// ("ssh-ed25519 AAAA..."), without a trailing newline. Safe to expose.
func (c *UserCA) AuthorizedKey() string {
	return authorizedKeyString(c.signer.PublicKey())
}

// IsUserAuthority reports whether key is this CA's public key. It is the
// callback for ssh.CertChecker.IsUserAuthority: a certificate signed by any
// other authority must not be trusted.
func (c *UserCA) IsUserAuthority(key ssh.PublicKey) bool {
	if c == nil || c.signer == nil || key == nil {
		return false
	}
	mine := c.signer.PublicKey()
	if key.Type() != mine.Type() {
		return false
	}
	// Constant-time comparison is unnecessary here: both values are public.
	a, b := key.Marshal(), mine.Marshal()
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SignUserCert issues an SSH user certificate binding clientPub to a single
// principal for ttl. The principal is the sole entry in ValidPrincipals and is
// also the KeyId (so it appears in audit logs); no critical options are set.
func (c *UserCA) SignUserCert(clientPub ssh.PublicKey, principal string, ttl time.Duration) (*ssh.Certificate, error) {
	if c == nil || c.signer == nil {
		return nil, errors.New("sign user cert: user CA not initialized")
	}
	if clientPub == nil {
		return nil, errors.New("sign user cert: nil client public key")
	}
	if principal == "" {
		return nil, errors.New("sign user cert: empty principal")
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             clientPub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           principal,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Add(-clockSkew).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			// Interactive sessions need a PTY; nothing else is granted, and
			// no critical options (source-address, force-command) are set.
			Extensions: map[string]string{"permit-pty": ""},
		},
	}

	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, fmt.Errorf("sign user cert: %w", err)
	}
	return cert, nil
}

// persistPublicKey writes the CA public key in authorized_keys form if it is
// missing or out of sync with the private key, which is the source of truth.
func (c *UserCA) persistPublicKey(st *store.Store) error {
	want := hex.EncodeToString([]byte(c.AuthorizedKey()))
	got, _, err := st.LookupConfig(configUserCAPub)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", configUserCAPub, err)
	}
	if got == want {
		return nil
	}
	if err := st.SetConfig(configUserCAPub, want); err != nil {
		return fmt.Errorf("store %s: %w", configUserCAPub, err)
	}
	return nil
}

// loadOrGenerateSigner returns the Ed25519 signer stored under configKey,
// generating and persisting one if the key is absent. label is a human-readable
// name used in logs and errors; it never includes key material.
func loadOrGenerateSigner(st *store.Store, configKey, storageKey, label string) (ssh.Signer, error) {
	encKey := auth.DeriveKey(storageKey)

	stored, ok, err := st.LookupConfig(configKey)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", configKey, err)
	}
	if ok && stored != "" {
		signer, err := decodeSigner(stored, encKey)
		if err != nil {
			// Deliberately do NOT overwrite the stored value: the caller
			// disables the gateway instead (FR-006).
			return nil, fmt.Errorf("load %s: %w", label, err)
		}
		return signer, nil
	}

	signer, encoded, err := generateSigner(encKey)
	if err != nil {
		return nil, fmt.Errorf("generate %s: %w", label, err)
	}
	if err := st.SetConfig(configKey, encoded); err != nil {
		return nil, fmt.Errorf("store %s: %w", label, err)
	}
	log.Printf("Generated new %s (%s)", label, ssh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}

// decodeSigner reverses the at-rest encoding: hex -> AES-256-GCM -> PKCS#8.
// Every failure wraps ErrCorruptKey, and no error carries key bytes.
func decodeSigner(stored string, encKey []byte) (ssh.Signer, error) {
	sealed, err := hex.DecodeString(stored)
	if err != nil {
		return nil, fmt.Errorf("%w: value is not valid hex", ErrCorruptKey)
	}
	der, err := auth.Decrypt(sealed, encKey)
	if err != nil {
		return nil, fmt.Errorf("%w: decryption failed (wrong storage key or damaged value)", ErrCorruptKey)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypted value is not a PKCS#8 private key", ErrCorruptKey)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: stored key is not Ed25519", ErrCorruptKey)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: key is unusable as an SSH signer", ErrCorruptKey)
	}
	return signer, nil
}

// generateSigner creates a new Ed25519 keypair and returns the signer along
// with its at-rest encoding for _config.
func generateSigner(encKey []byte) (ssh.Signer, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate Ed25519 key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", fmt.Errorf("marshal private key: %w", err)
	}
	sealed, err := auth.Encrypt(der, encKey)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt private key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, "", fmt.Errorf("build SSH signer: %w", err)
	}
	return signer, hex.EncodeToString(sealed), nil
}

// authorizedKeyString renders pub as a single authorized_keys line without the
// trailing newline ssh.MarshalAuthorizedKey appends.
func authorizedKeyString(pub ssh.PublicKey) string {
	line := ssh.MarshalAuthorizedKey(pub)
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return string(line)
}

// randomSerial returns a non-zero random 64-bit certificate serial.
func randomSerial() (uint64, error) {
	var buf [8]byte
	for i := 0; i < 8; i++ {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("generate certificate serial: %w", err)
		}
		if serial := binary.BigEndian.Uint64(buf[:]); serial != 0 {
			return serial, nil
		}
	}
	return 0, errors.New("generate certificate serial: exhausted retries")
}
