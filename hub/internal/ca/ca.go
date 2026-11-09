// Package ca provides certificate authority operations for Veyport mTLS.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/store"
)

// caConfig uses the same transaction for the trust pair and legacy migration.
// SQLite rejects a concurrent read-to-write upgrade rather than allowing one
// initializer to overwrite a trust root committed by another initializer.
type caConfig struct{ tx *sql.Tx }

func (c caConfig) lookup(key string) (string, bool, error) {
	var value string
	err := c.tx.QueryRow("SELECT value FROM _config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return value, err == nil, err
}

func (c caConfig) set(key, value string) error {
	_, err := c.tx.Exec("INSERT INTO _config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

// loadExistingCA decodes and decrypts an existing CA from hex-encoded DER values.
// If the key is stored unencrypted (pre-migration), it re-saves it encrypted.
func loadExistingCA(config caConfig, certHex, keyHex string, encKey []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certDER, err := hex.DecodeString(certHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decode CA cert hex: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, fmt.Errorf("stored certificate is not a signing CA")
	}

	keyDER, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decode CA key hex: %w", err)
	}

	// Try to decrypt first (encrypted key), fall back to raw DER (backward compat)
	var key *ecdsa.PrivateKey
	decrypted, decErr := auth.Decrypt(keyDER, encKey)
	if decErr == nil {
		pk, parseErr := x509.ParseECPrivateKey(decrypted)
		if parseErr == nil {
			key = pk
		}
	}
	legacy := key == nil
	if legacy {
		pk, parseErr := x509.ParseECPrivateKey(keyDER)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("parse CA key: %w", parseErr)
		}
		key = pk
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, fmt.Errorf("CA private key does not match certificate")
	}
	if legacy {
		encrypted, err := auth.Encrypt(keyDER, encKey)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt migrated CA key: %w", err)
		}
		if err := config.set("ca_key", hex.EncodeToString(encrypted)); err != nil {
			return nil, nil, fmt.Errorf("store migrated CA key: %w", err)
		}
	}

	return cert, key, nil
}

// generateAndSaveCA creates a new CA keypair and persists it encrypted in the store.
func generateAndSaveCA(config caConfig, encKey []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, key, err := GenerateCA()
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA: %w", err)
	}

	// Store cert as hex-encoded DER
	if err := config.set("ca_cert", hex.EncodeToString(cert.Raw)); err != nil {
		return nil, nil, fmt.Errorf("store CA cert: %w", err)
	}

	// Encrypt and store key
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CA key: %w", err)
	}
	encrypted, err := auth.Encrypt(keyDER, encKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt CA key: %w", err)
	}
	if err := config.set("ca_key", hex.EncodeToString(encrypted)); err != nil {
		return nil, nil, fmt.Errorf("store CA key: %w", err)
	}

	return cert, key, nil
}

// InitCA loads or creates the CA certificate and private key, storing them in the database.
// The CA key is encrypted with AES-256-GCM using a key derived from the storage key
// (the at-rest encryption key, separate from the JWT signing secret).
// Returns the CA certificate and private key for use by the gRPC server.
func InitCA(st *store.Store, storageKey string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	encKey := auth.DeriveKey(storageKey)

	tx, err := st.DB().Begin()
	if err != nil {
		return nil, nil, fmt.Errorf("begin CA initialization: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	config := caConfig{tx: tx}
	certHex, certPresent, err := config.lookup("ca_cert")
	if err != nil {
		return nil, nil, fmt.Errorf("load CA cert: %w", err)
	}
	keyHex, keyPresent, err := config.lookup("ca_key")
	if err != nil {
		return nil, nil, fmt.Errorf("load CA key: %w", err)
	}

	var cert *x509.Certificate
	var key *ecdsa.PrivateKey
	switch {
	case !certPresent && !keyPresent:
		cert, key, err = generateAndSaveCA(config, encKey)
	case certPresent && keyPresent && certHex != "" && keyHex != "":
		cert, key, err = loadExistingCA(config, certHex, keyHex, encKey)
	default:
		return nil, nil, fmt.Errorf("incomplete stored CA certificate and key; restore the existing CA")
	}
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit CA initialization: %w", err)
	}
	return cert, key, nil
}

// GenerateCA creates an ECDSA P-256 CA keypair with a self-signed certificate.
// The certificate has a 10-year validity, CN="Veyport CA", IsCA=true,
// and KeyUsage of CertSign|CRLSign.
func GenerateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Veyport CA"},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	return cert, key, nil
}

// SignCSR signs a DER-encoded PKCS#10 CSR with the CA, producing a client
// certificate. The CN is set to serverID (overriding whatever is in the CSR).
// The CSR signature is validated before signing.
func SignCSR(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, csrDER []byte, serverID string, validity time.Duration) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverID},
		NotBefore:    now,
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse signed certificate: %w", err)
	}

	return cert, nil
}

// GenerateServerCert creates a server TLS certificate signed by the CA.
// The certificate has the given CN, a 1-year validity, and is suitable for
// gRPC server authentication (ExtKeyUsageServerAuth).
func GenerateServerCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, sanHosts ...string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	var dnsNames []string
	var ipAddresses []net.IP
	for _, host := range sanHosts {
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ipAddresses = append(ipAddresses, ip)
			continue
		}
		dnsNames = append(dnsNames, host)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create server certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server certificate: %w", err)
	}

	return cert, key, nil
}

// randomSerial generates a random 128-bit serial number for certificates.
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}
