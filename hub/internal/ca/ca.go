// Package ca provides certificate authority operations for Veyport mTLS.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/store"
)

// loadExistingCA decodes and decrypts an existing CA from hex-encoded DER values.
// If the key is stored unencrypted (pre-migration), it re-saves it encrypted.
func loadExistingCA(st *store.Store, certHex, keyHex string, encKey []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certDER, err := hex.DecodeString(certHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decode CA cert hex: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
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
	if key == nil {
		// Fall back to raw DER (pre-encryption migration)
		pk, parseErr := x509.ParseECPrivateKey(keyDER)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("parse CA key: %w", parseErr)
		}
		key = pk
		// Re-save encrypted
		encrypted, err := auth.Encrypt(keyDER, encKey)
		if err == nil {
			_ = st.SetConfig("ca_key", hex.EncodeToString(encrypted))
			log.Println("CA key migrated to encrypted storage")
		}
	}

	return cert, key, nil
}

// generateAndSaveCA creates a new CA keypair and persists it encrypted in the store.
func generateAndSaveCA(st *store.Store, encKey []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, key, err := GenerateCA()
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA: %w", err)
	}

	// Store cert as hex-encoded DER
	if err := st.SetConfig("ca_cert", hex.EncodeToString(cert.Raw)); err != nil {
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
	if err := st.SetConfig("ca_key", hex.EncodeToString(encrypted)); err != nil {
		return nil, nil, fmt.Errorf("store CA key: %w", err)
	}

	log.Println("Generated new CA certificate and key")
	return cert, key, nil
}

// InitCA loads or creates the CA certificate and private key, storing them in the database.
// The CA key is encrypted with AES-256-GCM using a key derived from the JWT secret.
// Returns the CA certificate and private key for use by the gRPC server.
func InitCA(st *store.Store, jwtSecret string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	encKey := auth.DeriveKey(jwtSecret)

	// Try to load existing CA from database
	certHex, certErr := st.GetConfig("ca_cert")
	keyHex, keyErr := st.GetConfig("ca_key")

	if certErr == nil && keyErr == nil && certHex != "" && keyHex != "" {
		return loadExistingCA(st, certHex, keyHex, encKey)
	}

	return generateAndSaveCA(st, encKey)
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
