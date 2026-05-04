package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store manages client certificates for mTLS communication with the hub.
// All methods are safe for concurrent use.
type Store struct {
	mu     sync.RWMutex
	dir    string // empty for in-memory store
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	caCert *x509.Certificate

	// Raw PEM/DER kept for TLS config building
	certPEM []byte
	keyPEM  []byte
	caPEM   []byte
}

// NewStore creates a disk-backed certificate store. If dir is non-empty,
// StoreCert will persist PEM files to that directory.
func NewStore(dir string) *Store {
	s := &Store{dir: dir}
	if dir != "" {
		_ = s.loadFromDisk()
	}
	return s
}

// NewMemoryStore creates an in-memory certificate store for testing.
func NewMemoryStore() *Store {
	return &Store{}
}

func (s *Store) loadFromDisk() error {
	certPEM, err := os.ReadFile(filepath.Join(s.dir, "client.crt"))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(s.dir, "client.key"))
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(filepath.Join(s.dir, "ca.crt"))
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("decode client certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse client cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("decode client key")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse client key: %w", err)
	}

	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return fmt.Errorf("decode CA certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return fmt.Errorf("verify client cert signature: %w", err)
	}
	if err := verifyCertMatchesKey(cert, key); err != nil {
		return err
	}

	s.mu.Lock()
	s.cert = cert
	s.key = key
	s.caCert = caCert
	s.certPEM = certPEM
	s.keyPEM = keyPEM
	s.caPEM = caPEM
	s.mu.Unlock()

	return nil
}

// GenerateCSR generates an ECDSA P-256 keypair, stores the private key in
// memory, and returns a DER-encoded CSR with CN set to serverID.
func (s *Store) GenerateCSR(serverID string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: serverID,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	s.mu.Lock()
	s.key = key
	s.mu.Unlock()

	return csrDER, nil
}

// StoreCert parses and stores the signed client certificate and CA certificate
// (both DER-encoded). If a directory is configured, the certs and key are
// written to disk as PEM files with 0600 permissions.
func (s *Store) StoreCert(certDER, caCertDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse client cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	s.mu.RLock()
	key := s.key
	s.mu.RUnlock()

	if key == nil {
		return fmt.Errorf("no private key available (call GenerateCSR first)")
	}
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return fmt.Errorf("verify client cert signature: %w", err)
	}
	if err := verifyCertMatchesKey(cert, key); err != nil {
		return err
	}

	// Encode PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	s.mu.Lock()
	s.cert = cert
	s.caCert = caCert
	s.certPEM = certPEM
	s.keyPEM = keyPEM
	s.caPEM = caPEM
	s.mu.Unlock()

	// Write to disk if configured
	if s.dir != "" {
		if err := os.MkdirAll(s.dir, 0700); err != nil {
			return fmt.Errorf("create cert dir: %w", err)
		}
		files := map[string][]byte{
			"client.crt": certPEM,
			"client.key": keyPEM,
			"ca.crt":     caPEM,
		}
		for name, data := range files {
			path := filepath.Join(s.dir, name)
			if err := os.WriteFile(path, data, 0600); err != nil {
				return fmt.Errorf("write %s: %w", name, err)
			}
		}
	}

	return nil
}

func verifyCertMatchesKey(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal cert public key: %w", err)
	}
	keyPubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal private key public key: %w", err)
	}
	if !bytes.Equal(certPubDER, keyPubDER) {
		return fmt.Errorf("client certificate does not match generated private key")
	}
	return nil
}

// TLSConfig returns a *tls.Config configured for mTLS if certificates are
// available. Returns nil if no cert/key/CA have been stored.
func (s *Store) TLSConfig() *tls.Config {
	s.mu.RLock()
	certPEM := s.certPEM
	keyPEM := s.keyPEM
	caPEM := s.caPEM
	s.mu.RUnlock()

	if certPEM == nil || keyPEM == nil || caPEM == nil {
		return nil
	}

	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil
	}

	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
	}
}

// NeedsRenewal returns true if the stored certificate expires within the
// given threshold duration.
func (s *Store) NeedsRenewal(threshold time.Duration) bool {
	s.mu.RLock()
	cert := s.cert
	s.mu.RUnlock()

	if cert == nil {
		return false
	}

	return time.Until(cert.NotAfter) < threshold
}

// HasCert returns true if the store has a valid certificate and private key.
func (s *Store) HasCert() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cert != nil && s.key != nil
}
