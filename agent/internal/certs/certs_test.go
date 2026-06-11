package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testServerID       = "srv-abc123"
	testGenerateCSRFmt = "GenerateCSR: %v"
	testStoreCertFmt   = "StoreCert: %v"
)

// newTestCA creates a self-signed CA certificate and key for testing.
func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return caCert, caKey
}

// signCSR signs a DER-encoded CSR with the given CA and returns the
// signed certificate in DER encoding.
func signCSR(t *testing.T, csrDER []byte, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, notAfter time.Time) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return certDER
}

func TestGenerateCSR(t *testing.T) {
	s := NewMemoryStore()
	csrDER, err := s.GenerateCSR(testServerID)
	if err != nil {
		t.Fatalf(testGenerateCSRFmt, err)
	}
	if len(csrDER) == 0 {
		t.Fatal("CSR is empty")
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != testServerID {
		t.Errorf("CN = %q, want %q", csr.Subject.CommonName, testServerID)
	}
}

func TestStoreCertAndTLSConfig(t *testing.T) {
	caCert, caKey := newTestCA(t)

	s := NewMemoryStore()
	csrDER, err := s.GenerateCSR("test-server")
	if err != nil {
		t.Fatalf(testGenerateCSRFmt, err)
	}

	certDER := signCSR(t, csrDER, caCert, caKey, time.Now().Add(24*time.Hour))

	// Marshal CA cert to DER for StoreCert
	caCertDER := caCert.Raw

	if err := s.StoreCert(certDER, caCertDER); err != nil {
		t.Fatalf(testStoreCertFmt, err)
	}

	tlsCfg := s.TLSConfig()
	if tlsCfg == nil {
		t.Fatal("TLSConfig() returned nil after StoreCert")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.RootCAs == nil {
		t.Error("RootCAs is nil")
	}
}

func TestStoreCert_RejectsMismatchedPrivateKey(t *testing.T) {
	caCert, caKey := newTestCA(t)

	signer := NewMemoryStore()
	csrDER, err := signer.GenerateCSR("test-server")
	if err != nil {
		t.Fatalf(testGenerateCSRFmt, err)
	}
	certDER := signCSR(t, csrDER, caCert, caKey, time.Now().Add(24*time.Hour))

	receiver := NewMemoryStore()
	if _, err := receiver.GenerateCSR("other-server"); err != nil {
		t.Fatalf(testGenerateCSRFmt, err)
	}
	if err := receiver.StoreCert(certDER, caCert.Raw); err == nil {
		t.Fatal("expected StoreCert to reject a cert for a different private key")
	}
}

func TestNeedsRenewal(t *testing.T) {
	caCert, caKey := newTestCA(t)
	s := NewMemoryStore()

	// No cert yet — should return false
	if s.NeedsRenewal(time.Hour) {
		t.Error("NeedsRenewal should be false with no cert")
	}

	csrDER, err := s.GenerateCSR("test")
	if err != nil {
		t.Fatalf(testGenerateCSRFmt, err)
	}

	// Cert that expires in 2 hours
	certDER := signCSR(t, csrDER, caCert, caKey, time.Now().Add(2*time.Hour))
	if err := s.StoreCert(certDER, caCert.Raw); err != nil {
		t.Fatalf(testStoreCertFmt, err)
	}

	// Threshold 1 hour — cert has ~2h left, should NOT need renewal
	if s.NeedsRenewal(1 * time.Hour) {
		t.Error("NeedsRenewal(1h) should be false when cert has ~2h left")
	}

	// Threshold 3 hours — cert has ~2h left, should need renewal
	if !s.NeedsRenewal(3 * time.Hour) {
		t.Error("NeedsRenewal(3h) should be true when cert has ~2h left")
	}
}

func TestHasCert(t *testing.T) {
	caCert, caKey := newTestCA(t)
	s := NewMemoryStore()

	if s.HasCert() {
		t.Error("HasCert should be false before StoreCert")
	}

	csrDER, err := s.GenerateCSR("test")
	if err != nil {
		t.Fatalf(testGenerateCSRFmt, err)
	}

	// After GenerateCSR we have a key but no cert yet
	if s.HasCert() {
		t.Error("HasCert should be false after GenerateCSR but before StoreCert")
	}

	certDER := signCSR(t, csrDER, caCert, caKey, time.Now().Add(24*time.Hour))
	if err := s.StoreCert(certDER, caCert.Raw); err != nil {
		t.Fatalf(testStoreCertFmt, err)
	}

	if !s.HasCert() {
		t.Error("HasCert should be true after StoreCert")
	}
}

func TestDiskPersistence(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := newTestCA(t)

	s := NewStore(dir)
	csrDER, err := s.GenerateCSR("disk-test")
	if err != nil {
		t.Fatalf(testGenerateCSRFmt, err)
	}

	certDER := signCSR(t, csrDER, caCert, caKey, time.Now().Add(24*time.Hour))
	if err := s.StoreCert(certDER, caCert.Raw); err != nil {
		t.Fatalf(testStoreCertFmt, err)
	}

	// Verify files exist with correct permissions
	for _, name := range []string{"client.crt", "client.key", "ca.crt"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("file %s not found: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", name)
		}
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("file %s has permissions %o, want 0600", name, perm)
		}
	}
}

func TestDiskPersistenceReloadsCerts(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := newTestCA(t)

	s := NewStore(dir)
	csrDER, err := s.GenerateCSR("disk-reload-test")
	if err != nil {
		t.Fatalf(testGenerateCSRFmt, err)
	}

	certDER := signCSR(t, csrDER, caCert, caKey, time.Now().Add(24*time.Hour))
	if err := s.StoreCert(certDER, caCert.Raw); err != nil {
		t.Fatalf(testStoreCertFmt, err)
	}

	reloaded := NewStore(dir)
	if !reloaded.HasCert() {
		t.Fatal("expected NewStore to load persisted client certificate and key")
	}
	if reloaded.TLSConfig() == nil {
		t.Fatal("expected reloaded store to build a TLS config")
	}
}

func TestLoadFromDiskRejectsInvalidPersistedMaterial(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(t *testing.T, dir string)
		wantErr string
	}{
		{
			name: "missing client key",
			corrupt: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(dir, "client.key")); err != nil {
					t.Fatalf("remove client key: %v", err)
				}
			},
			wantErr: "client.key",
		},
		{
			name: "missing CA certificate",
			corrupt: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(dir, "ca.crt")); err != nil {
					t.Fatalf("remove CA cert: %v", err)
				}
			},
			wantErr: "ca.crt",
		},
		{
			name: "malformed client certificate PEM",
			corrupt: func(t *testing.T, dir string) {
				t.Helper()
				writeTestFile(t, filepath.Join(dir, "client.crt"), []byte("not a certificate"))
			},
			wantErr: "decode client certificate",
		},
		{
			name: "malformed client key PEM",
			corrupt: func(t *testing.T, dir string) {
				t.Helper()
				writeTestFile(t, filepath.Join(dir, "client.key"), []byte("not a key"))
			},
			wantErr: "decode client key",
		},
		{
			name: "malformed CA certificate PEM",
			corrupt: func(t *testing.T, dir string) {
				t.Helper()
				writeTestFile(t, filepath.Join(dir, "ca.crt"), []byte("not a CA certificate"))
			},
			wantErr: "decode CA certificate",
		},
		{
			name: "wrong CA certificate",
			corrupt: func(t *testing.T, dir string) {
				t.Helper()
				otherCA, _ := newTestCA(t)
				writeTestCertPEM(t, filepath.Join(dir, "ca.crt"), otherCA)
			},
			wantErr: "verify client cert signature",
		},
		{
			name: "mismatched client key",
			corrupt: func(t *testing.T, dir string) {
				t.Helper()
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("generate replacement key: %v", err)
				}
				keyDER, err := x509.MarshalECPrivateKey(key)
				if err != nil {
					t.Fatalf("marshal replacement key: %v", err)
				}
				writeTestFile(t, filepath.Join(dir, "client.key"), pem.EncodeToMemory(&pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: keyDER,
				}))
			},
			wantErr: "client certificate does not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeValidDiskCerts(t, dir)
			tt.corrupt(t, dir)

			s := &Store{dir: dir}
			err := s.loadFromDisk()
			if err == nil {
				t.Fatal("expected loadFromDisk to reject invalid persisted cert material")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("loadFromDisk error = %q, want to contain %q", err, tt.wantErr)
			}
			if s.HasCert() {
				t.Fatal("expected invalid persisted cert material to leave store empty")
			}
		})
	}
}

func writeValidDiskCerts(t *testing.T, dir string) {
	t.Helper()
	caCert, caKey := newTestCA(t)

	s := NewStore(dir)
	csrDER, err := s.GenerateCSR("disk-error-test")
	if err != nil {
		t.Fatalf(testGenerateCSRFmt, err)
	}

	certDER := signCSR(t, csrDER, caCert, caKey, time.Now().Add(24*time.Hour))
	if err := s.StoreCert(certDER, caCert.Raw); err != nil {
		t.Fatalf(testStoreCertFmt, err)
	}
}

func writeTestCertPEM(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	writeTestFile(t, path, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", filepath.Base(path), err)
	}
}
