package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/ca"
)

const (
	testGenerateCAFmt         = "GenerateCA: %v"
	testGenerateCAErrFmt      = "GenerateCA() error: %v"
	testGenerateKeyErrFmt     = "GenerateKey error: %v"
	testCreateCSRErrFmt       = "CreateCertificateRequest error: %v"
	testServerCN              = "veyport-hub"
	testGenerateServerCertFmt = "GenerateServerCert() error: %v"
)

func TestGenerateCA(t *testing.T) {
	cert, key, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAErrFmt, err)
	}

	if cert == nil {
		t.Fatal("GenerateCA() returned nil cert")
	}
	if key == nil {
		t.Fatal("GenerateCA() returned nil key")
	}

	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
	if cert.Subject.CommonName != "Veyport CA" {
		t.Errorf("expected CN='Veyport CA', got %q", cert.Subject.CommonName)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("expected KeyUsageCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("expected KeyUsageCRLSign")
	}

	// Verify ~10 year validity
	expectedExpiry := time.Now().Add(10 * 365 * 24 * time.Hour)
	if cert.NotAfter.Before(expectedExpiry.Add(-48 * time.Hour)) {
		t.Errorf("cert expires too soon: %v", cert.NotAfter)
	}
}

func TestSignCSR(t *testing.T) {
	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAErrFmt, err)
	}

	// Generate agent keypair and CSR
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(testGenerateKeyErrFmt, err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "original-cn"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, agentKey)
	if err != nil {
		t.Fatalf(testCreateCSRErrFmt, err)
	}

	serverID := "agent-server-001"
	validity := 12 * time.Hour

	cert, err := ca.SignCSR(caCert, caKey, csrDER, serverID, validity)
	if err != nil {
		t.Fatalf("SignCSR() error: %v", err)
	}

	// CN matches serverID (not the original CSR CN)
	if cert.Subject.CommonName != serverID {
		t.Errorf("expected CN=%q, got %q", serverID, cert.Subject.CommonName)
	}

	// Validity is ~12h
	expectedExpiry := time.Now().Add(validity)
	if cert.NotAfter.Before(expectedExpiry.Add(-1*time.Minute)) || cert.NotAfter.After(expectedExpiry.Add(1*time.Minute)) {
		t.Errorf("unexpected NotAfter: %v (expected ~%v)", cert.NotAfter, expectedExpiry)
	}

	// Cert chains to CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("cert does not chain to CA: %v", err)
	}

	// ExtKeyUsage is ClientAuth
	if len(cert.ExtKeyUsage) == 0 {
		t.Fatal("expected ExtKeyUsage to be set")
	}
	foundClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
		}
	}
	if !foundClientAuth {
		t.Error("expected ExtKeyUsageClientAuth")
	}

	// KeyUsage includes DigitalSignature
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected KeyUsageDigitalSignature")
	}
}

func TestSignCSR_ExpiredCert(t *testing.T) {
	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAErrFmt, err)
	}

	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(testGenerateKeyErrFmt, err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "agent"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, agentKey)
	if err != nil {
		t.Fatalf(testCreateCSRErrFmt, err)
	}

	// Sign with 0 duration => already expired
	cert, err := ca.SignCSR(caCert, caKey, csrDER, "expired-agent", 0)
	if err != nil {
		t.Fatalf("SignCSR() error: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err == nil {
		t.Error("expected expired cert to fail verification")
	}
}

func TestSignCSR_InvalidCSR(t *testing.T) {
	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAErrFmt, err)
	}

	_, err = ca.SignCSR(caCert, caKey, []byte("garbage"), "server-1", 12*time.Hour)
	if err == nil {
		t.Error("expected error for invalid CSR bytes")
	}
}

func TestSignCSR_BadSignature(t *testing.T) {
	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAErrFmt, err)
	}

	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(testGenerateKeyErrFmt, err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "agent"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, agentKey)
	if err != nil {
		t.Fatalf(testCreateCSRErrFmt, err)
	}

	// Tamper with the last few bytes (signature portion)
	tampered := make([]byte, len(csrDER))
	copy(tampered, csrDER)
	// Flip bits in the signature area (near the end)
	for i := len(tampered) - 10; i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	_, err = ca.SignCSR(caCert, caKey, tampered, "server-1", 12*time.Hour)
	if err == nil {
		// Some ASN.1 tampering may cause parse failure rather than signature failure,
		// which is also acceptable — we just need an error.
		t.Error("expected error for tampered CSR")
	}
}

// TestGenerateCA_UniqueSerials verifies that two CAs get different serial numbers.
func TestGenerateCA_UniqueSerials(t *testing.T) {
	cert1, _, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf("first GenerateCA() error: %v", err)
	}
	cert2, _, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf("second GenerateCA() error: %v", err)
	}
	if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		t.Error("two CA certs should have different serial numbers")
	}
}

// TestSignCSR_UniqueSerials verifies signed certs get unique serials.
func TestSignCSR_UniqueSerials(t *testing.T) {
	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAErrFmt, err)
	}

	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(testGenerateKeyErrFmt, err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "agent"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, agentKey)
	if err != nil {
		t.Fatalf(testCreateCSRErrFmt, err)
	}

	cert1, err := ca.SignCSR(caCert, caKey, csrDER, "agent-1", 12*time.Hour)
	if err != nil {
		t.Fatalf("first SignCSR() error: %v", err)
	}
	cert2, err := ca.SignCSR(caCert, caKey, csrDER, "agent-2", 12*time.Hour)
	if err != nil {
		t.Fatalf("second SignCSR() error: %v", err)
	}

	if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		t.Error("two signed certs should have different serial numbers")
	}
}

func TestGenerateServerCert_BasicFields(t *testing.T) {
	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAFmt, err)
	}

	cert, key, err := ca.GenerateServerCert(caCert, caKey, testServerCN)
	if err != nil {
		t.Fatalf(testGenerateServerCertFmt, err)
	}
	if cert == nil || key == nil {
		t.Fatal("expected non-nil cert and key")
	}
	if cert.Subject.CommonName != testServerCN {
		t.Errorf("expected CN=veyport-hub, got %s", cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) == 0 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Error("expected ServerAuth extended key usage")
	}
}

func TestGenerateServerCert_WithDNSSANs(t *testing.T) {
	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAFmt, err)
	}

	cert, _, err := ca.GenerateServerCert(caCert, caKey, testServerCN, "veyport.example.com", "localhost")
	if err != nil {
		t.Fatalf(testGenerateServerCertFmt, err)
	}

	expected := map[string]bool{"veyport.example.com": false, "localhost": false}
	for _, name := range cert.DNSNames {
		if _, ok := expected[name]; ok {
			expected[name] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("expected DNS SAN %q not found in cert, got %v", name, cert.DNSNames)
		}
	}
}

func TestGenerateServerCert_NoDNSSANs(t *testing.T) {
	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAFmt, err)
	}

	cert, _, err := ca.GenerateServerCert(caCert, caKey, testServerCN)
	if err != nil {
		t.Fatalf(testGenerateServerCertFmt, err)
	}
	if len(cert.DNSNames) != 0 {
		t.Errorf("expected no DNS SANs when none provided, got %v", cert.DNSNames)
	}
}
