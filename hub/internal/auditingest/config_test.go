package auditingest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func configFixture(t *testing.T) FileConfig {
	t.Helper()
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("storage request was not SigV4 signed")
		}
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case r.URL.Query().Has("versioning"):
			_, _ = w.Write([]byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`))
		case r.URL.Query().Has("object-lock"):
			if r.URL.Path == "/audit-governance" {
				_, _ = w.Write([]byte(`<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>3650</Days></DefaultRetention></Rule></ObjectLockConfiguration>`))
				return
			}
			_, _ = w.Write([]byte(`<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>`))
		default:
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(storage.Close)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		if os.WriteFile(path, b, 0600) != nil {
			t.Fatal("fixture write failed")
		}
		return path
	}
	tlsCert := storage.TLS.Certificates[0]
	keyBytes, err := x509.MarshalPKCS8PrivateKey(tlsCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := write("tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	certPath := write("tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: storage.Certificate().Raw}))
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signingBytes, _ := x509.MarshalECPrivateKey(signingKey)
	signingPath := write("signing.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: signingBytes}))
	q := validQualification()
	q.ArchiveEndpoint = storage.URL
	qBytes, _ := json.Marshal(q)
	qPath := write("qualification.json", qBytes)
	q.Bucket = "audit-governance"
	q.DefaultRetentionSeconds = 3650 * 86400
	govBytes, _ := json.Marshal(q)
	govPath := write("governance-qualification.json", govBytes)
	u, _ := url.Parse(storage.URL)
	return FileConfig{Listen: "127.0.0.1:0", Issuer: "ingest", Audience: "hub", TLSCertificatePath: certPath, TLSKeyPath: keyPath, ClientCAPath: certPath, AllowBearer: true, Credentials: []Credential{{ID: "ingest", TokenSHA256: auditrecord.Hash([]byte(strings.Repeat("i", 32))), Scope: ScopeIngest}}, SigningKeyID: "key-1", SigningKeyPath: signingPath, ArchiveEndpoint: storage.URL, ArchiveAllowedHosts: []string{u.Host}, ArchiveAllowedAddresses: []string{"127.0.0.1"}, ArchiveRegion: "region", ArchiveBucket: "archive", ArchiveKMSKeyID: "archive-key", ArchiveCAPath: certPath, ArchiveCredentialsPath: write("storage.json", []byte(`{"access_key":"synthetic-test-key","secret_key":"synthetic-test-only"}`)), QualificationPath: qPath, QualificationSHA256: auditrecord.Hash(qBytes), GovernanceBucket: "audit-governance", GovernanceRetentionSeconds: 3650 * 86400, GovernanceQualificationPath: govPath, GovernanceQualificationSHA256: auditrecord.Hash(govBytes), RetentionSeconds: 86400, ReceiptTTLSeconds: 60, Concurrency: 4}
}

func TestQualifiedConfigUsesVettedSigV4AndTLS(t *testing.T) {
	c := configFixture(t)
	server, err := c.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if server.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven || server.TLSConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("TLS authentication incorrect")
	}
	c.AllowBearer = false
	c.Credentials = []Credential{{ID: "mTLS", CertificateSHA256: auditrecord.Hash([]byte("certificate")), Scope: ScopeIngest}}
	server, err = c.Build(context.Background())
	if err != nil || server.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("mutual TLS mode incorrect")
	}
	b, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "config.json")
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("write")
	}
	loaded, err := LoadFileConfig(path)
	if err != nil || loaded.QualificationSHA256 != c.QualificationSHA256 {
		t.Fatal("config load failed")
	}
}

func TestProtectedFilesAndConfigFailClosed(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "private")
	if os.WriteFile(private, []byte("synthetic"), 0600) != nil {
		t.Fatal("write")
	}
	if _, err := ReadPrivateFile(private, 3); err == nil {
		t.Fatal("oversize private file accepted")
	}
	if _, err := ReadPrivateFile(private, 32); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	os.Symlink(private, link)
	if _, err := ReadPrivateFile(link, 32); err == nil {
		t.Fatal("symlink private file accepted")
	}
	os.Chmod(private, 0644)
	if _, err := ReadPrivateFile(private, 32); err == nil {
		t.Fatal("public secret file accepted")
	}
	if _, err := readPublicFile(private, 3); err == nil {
		t.Fatal("oversize public file accepted")
	}
	if _, err := LoadFileConfig(private); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	if _, err := ReadPrivateFile(dir, 32); err == nil {
		t.Fatal("directory accepted")
	}
	c := configFixture(t)
	badPath := filepath.Join(dir, "bad")
	os.WriteFile(badPath, []byte(`{"secret":"SYNTHETIC_SECRET"}`), 0600)
	changes := []func(*FileConfig){func(c *FileConfig) { c.Concurrency = 16 }, func(c *FileConfig) { c.SigningKeyPath = badPath }, func(c *FileConfig) { c.TLSKeyPath = badPath }, func(c *FileConfig) { c.TLSCertificatePath = badPath }, func(c *FileConfig) { c.ClientCAPath = badPath }, func(c *FileConfig) { c.ArchiveCAPath = badPath }, func(c *FileConfig) { c.ArchiveCredentialsPath = badPath }, func(c *FileConfig) { c.QualificationSHA256 = auditrecord.Hash(nil) }, func(c *FileConfig) { c.ArchiveBucket = "different" }, func(c *FileConfig) { c.AllowBearer = false }, func(c *FileConfig) { c.Credentials = nil }, func(c *FileConfig) { c.SigningKeyID = "../key" }}
	for _, change := range changes {
		bad := c
		change(&bad)
		if _, err := bad.Build(context.Background()); err == nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
			t.Fatal("invalid config accepted or exposed secret")
		}
	}
}
