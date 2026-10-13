package auditingest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/golang-jwt/jwt/v5"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

// FileConfig contains paths and public pins, never credential values. This binary
// has no flag that bypasses qualification, TLS, encryption or compliance retention.
type FileConfig struct {
	GovernanceBucket              string       `json:"governance_bucket"`
	GovernanceQualificationPath   string       `json:"governance_qualification_path"`
	GovernanceQualificationSHA256 string       `json:"governance_qualification_sha256"`
	GovernanceRetentionSeconds    uint64       `json:"governance_retention_seconds"`
	Listen                        string       `json:"listen"`
	Issuer                        string       `json:"issuer"`
	Audience                      string       `json:"audience"`
	TLSCertificatePath            string       `json:"tls_certificate_path"`
	TLSKeyPath                    string       `json:"tls_key_path"`
	ClientCAPath                  string       `json:"client_ca_path"`
	AllowBearer                   bool         `json:"allow_bearer"`
	Credentials                   []Credential `json:"credentials"`
	SigningKeyID                  string       `json:"signing_key_id"`
	SigningKeyPath                string       `json:"signing_key_path"`
	ArchiveEndpoint               string       `json:"archive_endpoint"`
	ArchiveAllowedHosts           []string     `json:"archive_allowed_hosts"`
	ArchiveAllowedAddresses       []string     `json:"archive_allowed_addresses"`
	ArchiveRegion                 string       `json:"archive_region"`
	ArchiveBucket                 string       `json:"archive_bucket"`
	ArchiveKMSKeyID               string       `json:"archive_kms_key_id"`
	ArchiveCAPath                 string       `json:"archive_ca_path"`
	ArchiveCredentialsPath        string       `json:"archive_credentials_path"`
	QualificationPath             string       `json:"qualification_path"`
	QualificationSHA256           string       `json:"qualification_sha256"`
	RetentionSeconds              uint64       `json:"retention_seconds"`
	ReceiptTTLSeconds             uint32       `json:"receipt_ttl_seconds"`
	Concurrency                   int          `json:"concurrency"`
}

func ReadPrivateFile(path string, max int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > max {
		return nil, ErrUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, ErrUnavailable
	}
	return b, nil
}

func readPublicFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, ErrUnavailable
	}
	return b, nil
}

func LoadFileConfig(path string) (FileConfig, error) {
	b, err := ReadPrivateFile(path, 64<<10)
	var c FileConfig
	if err != nil || auditrecord.Decode(b, &c, 64<<10) != nil {
		return c, ErrUnavailable
	}
	return c, nil
}

func (c FileConfig) Build(ctx context.Context) (*http.Server, error) {
	if c.RetentionSeconds < 3600 || c.RetentionSeconds > 10*365*24*3600 || c.ReceiptTTLSeconds < 1 || c.ReceiptTTLSeconds > 300 || c.Concurrency < 1 || c.Concurrency > 4 {
		return nil, ErrUnavailable
	}
	signingBytes, err := ReadPrivateFile(c.SigningKeyPath, 16<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	signingKey, err := jwt.ParseECPrivateKeyFromPEM(signingBytes)
	if err != nil {
		return nil, ErrUnavailable
	}
	keyBytes, err := ReadPrivateFile(c.TLSKeyPath, 16<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	certBytes, err := readPublicFile(c.TLSCertificatePath, 64<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	certificate, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, ErrUnavailable
	}
	clientCABytes, err := readPublicFile(c.ClientCAPath, 64<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	clientCA := x509.NewCertPool()
	if !clientCA.AppendCertsFromPEM(clientCABytes) {
		return nil, ErrUnavailable
	}
	archiveCABytes, err := readPublicFile(c.ArchiveCAPath, 64<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	archiveCA := x509.NewCertPool()
	if !archiveCA.AppendCertsFromPEM(archiveCABytes) {
		return nil, ErrUnavailable
	}
	secrets, err := ReadPrivateFile(c.ArchiveCredentialsPath, 16<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	var storageCredential struct {
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	if auditrecord.Decode(secrets, &storageCredential, 16<<10) != nil || storageCredential.AccessKey == "" || storageCredential.SecretKey == "" {
		return nil, ErrUnavailable
	}
	qBytes, err := readPublicFile(c.QualificationPath, 64<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	qualification, err := LoadQualification(qBytes, c.QualificationSHA256)
	if err != nil {
		return nil, ErrUnavailable
	}
	archive, err := NewS3Archive(ctx, S3Config{Endpoint: c.ArchiveEndpoint, Region: c.ArchiveRegion, Bucket: c.ArchiveBucket, KMSKeyID: c.ArchiveKMSKeyID, AllowedHosts: c.ArchiveAllowedHosts, AllowedAddresses: c.ArchiveAllowedAddresses, TLS: &tls.Config{RootCAs: archiveCA, MinVersion: tls.VersionTLS12}, Credentials: credentials.NewStaticCredentialsProvider(storageCredential.AccessKey, storageCredential.SecretKey, ""), Qualification: qualification}, nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	if c.GovernanceBucket == c.ArchiveBucket || c.GovernanceRetentionSeconds < 3600 || c.GovernanceRetentionSeconds > 3650*86400 {
		return nil, ErrUnavailable
	}
	governanceBytes, err := readPublicFile(c.GovernanceQualificationPath, 64<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	governanceQualification, err := LoadQualification(governanceBytes, c.GovernanceQualificationSHA256)
	if err != nil {
		return nil, ErrUnavailable
	}
	governance, err := NewS3Archive(ctx, S3Config{Endpoint: c.ArchiveEndpoint, Region: c.ArchiveRegion, Bucket: c.GovernanceBucket, KMSKeyID: c.ArchiveKMSKeyID, AllowedHosts: c.ArchiveAllowedHosts, AllowedAddresses: c.ArchiveAllowedAddresses, TLS: &tls.Config{RootCAs: archiveCA, MinVersion: tls.VersionTLS12}, Credentials: credentials.NewStaticCredentialsProvider(storageCredential.AccessKey, storageCredential.SecretKey, ""), Qualification: governanceQualification}, nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	service, err := NewService(ServiceConfig{Issuer: c.Issuer, Audience: c.Audience, Retention: time.Duration(c.RetentionSeconds) * time.Second, ReceiptTTL: time.Duration(c.ReceiptTTLSeconds) * time.Second, Timeout: 10 * time.Second, Concurrency: c.Concurrency, Signer: Signer{KeyID: c.SigningKeyID, Key: signingKey}, Archive: archive, GovernanceArchive: governance, GovernanceRetention: time.Duration(c.GovernanceRetentionSeconds) * time.Second})
	if err != nil {
		return nil, ErrUnavailable
	}
	for _, cred := range c.Credentials {
		if cred.TokenSHA256 != "" && !c.AllowBearer {
			return nil, ErrUnavailable
		}
	}
	auth, err := NewAuthenticator(c.Credentials)
	if err != nil {
		return nil, ErrUnavailable
	}
	handler, err := NewHandler(service, auth, c.Concurrency)
	if err != nil {
		return nil, ErrUnavailable
	}
	authMode := tls.RequireAndVerifyClientCert
	if c.AllowBearer {
		authMode = tls.VerifyClientCertIfGiven
	}
	return NewHTTPServer(c.Listen, handler, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, ClientCAs: clientCA, ClientAuth: authMode})
}
