// Package auditruntime wires operator-pinned archive destinations into live
// governance and execution enforcement. Governance trust lives outside SQLite.
package auditruntime

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

var ErrConfiguration = errors.New("protected audit runtime configuration rejected")

type ClientFiles struct {
	CertificatePath string `json:"certificate_path"`
	KeyPath         string `json:"key_path"`
}

type ClientSet struct {
	Ingest         ClientFiles `json:"hub-ingest"`
	Admin          ClientFiles `json:"hub-admin"`
	OriginalReader ClientFiles `json:"hub-original-reader,omitempty"`
	Exporter       ClientFiles `json:"redactor-index,omitempty"`
}

type PublicKeyFile struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

// EndpointConfig is an operator allowlist entry, never supplied by an HTTP
// caller. Public trust and service administration credentials are independent
// from a policy's immutable ingestion credential reference.
type EndpointConfig struct {
	Endpoint                      string          `json:"endpoint"`
	AllowedAddresses              []string        `json:"allowed_addresses,omitempty"`
	Issuer                        string          `json:"issuer"`
	Audience                      string          `json:"audience"`
	SigningKeyID                  string          `json:"signing_key_id"`
	SigningPublicKeyPath          string          `json:"signing_public_key_path"`
	SigningPublicKeys             []PublicKeyFile `json:"signing_public_keys,omitempty"`
	CAPath                        string          `json:"ca_path"`
	QualificationSHA256           string          `json:"qualification_sha256"`
	GovernanceQualificationSHA256 string          `json:"governance_qualification_sha256"`
	Clients                       ClientSet       `json:"clients"`
}

// The top-level endpoint is the fixed governance authority. Destinations adds
// operator-approved execution archives; changing policy destination never
// redirects governance preservation, history lookup or latest-anchor checks.
type FileConfig struct {
	EndpointConfig
	Destinations []EndpointConfig `json:"destinations,omitempty"`
}

type endpoint struct {
	config   EndpointConfig
	roots    *x509.CertPool
	keys     map[string]*ecdsa.PublicKey
	ingest   *auditgate.Client
	admin    *auditgate.Client
	verifier *auditgate.Verifier
	ready    *readyClient
}

func readPrivate(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrConfiguration
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return nil, ErrConfiguration
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit {
		return nil, ErrConfiguration
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return nil, ErrConfiguration
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrConfiguration
	}
	return b, nil
}

func resolvePath(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

func loadPublicKey(path string) (*ecdsa.PublicKey, error) {
	b, err := readPrivate(path, 16<<10)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		return nil, ErrConfiguration
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	public, ok := k.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return nil, ErrConfiguration
	}
	return public, nil
}

func clientTLS(base string, roots *x509.CertPool, files ClientFiles) (*tls.Config, error) {
	cert, err := readPrivate(resolvePath(base, files.CertificatePath), 32<<10)
	if err != nil {
		return nil, err
	}
	key, err := readPrivate(resolvePath(base, files.KeyPath), 32<<10)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, ErrConfiguration
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}, nil
}

func (e *endpoint) newVerifier(ids []string) (*auditgate.Verifier, error) {
	keys := map[string]*ecdsa.PublicKey{}
	for _, id := range ids {
		if e.keys[id] == nil || keys[id] != nil {
			return nil, ErrConfiguration
		}
		keys[id] = e.keys[id]
	}
	return auditgate.NewVerifier(auditgate.VerifierConfig{Issuer: e.config.Issuer, Audience: e.config.Audience, Keys: keys, QualificationSHA256: e.config.QualificationSHA256, GovernanceQualificationSHA256: e.config.GovernanceQualificationSHA256, MaxTTL: 5 * time.Minute, ClockSkew: 5 * time.Second})
}

func loadEndpoint(base string, c EndpointConfig, governance bool, now func() time.Time) (*endpoint, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.String() != c.Endpoint {
		return nil, ErrConfiguration
	}
	ca, err := readPrivate(resolvePath(base, c.CAPath), 64<<10)
	if err != nil {
		return nil, err
	}
	e := &endpoint{config: c, roots: x509.NewCertPool(), keys: map[string]*ecdsa.PublicKey{}}
	if !e.roots.AppendCertsFromPEM(ca) || !auditrecord.ValidHash(c.QualificationSHA256) || !auditrecord.ValidHash(c.GovernanceQualificationSHA256) || len(c.SigningPublicKeys) > 16 {
		return nil, ErrConfiguration
	}
	paths := make(map[string]string, len(c.SigningPublicKeys)+1)
	for _, key := range c.SigningPublicKeys {
		if paths[key.ID] != "" {
			return nil, ErrConfiguration
		}
		paths[key.ID] = key.Path
	}
	if c.SigningKeyID != "" {
		if paths[c.SigningKeyID] != "" || c.SigningPublicKeyPath == "" {
			return nil, ErrConfiguration
		}
		paths[c.SigningKeyID] = c.SigningPublicKeyPath
	}
	var ids []string
	for id, path := range paths {
		key, err := loadPublicKey(resolvePath(base, path))
		if err != nil {
			return nil, err
		}
		e.keys[id] = key
		ids = append(ids, id)
	}
	e.verifier, err = e.newVerifier(ids)
	if err != nil {
		return nil, ErrConfiguration
	}
	adminTLS, err := clientTLS(base, e.roots, c.Clients.Admin)
	if err != nil {
		return nil, err
	}
	adminConfig := e.clientConfig(adminTLS, "", e.verifier)
	adminConfig.Now = now
	e.admin, err = auditgate.NewClient(adminConfig)
	if err != nil {
		return nil, ErrConfiguration
	}
	e.ready, err = newReadyClient(e.clientConfig(adminTLS, "", e.verifier))
	if err != nil {
		return nil, ErrConfiguration
	}
	if governance {
		ingestTLS, err := clientTLS(base, e.roots, c.Clients.Ingest)
		if err != nil {
			return nil, err
		}
		if auditrecord.Hash(ingestTLS.Certificates[0].Certificate[0]) == auditrecord.Hash(adminTLS.Certificates[0].Certificate[0]) {
			return nil, ErrConfiguration
		}
		e.ingest, err = auditgate.NewClient(e.clientConfig(ingestTLS, "", e.verifier))
		if err != nil {
			return nil, ErrConfiguration
		}
	}
	return e, nil
}
