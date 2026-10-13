// Package testaudit supplies an independent TLS receipt service for behavioral
// tests. Its synthetic archive and identities are never deployment evidence.
package testaudit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditingest"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auditruntime"
)

type Clock struct {
	mu     sync.RWMutex
	now    time.Time
	live   bool
	offset time.Duration
}

func NewClock() *Clock { return &Clock{now: time.Now().UTC()} }

// NewRealClock follows wall time for tests that exercise a production worker's
// time.Now calls. NewClock remains fixed until Advance for deterministic tests.
func NewRealClock() *Clock { return &Clock{live: true} }

func (c *Clock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.live {
		return time.Now().UTC().Add(c.offset)
	}
	return c.now
}

func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live {
		c.offset += d
		return
	}
	c.now = c.now.Add(d)
}

type archived struct {
	ref auditrecord.ObjectRef
	raw []byte
}

type Archive struct {
	mu      sync.Mutex
	q       auditingest.Qualification
	objects map[string]archived
	failed  bool
}

func (a *Archive) Qualification() auditingest.Qualification { return a.q }
func (a *Archive) SetFailed(failed bool)                    { a.mu.Lock(); a.failed = failed; a.mu.Unlock() }
func (a *Archive) Ready(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || a.failed {
		return auditingest.ErrUnavailable
	}
	return a.q.Validate()
}
func (a *Archive) Put(ctx context.Context, key string, raw []byte, retain time.Time) (auditrecord.ObjectRef, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || a.failed {
		return auditrecord.ObjectRef{}, auditingest.ErrUnavailable
	}
	if _, exists := a.objects[key]; exists {
		return auditrecord.ObjectRef{}, auditingest.ErrConflict
	}
	ref := auditrecord.ObjectRef{Bucket: a.q.Bucket, Key: key, VersionID: "fixture-" + auditrecord.Hash(raw)[:16], SHA256: auditrecord.Hash(raw), Bytes: int64(len(raw)), RetainUntil: retain}
	a.objects[key] = archived{ref, append([]byte(nil), raw...)}
	return ref, nil
}
func (a *Archive) Find(ctx context.Context, key string) (auditrecord.ObjectRef, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || a.failed {
		return auditrecord.ObjectRef{}, nil, auditingest.ErrUnavailable
	}
	v, exists := a.objects[key]
	if !exists {
		return auditrecord.ObjectRef{}, nil, auditingest.ErrNotFound
	}
	return v.ref, append([]byte(nil), v.raw...), nil
}
func (a *Archive) Verify(ctx context.Context, ref auditrecord.ObjectRef, minimum time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, exists := a.objects[ref.Key]
	if ctx.Err() != nil || a.failed || !exists || auditrecord.Digest(v.ref) != auditrecord.Digest(ref) || ref.RetainUntil.Before(minimum) || auditrecord.Hash(v.raw) != ref.SHA256 {
		return auditingest.ErrUnavailable
	}
	return nil
}
func (a *Archive) Read(ctx context.Context, ref auditrecord.ObjectRef) ([]byte, error) {
	if err := a.Verify(ctx, ref, ref.RetainUntil); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.objects[ref.Key].raw...), nil
}
func (a *Archive) Envelopes() []auditrecord.Envelope {
	a.mu.Lock()
	defer a.mu.Unlock()
	var records []auditrecord.Envelope
	for _, object := range a.objects {
		var e auditrecord.Envelope
		if json.Unmarshal(object.raw, &e) == nil && e.SchemaVersion == 1 && e.EventType != "" {
			records = append(records, e)
		}
	}
	return records
}

func (a *Archive) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || a.failed {
		return nil, auditingest.ErrUnavailable
	}
	var keys []string
	for key := range a.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

type Fixture struct {
	Server     *httptest.Server
	Config     auditruntime.EndpointConfig
	Credential auditruntime.DestinationCredential
	Originals  *Archive
	Governance *Archive
	Clock      *Clock
	mu         sync.RWMutex
	fault      string
	opened     atomic.Int64
	live       atomic.Int64
}

func (f *Fixture) SetFault(fault string) { f.mu.Lock(); f.fault = fault; f.mu.Unlock() }
func (f *Fixture) currentFault() string  { f.mu.RLock(); defer f.mu.RUnlock(); return f.fault }
func (f *Fixture) Connections() (opened, live int64) {
	return f.opened.Load(), f.live.Load()
}

func qualification(bucket string, seconds uint64) auditingest.Qualification {
	return auditingest.Qualification{SchemaVersion: 1, ArchiveEndpoint: "https://synthetic-archive.invalid", ArchiveVersion: "test-only", Bucket: bucket, KMSKeyID: "synthetic-test-key", DefaultRetentionSeconds: seconds, ConfigurationSHA256: auditrecord.Hash([]byte(bucket + "-configuration")), ReportSHA256: auditrecord.Hash([]byte(bucket + "-report")), Digest: auditrecord.Hash([]byte(bucket + "-qualification")), VerifiedAt: time.Now().UTC(), Checks: []string{"versioning", "compliance_retention", "sse_kms", "exact_version_reads", "conditional_create", "writer_no_delete", "writer_no_retention_reduction", "acknowledged_write_process_crash", "acknowledged_write_power_loss", "encrypted_backup_restore", "key_restore"}}
}

func New(t testing.TB, clock *Clock) *Fixture {
	return newWithSigningKey(t, clock, nil)
}

// NewWithSigningKey lets a native integration test inject signed receipt faults
// using the same synthetic trust key as this TLS service. It is test support;
// callers still use the real scoped clients, qualification and verifier.
func NewWithSigningKey(t testing.TB, clock *Clock, key *ecdsa.PrivateKey) *Fixture {
	t.Helper()
	if key == nil || key.Curve != elliptic.P256() || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(key.Params().N) >= 0 || !key.Curve.IsOnCurve(key.X, key.Y) {
		t.Fatal("synthetic receipt signer must be a valid standard P-256 key")
	}
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		t.Fatal("synthetic receipt signer public and private keys differ")
	}
	return newWithSigningKey(t, clock, key)
}

func newWithSigningKey(t testing.TB, clock *Clock, key *ecdsa.PrivateKey) *Fixture {
	t.Helper()
	if clock == nil {
		clock = NewClock()
	}
	var err error
	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic receipt fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca.Raw = caDER
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	cert := func(serial int64, server bool) ([]byte, []byte, tls.Certificate) {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "synthetic receipt client"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &private.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return certPEM, keyPEM, pair
	}
	_, _, serverPair := cert(2, true)
	ingestCert, ingestKey, ingestPair := cert(3, false)
	adminCert, adminKey, adminPair := cert(4, false)
	readerCert, readerKey, readerPair := cert(5, false)
	f := &Fixture{Clock: clock, Originals: &Archive{q: qualification("synthetic-originals", 2*86400), objects: map[string]archived{}}, Governance: &Archive{q: qualification("synthetic-governance", 3651*86400), objects: map[string]archived{}}}
	service, err := auditingest.NewService(auditingest.ServiceConfig{Issuer: "synthetic-receipt", Audience: "synthetic-hub", Retention: 24 * time.Hour, GovernanceRetention: 3650 * 24 * time.Hour, ReceiptTTL: time.Minute, Timeout: 5 * time.Second, Concurrency: 4, Signer: auditingest.Signer{KeyID: "fixture-key", Key: key}, Archive: f.Originals, GovernanceArchive: f.Governance, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := auditingest.NewAuthenticator([]auditingest.Credential{{ID: "fixture-ingest", Scope: auditingest.ScopeIngest, CertificateSHA256: auditrecord.Hash(ingestPair.Certificate[0])}, {ID: "fixture-admin", Scope: auditingest.ScopeAdmin, CertificateSHA256: auditrecord.Hash(adminPair.Certificate[0])}, {ID: "fixture-reader", Scope: auditingest.ScopeRead, CertificateSHA256: auditrecord.Hash(readerPair.Certificate[0])}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := auditingest.NewHandler(service, authenticator, 4)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fault := f.currentFault()
		if fault == "admin-auth" && r.Method == "GET" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if fault == "ready" && r.URL.Path == "/v1/ready" || fault == "anchor" && strings.HasPrefix(r.URL.Path, "/v1/anchors/") || (fault == "lookup" || fault == "result-uncertain") && strings.HasPrefix(r.URL.Path, "/v1/records/") || fault == "ingest" && r.Method == "POST" {
			w.WriteHeader(503)
			return
		}
		var body []byte
		if r.Method == "POST" && (strings.HasPrefix(fault, "lose-") || fault == "result-uncertain") {
			body, _ = io.ReadAll(r.Body)
			r.Body.Close()
			r.Body = io.NopCloser(strings.NewReader(string(body)))
		}
		if (fault == "receipt" || fault == "manifest" || fault == "expired-receipt") && r.Method == "POST" {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)
			if recorder.Code != 200 {
				w.WriteHeader(recorder.Code)
				return
			}
			var receipt auditrecord.Receipt
			_ = json.Unmarshal(recorder.Body.Bytes(), &receipt)
			if fault == "receipt" {
				receipt.Token = "invalid.signature.receipt"
			}
			if fault == "manifest" {
				receipt.Manifest.VersionID = "tampered-reference"
			}
			if fault == "expired-receipt" {
				f.Clock.Advance(2 * time.Minute)
			}
			_ = json.NewEncoder(w).Encode(receipt)
			return
		}
		if (strings.HasPrefix(fault, "lose-") && strings.Contains(string(body), `"event_type":"`+strings.TrimPrefix(fault, "lose-")+`"`)) || (fault == "result-uncertain" && strings.Contains(string(body), `"event_type":"policy.result"`)) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)
			w.WriteHeader(503)
			return
		}
		handler.ServeHTTP(w, r)
	})
	f.Server = httptest.NewUnstartedServer(wrapped)
	f.Server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			f.opened.Add(1)
			f.live.Add(1)
		} else if state == http.StateClosed {
			f.live.Add(-1)
		}
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	f.Server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	f.Server.StartTLS()
	t.Cleanup(f.Server.Close)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f.Config = auditruntime.EndpointConfig{Endpoint: f.Server.URL, AllowedAddresses: []string{"127.0.0.1"}, Issuer: "synthetic-receipt", Audience: "synthetic-hub", SigningKeyID: "fixture-key", SigningPublicKeyPath: write("signer.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})), CAPath: write("ca.pem", caPEM), QualificationSHA256: f.Originals.q.Digest, GovernanceQualificationSHA256: f.Governance.q.Digest, Clients: auditruntime.ClientSet{Ingest: auditruntime.ClientFiles{CertificatePath: write("ingest.pem", ingestCert), KeyPath: write("ingest-key.pem", ingestKey)}, Admin: auditruntime.ClientFiles{CertificatePath: write("admin.pem", adminCert), KeyPath: write("admin-key.pem", adminKey)}, OriginalReader: auditruntime.ClientFiles{CertificatePath: write("reader.pem", readerCert), KeyPath: write("reader-key.pem", readerKey)}}}
	f.Credential = auditruntime.DestinationCredential{CertificatePEM: string(ingestCert), PrivateKeyPEM: string(ingestKey)}
	return f
}

func (f *Fixture) ConfigFile(t testing.TB, destinations ...auditruntime.EndpointConfig) string {
	t.Helper()
	raw, err := json.Marshal(auditruntime.FileConfig{EndpointConfig: f.Config, Destinations: destinations})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
