package auditruntime

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/proto/protectedinput"
)

type Options struct {
	Store             *store.Store
	Spool             protectedinput.Store
	GatewayReady      func() bool
	SupportsProtected func(string) bool
	ResolveSecret     func(string) (kind, value string, err error)
	Now               func() time.Time
}

type Runtime struct {
	governance   *endpoint
	destinations map[string]*endpoint
	options      Options
	archiveMu    sync.Mutex
	archives     map[string]*cachedArchive
	archiveTick  uint64
}

const maxArchiveClients = 32

type cachedArchive struct {
	client   *auditgate.Client
	verifier *auditgate.Verifier
	used     uint64
}

func Load(path string, options Options) (*Runtime, error) {
	raw, err := readPrivate(path, 256<<10)
	if err != nil {
		return nil, err
	}
	var config FileConfig
	if auditrecord.Decode(raw, &config, 256<<10) != nil || len(config.Destinations) > 16 {
		return nil, ErrConfiguration
	}
	base := filepath.Dir(path)
	governance, err := loadEndpoint(base, config.EndpointConfig, true, options.Now)
	if err != nil {
		return nil, ErrConfiguration
	}
	runtime := &Runtime{governance: governance, destinations: map[string]*endpoint{config.Endpoint: governance}, options: options, archives: map[string]*cachedArchive{}}
	for _, destination := range config.Destinations {
		if runtime.destinations[destination.Endpoint] != nil {
			return nil, ErrConfiguration
		}
		e, err := loadEndpoint(base, destination, false, options.Now)
		if err != nil {
			return nil, ErrConfiguration
		}
		runtime.destinations[destination.Endpoint] = e
	}
	return runtime, nil
}

func (r *Runtime) AllowedHosts() []string {
	var hosts []string
	for destination := range r.destinations {
		u, _ := url.Parse(destination)
		hosts = append(hosts, u.Host)
	}
	return hosts
}

func (r *Runtime) Evidence() *authorization.ReceiptEvidence {
	return &authorization.ReceiptEvidence{Ingest: r.governance.ingest, Admin: r.governance.admin, Verifier: r.governance.verifier, TransportReady: r.transportReady, PolicyReady: r.policyReady, CandidateTest: r.Test, Now: r.now}
}

func (r *Runtime) now() time.Time {
	if r.options.Now != nil {
		return r.options.Now()
	}
	return time.Now().UTC()
}

func (r *Runtime) policyReady(ctx context.Context, p model.AuditPolicy) error {
	if err := r.governance.ready.check(ctx, r.governance.config, 24*time.Hour, true); err != nil {
		return err
	}
	if p.Profile == "standard" {
		return nil
	}
	_, endpoint, err := r.archive(p)
	if err != nil {
		return err
	}
	return endpoint.ready.check(ctx, endpoint.config, time.Duration(p.RetentionHours)*time.Hour, false)
}

func (r *Runtime) transportReady(ctx context.Context, p model.AuditPolicy) error {
	if ctx.Err() != nil || r.options.Store == nil || r.options.Spool == nil || r.options.Spool.Ready() != nil || r.options.GatewayReady == nil || !r.options.GatewayReady() || r.options.SupportsProtected == nil {
		return authorization.ErrNotReady
	}
	return r.checkScopedNodes(ctx, p)
}

// Stream only identifiers in bounded pages. Actor scope is OR node scope:
// an operations administrator can reach all nodes; other actors contribute
// their assigned nodes even when no explicit node appears in policy.Nodes.
func (r *Runtime) checkScopedNodes(ctx context.Context, p model.AuditPolicy) error {
	if len(p.Actors) > 1000 || len(p.Nodes) > 1000 {
		return authorization.ErrNotReady
	}
	args := []any{len(p.Actors) == 0 && len(p.Nodes) == 0}
	clauses := []string{"?"}
	placeholders := func(ids []string) string {
		for _, id := range ids {
			args = append(args, id)
		}
		return strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	}
	if len(p.Nodes) > 0 {
		clauses = append(clauses, "s.id IN ("+placeholders(p.Nodes)+")")
	}
	if len(p.Actors) > 0 {
		clauses = append(clauses, "EXISTS (SELECT 1 FROM permissions a WHERE a.server_id=s.id AND a.user_id IN ("+placeholders(p.Actors)+"))")
		clauses = append(clauses, "EXISTS (SELECT 1 FROM user_roles r WHERE r.role='admin' AND r.user_id IN ("+placeholders(p.Actors)+"))")
	}
	explicit := make(map[string]bool, len(p.Nodes))
	for _, id := range p.Nodes {
		explicit[id] = false
	}
	last := ""
	total := 0
	for {
		pageArgs := append(append([]any(nil), args...), last)
		rows, err := r.options.Store.DB().QueryContext(ctx, "SELECT s.id FROM servers s WHERE ("+strings.Join(clauses, " OR ")+") AND s.id>? ORDER BY s.id LIMIT 256", pageArgs...)
		if err != nil {
			return authorization.ErrNotReady
		}
		count := 0
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return authorization.ErrNotReady
			}
			if ctx.Err() != nil || !r.options.SupportsProtected(id) {
				rows.Close()
				return authorization.ErrNotReady
			}
			if _, requested := explicit[id]; requested {
				explicit[id] = true
			}
			last = id
			count++
			total++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return authorization.ErrNotReady
		}
		if count < 256 {
			break
		}
	}
	for _, present := range explicit {
		if !present {
			return authorization.ErrNotReady
		}
	}
	if total == 0 {
		return authorization.ErrNotReady
	}
	return nil
}

// DestinationCredential is stored as the exact value of a versioned,
// write-only destination secret. Policy changes reference its immutable ID.
type DestinationCredential struct {
	Bearer         string `json:"bearer,omitempty"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
}

func (e *endpoint) clientConfig(tlsConfig *tls.Config, bearer string, verifier *auditgate.Verifier) auditgate.ClientConfig {
	u, _ := url.Parse(e.config.Endpoint)
	return auditgate.ClientConfig{Endpoint: e.config.Endpoint, AllowedHosts: []string{u.Host}, AllowedAddresses: e.config.AllowedAddresses, TLS: tlsConfig, Bearer: bearer, Verifier: verifier}
}

func (r *Runtime) archive(p model.AuditPolicy) (auditgate.Gate, *endpoint, error) {
	e := r.destinations[p.Destination]
	if e == nil || p.QualificationSHA256 != e.config.QualificationSHA256 || r.options.ResolveSecret == nil || p.CredentialRef == "" || p.RetentionHours < 24 || p.RetentionHours > 3650*24 {
		return auditgate.Gate{}, nil, authorization.ErrNotReady
	}
	verifier, err := e.newVerifier(p.TrustKeyIDs)
	if err != nil {
		return auditgate.Gate{}, nil, authorization.ErrNotReady
	}
	kind, value, err := r.options.ResolveSecret(p.CredentialRef)
	var credential DestinationCredential
	if err != nil || kind != "destination" || auditrecord.Decode([]byte(value), &credential, 64<<10) != nil {
		return auditgate.Gate{}, nil, authorization.ErrNotReady
	}
	tlsConfig := &tls.Config{RootCAs: e.roots, MinVersion: tls.VersionTLS12}
	if credential.Bearer != "" {
		if len(credential.Bearer) < 32 || len(credential.Bearer) > 512 || credential.CertificatePEM != "" || credential.PrivateKeyPEM != "" {
			return auditgate.Gate{}, nil, authorization.ErrNotReady
		}
	} else {
		pair, err := tls.X509KeyPair([]byte(credential.CertificatePEM), []byte(credential.PrivateKeyPEM))
		if err != nil {
			return auditgate.Gate{}, nil, authorization.ErrNotReady
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	// Cache only exact immutable policy, credential bytes and trust combinations.
	// Resolve the reference before every lookup so missing/decryption-failed state
	// cannot keep using a cached credential after restoration or key loss.
	key := auditrecord.Digest(struct {
		Policy        model.AuditPolicy `json:"policy"`
		CredentialSHA string            `json:"credential_sha256"`
	}{p, auditrecord.Hash([]byte(value))})
	r.archiveMu.Lock()
	defer r.archiveMu.Unlock()
	r.archiveTick++
	if cached := r.archives[key]; cached != nil {
		cached.used = r.archiveTick
		return auditgate.Gate{Preserver: cached.client, Verifier: cached.verifier}, e, nil
	}
	client, err := auditgate.NewClient(e.clientConfig(tlsConfig, credential.Bearer, verifier))
	if err != nil {
		return auditgate.Gate{}, nil, authorization.ErrNotReady
	}
	if len(r.archives) == maxArchiveClients {
		var oldestKey string
		var oldest *cachedArchive
		for id, cached := range r.archives {
			if oldest == nil || cached.used < oldest.used {
				oldestKey, oldest = id, cached
			}
		}
		oldest.client.CloseIdleConnections()
		delete(r.archives, oldestKey)
	}
	r.archives[key] = &cachedArchive{client: client, verifier: verifier, used: r.archiveTick}
	return auditgate.Gate{Preserver: client, Verifier: verifier}, e, nil
}

// Close releases retained idle connections. Existing in-flight requests keep
// their exact client and are not replaced or canceled by cache eviction.
func (r *Runtime) Close() {
	r.archiveMu.Lock()
	defer r.archiveMu.Unlock()
	for key, cached := range r.archives {
		cached.client.CloseIdleConnections()
		delete(r.archives, key)
	}
	for _, e := range r.destinations {
		e.admin.CloseIdleConnections()
		e.ready.client.CloseIdleConnections()
		if e.ingest != nil {
			e.ingest.CloseIdleConnections()
		}
	}
}

// ResolveArchive binds the gateway to this exact stored policy version. Live
// policy selection happens in authorization; this never substitutes a destination
// or credential from a newer policy for old admission/lifecycle evidence.
func (r *Runtime) ResolveArchive(ctx context.Context, p model.PolicyVersion) (auditgate.Gate, error) {
	if ctx.Err() != nil || p.Version == 0 || p.SHA256 != auditrecord.Digest(p.Policy) {
		return auditgate.Gate{}, authorization.ErrNotReady
	}
	gate, e, err := r.archive(p.Policy)
	if err != nil {
		return gate, err
	}
	if err := e.ready.check(ctx, e.config, time.Duration(p.Policy.RetentionHours)*time.Hour, false); err != nil {
		return auditgate.Gate{}, err
	}
	return gate, nil
}

// Test creates an explicitly synthetic completed lifecycle record. It sends no
// command, attachments, execution permit or claimed human approval, and launches
// no process. A signed exact-record receipt proves protected write and retention.
func (r *Runtime) Test(ctx context.Context, p model.AuditPolicy) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	gate, e, err := r.archive(p)
	if err != nil {
		return err
	}
	retention := time.Duration(p.RetentionHours) * time.Hour
	if err := e.ready.check(ctx, e.config, retention, false); err != nil {
		return err
	}
	now := r.now()
	id := "qualification-" + uuid.NewString()
	hash := auditrecord.Hash([]byte("synthetic-readiness-probe"))
	binding := &auditrecord.ExecutionBinding{ExecutionID: id, PreparationID: id, BootID: "synthetic-readiness", NodeID: "synthetic-readiness", NodeName: "synthetic readiness test; no process launched", CommandSHA256: hash, CommandBytes: 25, PreparedUntil: now, Identity: auditrecord.Identity{Username: "synthetic-readiness", UID: 1, GID: 1, Home: "/", Shell: "/bin/sh", CWD: "/", Groups: []uint32{1}, GroupsSHA256: hash, IdentitySHA256: hash}, Limits: auditrecord.Limits{MaxFrameBytes: 65536, MaxBufferBytes: 2097152, RuntimeSeconds: 1, TermGraceSeconds: 1, BlockedConsumerSeconds: 1}}
	envelope := auditrecord.Envelope{SchemaVersion: 1, EventID: id, EventType: auditrecord.ExecutionLifecycle, Actor: auditrecord.Actor{UserID: "synthetic-readiness", PersonID: "synthetic-readiness", Name: "Archive readiness probe", Provider: "system", Subject: "synthetic-readiness"}, Execution: binding, PolicyVersion: 1, PolicySHA256: auditrecord.Digest(p), OccurredAt: now, Details: &auditrecord.Details{CorrelationID: id, State: "synthetic-readiness-no-process"}}
	raw, _ := json.Marshal(envelope)
	expected, _, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return err
	}
	expected.MinRetainUntil = now.Add(retention)
	receipt, err := gate.Preserver.Preserve(ctx, raw, nil)
	if err != nil {
		return authorization.ErrNotReady
	}
	claims, err := gate.Verifier.Verify(receipt.Token, expected, r.now())
	if err != nil || auditrecord.Digest(claims.Manifest) != auditrecord.Digest(receipt.Manifest) {
		return authorization.ErrNotReady
	}
	return nil
}

type readyResponse struct {
	Ready                         bool   `json:"ready"`
	ArchiveReady                  *bool  `json:"archive_ready,omitempty"`
	GovernanceReady               *bool  `json:"governance_ready,omitempty"`
	QualificationSHA256           string `json:"qualification_sha256"`
	GovernanceQualificationSHA256 string `json:"governance_qualification_sha256"`
	RetentionSeconds              int64  `json:"retention_seconds"`
	GovernanceRetentionSeconds    int64  `json:"governance_retention_seconds"`
}

type readyClient struct {
	client   *http.Client
	endpoint string
}

func newReadyClient(c auditgate.ClientConfig) (*readyClient, error) {
	client, err := auditgate.NewTLSClient(auditgate.TransportConfig{Endpoint: c.Endpoint, AllowedHosts: c.AllowedHosts, AllowedAddresses: c.AllowedAddresses, TLS: c.TLS, Timeout: 5 * time.Second, Connections: 2})
	if err != nil {
		return nil, err
	}
	return &readyClient{client, c.Endpoint}, nil
}

func (c *readyClient) check(ctx context.Context, config EndpointConfig, retention time.Duration, governanceOnly bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/v1/ready", nil)
	if err != nil {
		return authorization.ErrNotReady
	}
	response, err := c.client.Do(req)
	if err != nil {
		return authorization.ErrNotReady
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return authorization.ErrNotReady
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	var status readyResponse
	if err != nil || auditrecord.Decode(raw, &status, 4096) != nil || status.QualificationSHA256 != config.QualificationSHA256 || status.GovernanceQualificationSHA256 != config.GovernanceQualificationSHA256 || status.GovernanceRetentionSeconds < 3650*86400 {
		return authorization.ErrNotReady
	}
	archiveReady, governanceReady := status.Ready, status.Ready
	if status.ArchiveReady != nil {
		archiveReady = *status.ArchiveReady
	}
	if status.GovernanceReady != nil {
		governanceReady = *status.GovernanceReady
	}
	if !governanceReady || !governanceOnly && (!archiveReady || status.RetentionSeconds < int64(retention/time.Second)) {
		return authorization.ErrNotReady
	}
	return nil
}
