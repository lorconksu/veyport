package auditingest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type ProjectionReader interface {
	Read(context.Context, auditrecord.ObjectRef) ([]byte, error)
}
type ProjectionIndex interface {
	Page(context.Context, string, int) (ExportPage, error)
}
type ProjectionSink interface {
	Send(context.Context, Projection) error
}

type ExportCheckpoint struct {
	Cursor               string    `json:"cursor"`
	Accepted             uint64    `json:"accepted"`
	Skipped              uint64    `json:"skipped"`
	LastAcceptedAt       time.Time `json:"last_accepted_at"`
	LastCycleCompletedAt time.Time `json:"last_cycle_completed_at"`
	AttemptedAt          time.Time `json:"attempted_at"`
	Failure              string    `json:"failure,omitempty"`
	Failures             uint32    `json:"failures"`
	RetryAt              time.Time `json:"retry_at"`
	PendingOccurredAt    time.Time `json:"pending_occurred_at,omitempty"`
}

type Exporter struct {
	Index          ProjectionIndex
	Archives       map[string]ProjectionReader
	Sink           ProjectionSink
	CheckpointPath string
	Checkpoint     ExportCheckpoint
	Now            func() time.Time
}

func (e *Exporter) fail(code string, now time.Time) error {
	e.Checkpoint.Failure = code
	if e.Checkpoint.Failures < 7 {
		e.Checkpoint.Failures++
	}
	e.Checkpoint.RetryAt = now.Add(time.Duration(1<<e.Checkpoint.Failures) * time.Second)
	_ = e.save()
	return ErrUnavailable
}

// Step holds only one bounded index page and one envelope. Checkpoints contain
// metadata only. A Logstash HTTP acknowledgment means accepted, not indexed;
// each completed pass restarts enumeration so deletion/outage is replayable.
func (e *Exporter) Step(ctx context.Context) error {
	if e.Index == nil || e.Sink == nil || len(e.Archives) == 0 {
		return ErrUnavailable
	}
	now := time.Now().UTC()
	if e.Now != nil {
		now = e.Now().UTC()
	}
	if now.Before(e.Checkpoint.RetryAt) {
		return ErrBusy
	}
	e.Checkpoint.AttemptedAt = now
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	page, err := e.Index.Page(ctx, e.Checkpoint.Cursor, 8)
	if err != nil || len(page.Records) > MaxExportPage {
		return e.fail("index_unavailable", now)
	}
	prior := e.Checkpoint.Cursor
	for _, ref := range page.Records {
		if !ref.valid() || ref.EventID <= prior {
			return e.fail("index_invalid", now)
		}
		prior = ref.EventID
		if ref.expired(now) {
			e.Checkpoint.Skipped++
			continue
		}
		archive := e.Archives[ref.Manifest.Bucket]
		if archive == nil {
			return e.fail("archive_unavailable", now)
		}
		manifestBytes, err := archive.Read(ctx, ref.Manifest)
		var m auditrecord.Manifest
		if err != nil || auditrecord.Decode(manifestBytes, &m, auditrecord.MaxEnvelopeBytes) != nil || m.SchemaVersion != 1 || m.EventID != ref.EventID || m.RecordSHA256 != ref.RecordSHA256 || !m.Envelope.Valid() || m.Envelope.Bucket != ref.Manifest.Bucket || m.Envelope.SHA256 != ref.RecordSHA256 || m.Envelope.Bytes > auditrecord.MaxEnvelopeBytes || !m.RetainUntil.Equal(ref.Manifest.RetainUntil) || !m.Envelope.RetainUntil.Equal(m.RetainUntil) {
			return e.fail("archive_invalid", now)
		}
		raw, err := archive.Read(ctx, m.Envelope)
		if err != nil {
			return e.fail("archive_unavailable", now)
		}
		p, err := Project(raw, ref)
		if err != nil {
			return e.fail("projection_invalid", now)
		}
		// Seven days limits the search projection, independently of raw retention.
		if p.Timestamp.Before(now.Add(-7 * 24 * time.Hour)) {
			e.Checkpoint.Skipped++
			continue
		}
		e.Checkpoint.PendingOccurredAt = p.Timestamp
		if e.Sink.Send(ctx, p) != nil {
			return e.fail("search_unavailable", now)
		}
		e.Checkpoint.Accepted++
		e.Checkpoint.LastAcceptedAt = now
	}
	if page.Next != "" && (len(page.Records) == 0 || page.Next != prior) {
		return e.fail("index_invalid", now)
	}
	e.Checkpoint.Cursor = page.Next
	if page.Next == "" {
		e.Checkpoint.LastCycleCompletedAt = now
	}
	e.Checkpoint.Failure = ""
	e.Checkpoint.Failures = 0
	e.Checkpoint.PendingOccurredAt = time.Time{}
	e.Checkpoint.RetryAt = now.Add(5 * time.Second)
	if e.save() != nil {
		return e.fail("checkpoint_unavailable", now)
	}
	return nil
}

func (e *Exporter) LoadCheckpoint() error {
	if e.CheckpointPath == "" {
		return nil
	}
	if _, err := os.Lstat(e.CheckpointPath); os.IsNotExist(err) {
		return nil
	}
	b, err := ReadPrivateFile(e.CheckpointPath, 4096)
	if err != nil || auditrecord.Decode(b, &e.Checkpoint, 4096) != nil || e.Checkpoint.Cursor != "" && !auditrecord.ValidID(e.Checkpoint.Cursor) || e.Checkpoint.Failures > 7 {
		return ErrUnavailable
	}
	return nil
}

func (e *Exporter) save() error {
	if e.CheckpointPath == "" {
		return nil
	}
	b, err := json.Marshal(e.Checkpoint)
	if err != nil {
		return ErrUnavailable
	}
	dir := filepath.Dir(e.CheckpointPath)
	f, err := os.CreateTemp(dir, ".export-checkpoint-")
	if err != nil {
		return ErrUnavailable
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return ErrUnavailable
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return ErrUnavailable
	}
	if f.Close() != nil || os.Rename(name, e.CheckpointPath) != nil {
		return ErrUnavailable
	}
	d, err := os.Open(dir)
	if err != nil {
		return ErrUnavailable
	}
	defer d.Close()
	return d.Sync()
}

type HTTPProjectionIndex struct {
	Client   *http.Client
	Endpoint string
}

func (i HTTPProjectionIndex) Page(ctx context.Context, after string, limit int) (ExportPage, error) {
	if after != "" && !auditrecord.ValidID(after) || limit < 1 || limit > MaxExportPage {
		return ExportPage{}, ErrUnavailable
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, i.Endpoint+"/v1/export-index?after="+url.QueryEscape(after)+"&limit="+strconv.Itoa(limit), nil)
	if err != nil || i.Client == nil {
		return ExportPage{}, ErrUnavailable
	}
	response, err := i.Client.Do(r)
	if err != nil {
		return ExportPage{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ExportPage{}, ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, (128<<10)+1))
	var page ExportPage
	if err != nil || auditrecord.Decode(b, &page, 128<<10) != nil {
		return ExportPage{}, ErrUnavailable
	}
	return page, nil
}

type HTTPProjectionSink struct {
	Client   *http.Client
	Endpoint string
}

func (s HTTPProjectionSink) Send(ctx context.Context, p Projection) error {
	b, err := p.JSON()
	if err != nil || len(b) > 8192 || s.Client == nil {
		return ErrUnavailable
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, bytes.NewReader(b))
	if err != nil {
		return ErrUnavailable
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := s.Client.Do(r)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	// Never dump a server's error body or echo rejected document bytes.
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrUnavailable
	}
	return nil
}

type ExportTLSFiles struct {
	Endpoint         string   `json:"endpoint"`
	CAPath           string   `json:"ca_path"`
	CertificatePath  string   `json:"certificate_path"`
	KeyPath          string   `json:"key_path"`
	AllowedHosts     []string `json:"allowed_hosts"`
	AllowedAddresses []string `json:"allowed_addresses"`
}

func (c ExportTLSFiles) client() (*http.Client, error) {
	ca, err := readPublicFile(c.CAPath, 64<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, ErrUnavailable
	}
	cert, err := readPublicFile(c.CertificatePath, 64<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	key, err := ReadPrivateFile(c.KeyPath, 16<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, ErrUnavailable
	}
	return auditgate.NewTLSClient(auditgate.TransportConfig{Endpoint: c.Endpoint, AllowedHosts: c.AllowedHosts, AllowedAddresses: c.AllowedAddresses, TLS: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, Timeout: 10 * time.Second, Connections: 1})
}

type ExportFileConfig struct {
	ReplayIndex            string         `json:"replay_index,omitempty"`
	Index                  ExportTLSFiles `json:"index"`
	Search                 ExportTLSFiles `json:"search"`
	ArchiveEndpoint        string         `json:"archive_endpoint"`
	ArchiveCAPath          string         `json:"archive_ca_path"`
	ArchiveCredentialsPath string         `json:"archive_credentials_path"`
	QualificationPaths     []string       `json:"qualification_paths"`
	QualificationSHA256s   []string       `json:"qualification_sha256s"`
	CheckpointPath         string         `json:"checkpoint_path"`
}

func LoadExporter(path string) (*Exporter, error) {
	b, err := ReadPrivateFile(path, 64<<10)
	var c ExportFileConfig
	if err != nil || auditrecord.Decode(b, &c, 64<<10) != nil || len(c.QualificationPaths) != 2 || len(c.QualificationSHA256s) != 2 || c.CheckpointPath == "" || c.ReplayIndex != "" && (!strings.HasPrefix(c.ReplayIndex, "veyport-replay-") || !auditrecord.ValidID(c.ReplayIndex) || strings.ToLower(c.ReplayIndex) != c.ReplayIndex) {
		return nil, ErrUnavailable
	}
	index, err := c.Index.client()
	if err != nil {
		return nil, ErrUnavailable
	}
	search, err := c.Search.client()
	if err != nil {
		return nil, ErrUnavailable
	}
	ca, err := readPublicFile(c.ArchiveCAPath, 64<<10)
	if err != nil {
		return nil, ErrUnavailable
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, ErrUnavailable
	}
	secret, err := ReadPrivateFile(c.ArchiveCredentialsPath, 16<<10)
	var cred struct {
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	if err != nil || auditrecord.Decode(secret, &cred, 16<<10) != nil || cred.AccessKey == "" || cred.SecretKey == "" {
		return nil, ErrUnavailable
	}
	u, err := url.Parse(c.ArchiveEndpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, ErrUnavailable
	}
	transport, err := auditgate.NewTLSClient(auditgate.TransportConfig{Endpoint: c.ArchiveEndpoint, AllowedHosts: []string{u.Host}, AllowedAddresses: []string{u.Hostname()}, TLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, Timeout: 10 * time.Second, Connections: 1})
	if err != nil {
		return nil, ErrUnavailable
	}
	searchEndpoint := c.Search.Endpoint
	if c.ReplayIndex != "" {
		searchEndpoint += "/replay/" + c.ReplayIndex
	}
	e := &Exporter{Index: HTTPProjectionIndex{index, c.Index.Endpoint}, Sink: HTTPProjectionSink{search, searchEndpoint}, Archives: map[string]ProjectionReader{}, CheckpointPath: c.CheckpointPath}
	for n, path := range c.QualificationPaths {
		body, err := readPublicFile(path, 64<<10)
		if err != nil {
			return nil, ErrUnavailable
		}
		q, err := LoadQualification(body, c.QualificationSHA256s[n])
		if err != nil || q.ArchiveEndpoint != c.ArchiveEndpoint {
			return nil, ErrUnavailable
		}
		// This read-only identity cannot inspect/mutate bucket configuration. Every
		// exact read still verifies version/hash/KMS/compliance/qualification pins.
		api := s3.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(cred.AccessKey, cred.SecretKey, ""), HTTPClient: transport, RetryMaxAttempts: 1, RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired, ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired}, func(o *s3.Options) { o.BaseEndpoint = aws.String(c.ArchiveEndpoint); o.UsePathStyle = true })
		e.Archives[q.Bucket] = &S3Archive{config: S3Config{Bucket: q.Bucket, KMSKeyID: q.KMSKeyID, Qualification: q}, api: api}
	}
	if e.LoadCheckpoint() != nil {
		return nil, ErrUnavailable
	}
	return e, nil
}
