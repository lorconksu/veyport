package auditingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func TestReadOnlyExporterConfigAndCredentials(t *testing.T) {
	c := configFixture(t)
	u, _ := url.Parse(c.ArchiveEndpoint)
	conn := ExportTLSFiles{Endpoint: c.ArchiveEndpoint, CAPath: c.ArchiveCAPath, CertificatePath: c.TLSCertificatePath, KeyPath: c.TLSKeyPath, AllowedHosts: []string{u.Host}, AllowedAddresses: []string{"127.0.0.1"}}
	config := ExportFileConfig{Index: conn, Search: conn, ArchiveEndpoint: c.ArchiveEndpoint, ArchiveCAPath: c.ArchiveCAPath, ArchiveCredentialsPath: c.ArchiveCredentialsPath, QualificationPaths: []string{c.QualificationPath, c.GovernanceQualificationPath}, QualificationSHA256s: []string{c.QualificationSHA256, c.GovernanceQualificationSHA256}, CheckpointPath: filepath.Join(t.TempDir(), "checkpoint.json")}
	path := filepath.Join(t.TempDir(), "export-config.json")
	write := func(value ExportFileConfig) {
		b, _ := json.Marshal(value)
		if os.WriteFile(path, b, 0600) != nil {
			t.Fatal("write")
		}
	}
	write(config)
	worker, err := LoadExporter(path)
	if err != nil || len(worker.Archives) != 2 {
		t.Fatal("read-only config construction failed")
	}
	for _, change := range []func(*ExportFileConfig){func(c *ExportFileConfig) { c.Index.KeyPath = "/missing" }, func(c *ExportFileConfig) { c.Search.AllowedHosts = []string{"other:443"} }, func(c *ExportFileConfig) { c.ArchiveCAPath = "/missing" }, func(c *ExportFileConfig) { c.ArchiveCredentialsPath = "/missing" }, func(c *ExportFileConfig) { c.QualificationPaths = []string{"/missing", "/missing"} }, func(c *ExportFileConfig) {
		c.QualificationSHA256s = []string{auditrecord.Hash(nil), auditrecord.Hash(nil)}
	}, func(c *ExportFileConfig) { c.ArchiveEndpoint = "http://127.0.0.1" }} {
		bad := config
		change(&bad)
		write(bad)
		if _, err := LoadExporter(path); err == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
	write(config)
	os.Chmod(path, 0644)
	if _, err := LoadExporter(path); err == nil {
		t.Fatal("public secret config accepted")
	}
}

func TestHTTPIndexAndSinkBodiesRemainPrivate(t *testing.T) {
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if r.URL.Path == "/v1/export-index" {
			_, _ = w.Write([]byte(`{"records":[]}`))
		} else {
			_, _ = w.Write([]byte("SYNTHETIC_SECRET_error_body"))
		}
	}))
	defer server.Close()
	index := HTTPProjectionIndex{server.Client(), server.URL}
	if _, err := index.Page(context.Background(), "", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := index.Page(context.Background(), "../raw", 1); err == nil {
		t.Fatal("arbitrary cursor accepted")
	}
	sink := HTTPProjectionSink{server.Client(), server.URL}
	if sink.Send(context.Background(), Projection{}) != nil {
		t.Fatal("success rejected")
	}
	status = http.StatusServiceUnavailable
	if _, err := index.Page(context.Background(), "", 1); err == nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
		t.Fatal("index error leak")
	}
	if err := sink.Send(context.Background(), Projection{}); err == nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
		t.Fatal("sink error leak")
	}
}

type brokenIndex struct {
	page ExportPage
	err  error
}

func (i brokenIndex) Page(context.Context, string, int) (ExportPage, error) { return i.page, i.err }

func TestExporterRefusesCorruptionAndBoundsRetention(t *testing.T) {
	s, a, _, now := testService(t)
	raw, _ := testRecord(t, now, nil)
	r, err := s.Preserve(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	ref := ExportReference{"event-1", auditrecord.ExecutionAdmission, auditrecord.Hash(raw), r.Manifest}
	worker := &Exporter{Index: brokenIndex{page: ExportPage{Records: []ExportReference{ref}}}, Archives: map[string]ProjectionReader{a.q.Bucket: a}, Sink: &memorySink{docs: map[string]Projection{}}, Now: func() time.Time { return now }}
	ref.Manifest.RetainUntil = now.Add(-time.Second)
	worker.Index = brokenIndex{page: ExportPage{Records: []ExportReference{ref}}}
	if worker.Step(context.Background()) != nil || worker.Checkpoint.Skipped != 1 {
		t.Fatal("expired originals prevented rescan")
	}
	ref.Manifest = r.Manifest
	ref.RecordSHA256 = auditrecord.Hash([]byte("wrong"))
	worker.Index = brokenIndex{page: ExportPage{Records: []ExportReference{ref}}}
	now = now.Add(6 * time.Second)
	if worker.Step(context.Background()) == nil || worker.Checkpoint.Failure != "archive_invalid" {
		t.Fatal("corrupt binding projected")
	}
	now = now.Add(10 * time.Second)
	worker.Index = brokenIndex{page: ExportPage{Next: "invalid-next"}}
	if worker.Step(context.Background()) == nil || worker.Checkpoint.Failure != "index_invalid" {
		t.Fatal("unbounded cursor accepted")
	}
}
