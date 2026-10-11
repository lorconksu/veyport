package main

import (
	"bytes"
	"context"
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
	"time"

	"github.com/wyiu/veyport/hub/internal/auditingest"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func TestVersionDoesNotLoadPrivateConfiguration(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--version", "--config", "/missing/private/config"}, &out); err != nil || strings.TrimSpace(out.String()) != version {
		t.Fatal("side-effect-free version unavailable")
	}
}

func TestConfigErrorsAreGeneric(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{{"--config", "/missing/private/config"}, {"--unknown"}, {"extra"}} {
		out.Reset()
		if run(context.Background(), args, &out) == nil {
			t.Fatal("invalid args/config accepted")
		}
		if strings.Contains(out.String(), "/missing/private/config") {
			t.Fatal("private path exposed")
		}
	}
}

func TestBoundedOnceAndShutdown(t *testing.T) {
	status := http.StatusOK
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"records":[]}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if os.WriteFile(path, data, 0600) != nil {
			t.Fatal("fixture write")
		}
		return path
	}
	cert := write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	keyBytes, err := x509.MarshalPKCS8PrivateKey(server.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key := write("client.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	u, _ := url.Parse(server.URL)
	conn := auditingest.ExportTLSFiles{Endpoint: server.URL, CAPath: cert, CertificatePath: cert, KeyPath: key, AllowedHosts: []string{u.Host}, AllowedAddresses: []string{"127.0.0.1"}}
	config := auditingest.ExportFileConfig{Index: conn, Search: conn, ArchiveEndpoint: server.URL, ArchiveCAPath: cert, ArchiveCredentialsPath: write("reader.json", []byte(`{"access_key":"synthetic-only","secret_key":"synthetic-only"}`)), CheckpointPath: filepath.Join(dir, "checkpoint.json")}
	for _, bucket := range []string{"originals", "governance"} {
		q := auditingest.Qualification{SchemaVersion: 1, ArchiveEndpoint: server.URL, ArchiveVersion: "qualified-test", Bucket: bucket, KMSKeyID: "kms-test", DefaultRetentionSeconds: 86400, ConfigurationSHA256: auditrecord.Hash(nil), ReportSHA256: auditrecord.Hash(nil), VerifiedAt: time.Now().UTC(), Checks: []string{"versioning", "compliance_retention", "sse_kms", "exact_version_reads", "conditional_create", "writer_no_delete", "writer_no_retention_reduction", "acknowledged_write_process_crash", "acknowledged_write_power_loss", "encrypted_backup_restore", "key_restore"}}
		body, _ := json.Marshal(q)
		config.QualificationPaths = append(config.QualificationPaths, write(bucket+".json", body))
		config.QualificationSHA256s = append(config.QualificationSHA256s, auditrecord.Hash(body))
	}
	body, _ := json.Marshal(config)
	path := write("config.json", body)
	var output bytes.Buffer
	if run(context.Background(), []string{"--config", path, "--once"}, &output) != nil {
		t.Fatal("bounded empty archive scan failed")
	}
	os.Remove(config.CheckpointPath)
	status = http.StatusServiceUnavailable
	if run(context.Background(), []string{"--config", path, "--once"}, &output) == nil || !strings.Contains(output.String(), "page unavailable") {
		t.Fatal("once silently succeeded on outage")
	}
	os.Remove(config.CheckpointPath)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if run(ctx, []string{"--config", path}, &output) != nil {
		t.Fatal("shutdown did not complete")
	}
}
