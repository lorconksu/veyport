package auditingest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func testHandler(t *testing.T) (*Handler, *Service, *memoryArchive, time.Time) {
	t.Helper()
	s, a, _, now := testService(t)
	auth, err := NewAuthenticator([]Credential{{ID: "ingest", TokenSHA256: auditrecord.Hash([]byte(strings.Repeat("i", 32))), Scope: ScopeIngest}, {ID: "reader", TokenSHA256: auditrecord.Hash([]byte(strings.Repeat("r", 32))), Scope: ScopeRead}, {ID: "admin", TokenSHA256: auditrecord.Hash([]byte(strings.Repeat("a", 32))), Scope: ScopeAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(s, auth, 4)
	if err != nil {
		t.Fatal(err)
	}
	return h, s, a, now
}
func callHandler(h *Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHTTPScopedCredentialsAndPrivacy(t *testing.T) {
	h, _, _, now := testHandler(t)
	raw, _ := testRecord(t, now, nil)
	cases := []struct {
		method, path, token string
		body                []byte
		status              int
	}{{"POST", "/v1/records", "", raw, 401}, {"POST", "/v1/records", strings.Repeat("r", 32), raw, 401}, {"POST", "/v1/originals", strings.Repeat("i", 32), raw, 401}, {"GET", "/v1/ready", strings.Repeat("i", 32), nil, 401}, {"GET", "/v1/ready", strings.Repeat("a", 32), nil, 200}, {"POST", "/v1/records", strings.Repeat("i", 32), raw, 200}, {"POST", "/v1/records", strings.Repeat("i", 32), append([]byte(" "), raw...), 409}, {"POST", "/v1/records", strings.Repeat("i", 32), []byte(`{"unknown":"SYNTHETIC_SECRET"}`), 400}, {"GET", "/v1/records", strings.Repeat("i", 32), nil, 405}, {"POST", "/unknown", strings.Repeat("i", 32), nil, 404}}
	for _, c := range cases {
		w := callHandler(h, c.method, c.path, c.token, c.body)
		if w.Code != c.status {
			t.Fatalf("%s %s got %d expected %d", c.method, c.path, w.Code, c.status)
		}
		if strings.Contains(w.Body.String(), "SYNTHETIC_SECRET") || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("response exposed raw input or allowed caching")
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/records", bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("i", 32))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("cleartext bearer accepted")
	}
	for i := 0; i < cap(h.slots); i++ {
		h.slots <- struct{}{}
	}
	if callHandler(h, "POST", "/v1/records", strings.Repeat("i", 32), raw).Code != 429 {
		t.Fatal("unbounded concurrency")
	}
}

func TestReadinessRequiresBothArchivesAndReportsSeparatePins(t *testing.T) {
	h, s, originals, _ := testHandler(t)
	governance := s.config.GovernanceArchive.(*memoryArchive)
	for _, unavailable := range []string{"", "originals", "governance"} {
		originals.failFind = unavailable == "originals"
		governance.failFind = unavailable == "governance"
		w := callHandler(h, http.MethodGet, "/v1/ready", strings.Repeat("a", 32), nil)
		var response struct {
			Ready               bool   `json:"ready"`
			ArchiveReady        bool   `json:"archive_ready"`
			GovernanceReady     bool   `json:"governance_ready"`
			OriginalPin         string `json:"qualification_sha256"`
			GovernancePin       string `json:"governance_qualification_sha256"`
			OriginalRetention   int64  `json:"retention_seconds"`
			GovernanceRetention int64  `json:"governance_retention_seconds"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Ready != (unavailable == "") || response.OriginalPin != originals.q.Digest || response.GovernancePin != governance.q.Digest || response.OriginalRetention != 86400 || response.GovernanceRetention != 3650*86400 {
			t.Fatal("readiness omitted an archive dependency, pin or retention guarantee")
		}
		if response.ArchiveReady != (unavailable != "originals") || response.GovernanceReady != (unavailable != "governance") {
			t.Fatal("independent authority readiness was coupled to the other bucket")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.Ready(ctx) == nil {
		t.Fatal("canceled readiness accepted")
	}
}

type readinessArchive struct {
	Archive
	ready func(context.Context) error
}

func (a readinessArchive) Ready(ctx context.Context) error { return a.ready(ctx) }

func TestReadinessTimeoutDoesNotCancelHealthyAuthorityProbe(t *testing.T) {
	h, s, _, _ := testHandler(t)
	s.config.Timeout = 25 * time.Millisecond
	s.config.Archive = readinessArchive{Archive: s.config.Archive, ready: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	s.config.GovernanceArchive = readinessArchive{Archive: s.config.GovernanceArchive, ready: func(ctx context.Context) error {
		return ctx.Err()
	}}
	w := callHandler(h, http.MethodGet, "/v1/ready", strings.Repeat("a", 32), nil)
	var response struct {
		Ready           bool `json:"ready"`
		ArchiveReady    bool `json:"archive_ready"`
		GovernanceReady bool `json:"governance_ready"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatal("readiness response unavailable")
	}
	if response.Ready || response.ArchiveReady || !response.GovernanceReady {
		t.Fatal("timed-out originals probe cancelled healthy governance readiness")
	}
}

func TestMultipartClientServerProtectedOriginal(t *testing.T) {
	h, s, a, now := testHandler(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	u, _ := url.Parse(server.URL)
	client := func(token string) *auditgate.Client {
		c, err := auditgate.NewClient(auditgate.ClientConfig{Endpoint: server.URL, AllowedHosts: []string{u.Host}, AllowedAddresses: []string{"127.0.0.1"}, TLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, Bearer: strings.Repeat(token, 32)})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	raw, inputs := testRecord(t, now, []byte("SYNTHETIC_SECRET_script"))
	receipt, err := client("i").Preserve(context.Background(), raw, inputs)
	if err != nil {
		t.Fatal(err)
	}
	var manifest auditrecord.Manifest
	json.Unmarshal(a.objects[receipt.Manifest.Key].data, &manifest)
	if _, err = client("r").ReadOriginal(context.Background(), manifest.Envelope, receipt.Token); err == nil {
		t.Fatal("admission token gave raw read")
	}
	e := auditrecord.Envelope{SchemaVersion: 1, EventID: "original-access", EventType: auditrecord.OriginalReadIntent, Actor: auditrecord.Actor{UserID: "user", PersonID: "person"}, PolicyVersion: 1, PolicySHA256: auditrecord.Hash(nil), OccurredAt: now, Details: &auditrecord.Details{CorrelationID: "access", SessionSHA256: auditrecord.Hash(nil), Reason: "incident", Originals: []auditrecord.ObjectRef{manifest.Envelope}}}
	b, _ := json.Marshal(e)
	intent, err := s.Preserve(context.Background(), b, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := client("r").ReadOriginal(context.Background(), manifest.Envelope, intent.Token)
	if err != nil {
		t.Fatal(err)
	}
	original, err := io.ReadAll(body)
	body.Close()
	if err != nil || !bytes.Equal(raw, original) {
		t.Fatal("exact original not returned")
	}
	if _, err = client("a").Lookup(context.Background(), "event-1", auditrecord.Hash(raw)); err != nil {
		t.Fatal(err)
	}
}

func TestAuthAndTLSConfigurationRefusals(t *testing.T) {
	for _, c := range [][]Credential{nil, {{ID: "x", TokenSHA256: "bad", Scope: ScopeIngest}}, {{ID: "x", TokenSHA256: auditrecord.Hash(nil), Scope: "invalid"}}, {{ID: "x", TokenSHA256: auditrecord.Hash(nil), Scope: ScopeIngest}, {ID: "y", TokenSHA256: auditrecord.Hash(nil), Scope: ScopeRead}}} {
		if _, err := NewAuthenticator(c); err == nil {
			t.Fatal("invalid/shared credential accepted")
		}
	}
	certificate := &x509.Certificate{Raw: []byte("verified cert")}
	a, err := NewAuthenticator([]Credential{{ID: "cert", CertificateSHA256: auditrecord.Hash(certificate.Raw), Scope: ScopeIngest}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://ingest/v1/records", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	if !a.authorize(r, ScopeIngest) || a.authorize(r, ScopeRead) {
		t.Fatal("verified certificate scope incorrect")
	}
	r.TLS.VerifiedChains = nil
	if a.authorize(r, ScopeIngest) {
		t.Fatal("unverified client certificate accepted")
	}
	h, _, _, _ := testHandler(t)
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{}}, ClientCAs: x509.NewCertPool(), ClientAuth: tls.RequireAndVerifyClientCert}
	server, err := NewHTTPServer("127.0.0.1:0", h, config)
	if err != nil || server.ReadHeaderTimeout == 0 || server.ReadTimeout == 0 || server.MaxHeaderBytes == 0 {
		t.Fatal("server not bounded")
	}
	config.ClientAuth = tls.NoClientCert
	if _, err = NewHTTPServer("127.0.0.1:0", h, config); err == nil {
		t.Fatal("unauthenticated TLS config accepted")
	}
}
