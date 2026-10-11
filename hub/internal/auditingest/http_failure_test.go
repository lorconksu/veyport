package auditingest

import (
	"bytes"
	"crypto/tls"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func submissionFixture(t *testing.T, raw, script []byte, envelopeID, envelopeType, scriptID, scriptType string, extra bool) (string, []byte) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	part := func(id, typ string, data []byte) {
		h := textproto.MIMEHeader{}
		h.Set("Content-ID", id)
		h.Set("Content-Type", typ)
		p, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	part(envelopeID, envelopeType, raw)
	if script != nil {
		part(scriptID, scriptType, script)
	}
	if extra {
		part("extra", "application/octet-stream", []byte("unbound secret"))
	}
	if w.Close() != nil {
		t.Fatal("close multipart")
	}
	return w.FormDataContentType(), b.Bytes()
}

func TestHTTPRejectsMalformedMultipartWithoutPublishingOrEchoing(t *testing.T) {
	for _, name := range []string{"missing_attachment", "wrong_envelope_id", "wrong_envelope_type", "wrong_attachment_id", "wrong_attachment_type", "truncated_attachment", "overlong_attachment", "wrong_hash", "extra_part", "missing_closing_boundary", "invalid_envelope"} {
		t.Run(name, func(t *testing.T) {
			h, _, a, now := testHandler(t)
			raw, _ := testRecord(t, now, []byte("secret"))
			script := []byte("secret")
			envelopeID, envelopeType, scriptID, scriptType := "envelope", "application/json", "script", "application/octet-stream"
			switch name {
			case "missing_attachment":
				script = nil
			case "wrong_envelope_id":
				envelopeID = "raw"
			case "wrong_envelope_type":
				envelopeType = "text/plain"
			case "wrong_attachment_id":
				scriptID = "unbound"
			case "wrong_attachment_type":
				scriptType = "text/plain"
			case "truncated_attachment":
				script = []byte("sec")
			case "overlong_attachment":
				script = []byte("secret!")
			case "wrong_hash":
				script = []byte("xxxxxx")
			case "invalid_envelope":
				raw = []byte(`{"actor":{"name":"SYNTHETIC_SECRET"}}`)
			}
			contentType, body := submissionFixture(t, raw, script, envelopeID, envelopeType, scriptID, scriptType, name == "extra_part")
			if name == "missing_closing_boundary" {
				body = body[:len(body)-8]
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/records", bytes.NewReader(body))
			r.TLS = &tls.ConnectionState{}
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("i", 32))
			r.Header.Set("Content-Type", contentType)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || len(a.order) != 0 || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "SYNTHETIC_SECRET") {
				t.Fatalf("malformed multipart published or leaked: status=%d writes=%v", w.Code, a.order)
			}
		})
	}
}

func TestHTTPRejectsInvalidContentTypesAndBodyReadFailures(t *testing.T) {
	h, s, a, now := testHandler(t)
	raw, _ := testRecord(t, now, nil)
	for _, tc := range []struct {
		name, contentType string
		body              io.Reader
		path, token       string
		status            int
	}{
		{"malformed_media_type", `multipart/form-data; boundary="`, bytes.NewReader(raw), "/v1/records", "i", 400},
		{"unsupported", "text/plain", bytes.NewReader(raw), "/v1/records", "i", 400},
		{"no_boundary", "multipart/mixed", bytes.NewReader(raw), "/v1/records", "i", 400},
		{"long_boundary", "multipart/mixed; boundary=" + strings.Repeat("x", 71), bytes.NewReader(raw), "/v1/records", "i", 400},
		{"json_read_failure", "application/json", &sourceFailure{err: io.ErrUnexpectedEOF}, "/v1/records", "i", 400},
		{"multipart_read_failure", "multipart/mixed; boundary=x", &sourceFailure{err: io.ErrUnexpectedEOF}, "/v1/records", "i", 400},
		{"original_read_failure", "application/json", &sourceFailure{err: io.ErrUnexpectedEOF}, "/v1/originals", "r", 400},
		{"original_oversized", "application/json", strings.NewReader(strings.Repeat("x", auditrecord.MaxReceiptBytes+4097)), "/v1/originals", "r", 400},
		{"original_ambiguous", "application/json", strings.NewReader(`{"intent_token":"one","intent_token":"two"}`), "/v1/originals", "r", 400},
		{"original_schema_failure", "application/json", strings.NewReader(`{"object":{},"intent_token":"invalid"}`), "/v1/originals", "r", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tc.path, tc.body)
			r.TLS = &tls.ConnectionState{}
			r.Header.Set("Authorization", "Bearer "+strings.Repeat(tc.token, 32))
			r.Header.Set("Content-Type", tc.contentType)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || len(a.order) != 0 {
				t.Fatalf("invalid request wrote archive: status=%d writes=%v", w.Code, a.order)
			}
		})
	}
	for _, path := range []string{"/v1/originals", "/v1/ready", "/v1/export-index", "/v1/records/event-1"} {
		method := http.MethodPost
		if path == "/v1/originals" {
			method = http.MethodGet
		}
		if w := callHandler(h, method, path, strings.Repeat("a", 32), nil); w.Code != 405 {
			t.Fatal("unsupported method reached authority", path, w.Code)
		}
	}
	s.config.GovernanceArchive.(*memoryArchive).failFind = true
	if w := callHandler(h, http.MethodPost, "/v1/records", strings.Repeat("i", 32), raw); w.Code != 503 {
		t.Fatal("ledger outage not refused")
	}
	for i := 0; i < cap(s.slots); i++ {
		s.slots <- struct{}{}
	}
	if w := callHandler(h, http.MethodPost, "/v1/records", strings.Repeat("i", 32), raw); w.Code != 429 {
		t.Fatal("service capacity did not reach HTTP caller")
	}
	for i := 0; i < cap(s.slots); i++ {
		<-s.slots
	}
}
