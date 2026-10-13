package auditgate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func TestAnchorAbsenceRequiresTypedCurrentResponse(t *testing.T) {
	v, _, _, _, _ := fixture(t)
	cases := []struct {
		name    string
		status  int
		body    func(*http.Request) string
		missing bool
	}{
		{"typed", 404, func(r *http.Request) string {
			b, _ := json.Marshal(auditrecord.AnchorNotFoundResponse{Code: "anchor_not_found", InstallationID: "installation", Nonce: r.URL.Query().Get("nonce")})
			return string(b)
		}, true},
		{"empty404", 404, func(*http.Request) string { return "" }, false},
		{"route404", 404, func(*http.Request) string { return "page not found" }, false},
		{"wrong_nonce", 404, func(*http.Request) string {
			return `{"code":"anchor_not_found","installation_id":"installation","nonce":"old"}`
		}, false},
		{"wrong_installation", 404, func(r *http.Request) string {
			b, _ := json.Marshal(auditrecord.AnchorNotFoundResponse{Code: "anchor_not_found", InstallationID: "other", Nonce: r.URL.Query().Get("nonce")})
			return string(b)
		}, false},
		{"unauthorized", 401, func(*http.Request) string { return "" }, false},
		{"unavailable", 503, func(*http.Request) string { return "" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{endpoint: "https://audit.example", verifier: v, http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body(r)))}, nil
			})}}
			_, err := client.Anchor(context.Background(), "installation")
			if err == nil || errors.Is(err, ErrAnchorNotFound) != tc.missing {
				t.Fatal("generic failure accepted as authentic bootstrap absence", err)
			}
			if tc.missing {
				if _, err = client.Lookup(context.Background(), "event", auditrecord.Hash(nil)); errors.Is(err, ErrAnchorNotFound) {
					t.Fatal("record lookup returned anchor absence")
				}
			}
		})
	}
}

func TestAnchorVerifiesLatestNonceAndInstallation(t *testing.T) {
	v, k, c, _, now := fixture(t)
	e := auditrecord.Envelope{SchemaVersion: 1, EventID: "change-anchor", EventType: auditrecord.PolicyAnchor, Actor: auditrecord.Actor{UserID: "user", PersonID: "person"}, PolicyVersion: 2, PolicySHA256: auditrecord.Hash([]byte("new-policy")), OccurredAt: now, Details: &auditrecord.Details{InstallationID: "installation", CorrelationID: "installation", RequestID: "change", RequestSHA256: auditrecord.Hash([]byte("approved")), ExpectedPolicyVersion: 1, NewPolicyVersion: 2}}
	raw, _ := json.Marshal(e)
	expected, _, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.ID = e.EventID
	c.EventID = e.EventID
	c.EventType = e.EventType
	c.RecordSHA256 = expected.RecordSHA256
	c.ActorSHA256 = expected.ActorSHA256
	c.BindingSHA256 = expected.BindingSHA256
	c.PolicyVersion = e.PolicyVersion
	c.PolicySHA256 = e.PolicySHA256
	c.ExecutionID = ""
	c.PreparationID = ""
	c.BootID = ""
	c.NodeID = ""
	c.IdentitySHA256 = ""
	wrongNonce := false
	client := &Client{endpoint: "https://audit.example", verifier: v, http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		nonce := r.URL.Query().Get("nonce")
		if !auditrecord.ValidHash(nonce) {
			t.Fatal("lookup lacked fresh nonce")
		}
		c.LookupNonce = nonce
		response := auditrecord.AnchorResponse{Record: raw, Receipt: auditrecord.Receipt{Token: sign(t, k, c), Manifest: c.Manifest}, Nonce: nonce}
		if wrongNonce {
			response.Nonce = auditrecord.Hash([]byte("old lookup"))
		}
		return jsonResponse(response), nil
	})}}
	response, err := client.Anchor(context.Background(), "installation")
	if err != nil || response.Receipt.Token == "" {
		t.Fatal(err)
	}
	wrongNonce = true
	if _, err = client.Anchor(context.Background(), "installation"); err == nil {
		t.Fatal("replayed latest-state response accepted")
	}
	wrongNonce = false
	if _, err = client.Anchor(context.Background(), "different-installation"); err == nil {
		t.Fatal("different installation accepted")
	}
	client.verifier = nil
	if _, err = client.Anchor(context.Background(), "installation"); err == nil {
		t.Fatal("unsigned anchor trust accepted")
	}
}

func TestVerifierConfigAndDuplicateClaims(t *testing.T) {
	v, k, c, e, now := fixture(t)
	tok := sign(t, k, c)
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	payload = bytes.Replace(payload, []byte(`"event_id":"event"`), []byte(`"event_id":"event","event_id":"event"`), 1)
	unsigned := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig, err := jwt.SigningMethodES256.Sign(unsigned, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Verify(unsigned+"."+base64.RawURLEncoding.EncodeToString(sig), e, now); err == nil {
		t.Fatal("duplicate signed claims accepted")
	}
	bad := v.config
	bad.ClockSkew = time.Minute
	if _, err = NewVerifier(bad); err == nil {
		t.Fatal("unbounded clock skew")
	}
	bad = v.config
	bad.QualificationSHA256 = "invalid"
	if _, err = NewVerifier(bad); err == nil {
		t.Fatal("untrusted qualification")
	}
	bad = v.config
	bad.Keys = map[string]*ecdsa.PublicKey{"key": nil}
	if _, err = NewVerifier(bad); err == nil {
		t.Fatal("nil key accepted")
	}
	c.EventType = auditrecord.ExecutionLifecycle
	e.EventType = c.EventType
	e.Execution.PreparedUntil = now.Add(-time.Hour)
	if _, err = v.Verify(sign(t, k, c), e, now); err != nil {
		t.Fatal("late lifecycle evidence rejected", err)
	}
}

func TestTransportRequiresExplicitAddressPins(t *testing.T) {
	base := TransportConfig{Endpoint: "https://10.10.1.60:8443", AllowedHosts: []string{"10.10.1.60:8443"}, TLS: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}, Timeout: time.Second, Connections: 1}
	if _, err := NewTLSClient(base); err != nil {
		t.Fatal(err)
	}
	base.Endpoint = "https://audit.example"
	base.AllowedHosts = []string{"audit.example"}
	if _, err := NewTLSClient(base); err == nil {
		t.Fatal("DNS name lacked address pins")
	}
	base.AllowedAddresses = []string{"10.10.1.60"}
	client, err := NewTLSClient(base)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if _, err = transport.DialContext(context.Background(), "tcp", "other.example:443"); err == nil {
		t.Fatal("dial host not bounded")
	}
	base.TLS.ServerName = "other.example"
	if _, err = NewTLSClient(base); err == nil {
		t.Fatal("alternate TLS identity accepted")
	}
	base.TLS.ServerName = ""
	base.AllowedAddresses = []string{"::"}
	if _, err = NewTLSClient(base); err == nil {
		t.Fatal("unspecified address allowed")
	}
	for _, mapped := range []string{"::ffff:169.254.169.254", "::ffff:224.0.0.1", "::ffff:0.0.0.0"} {
		base.AllowedAddresses = []string{mapped}
		if _, err = NewTLSClient(base); err == nil {
			t.Fatal("mapped unsafe address accepted", mapped)
		}
	}
	base.Endpoint = "https://[::ffff:169.254.169.254]"
	base.AllowedHosts = []string{"[::ffff:169.254.169.254]"}
	base.AllowedAddresses = nil
	if _, err = NewTLSClient(base); err == nil {
		t.Fatal("mapped metadata endpoint implicitly permitted")
	}
}
