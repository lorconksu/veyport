package auditgate

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func TestVerifyRejectsMalformedAndAmbiguousJWT(t *testing.T) {
	v, key, claims, expected, now := fixture(t)
	valid := sign(t, key, claims)
	parts := strings.Split(valid, ".")
	encode := base64.RawURLEncoding.EncodeToString
	cases := map[string]string{
		"empty": "", "too_large": strings.Repeat("x", auditrecord.MaxReceiptBytes+1),
		"missing_segment":      parts[0] + "." + parts[1],
		"bad_header_encoding":  "!" + "." + parts[1] + "." + parts[2],
		"bad_payload_encoding": parts[0] + ".!." + parts[2],
		"duplicate_header":     encode([]byte(`{"alg":"ES256","alg":"ES256","kid":"key-1","typ":"JWT"}`)) + "." + parts[1] + "." + parts[2],
		"wrong_header_type":    encode([]byte(`{"alg":"ES256","kid":"key-1","typ":"JWS"}`)) + "." + parts[1] + "." + parts[2],
		"unknown_header":       encode([]byte(`{"alg":"ES256","kid":"key-1","typ":"JWT","jku":"https://attacker.invalid"}`)) + "." + parts[1] + "." + parts[2],
		"duplicate_payload":    parts[0] + "." + encode([]byte(`{"event_id":"event","event_id":"event"}`)) + "." + parts[2],
		"wrong_payload_type":   parts[0] + "." + encode([]byte(`{"schema_version":"1"}`)) + "." + parts[2],
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			consumer := &replayConsumer{}
			if _, err := v.Consume(context.Background(), token, expected, now, consumer); !errors.Is(err, ErrReceipt) || consumer.used {
				t.Fatal("malformed permit reached durable consumption")
			}
		})
	}
	var missing *Verifier
	if _, err := missing.Verify(valid, expected, now); !errors.Is(err, ErrReceipt) {
		t.Fatal("nil verifier admitted receipt")
	}
}

func TestVerifyEnforcesTemporalAndNonceClaimsBeforeConsumption(t *testing.T) {
	v, key, claims, expected, now := fixture(t)
	for _, tc := range []struct {
		name   string
		change func(*auditrecord.Claims)
	}{
		{"missing_iat", func(c *auditrecord.Claims) { c.IssuedAt = nil }},
		{"missing_nbf", func(c *auditrecord.Claims) { c.NotBefore = nil }},
		{"missing_exp", func(c *auditrecord.Claims) { c.ExpiresAt = nil }},
		{"nbf_precedes_issuance", func(c *auditrecord.Claims) { c.NotBefore = jwt.NewNumericDate(now.Add(-time.Second)) }},
		{"nbf_in_future", func(c *auditrecord.Claims) { c.NotBefore = jwt.NewNumericDate(now.Add(6 * time.Second)) }},
		{"expiry_precedes_issuance", func(c *auditrecord.Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Second)) }},
		{"multiple_audiences", func(c *auditrecord.Claims) { c.Audience = jwt.ClaimStrings{"hub", "another-hub"} }},
		{"wrong_nonce", func(c *auditrecord.Claims) { c.LookupNonce = auditrecord.Hash(nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := claims
			tc.change(&bad)
			consumer := &replayConsumer{}
			if _, err := v.Consume(context.Background(), sign(t, key, bad), expected, now, consumer); !errors.Is(err, ErrReceipt) || consumer.used {
				t.Fatal("invalid signed authority consumed")
			}
		})
	}
	expected.Execution.PreparedUntil = now.Add(30 * time.Second)
	if _, err := v.Verify(sign(t, key, claims), expected, now); !errors.Is(err, ErrReceipt) {
		t.Fatal("receipt outlived live preparation")
	}
	claims.EventType, expected.EventType = auditrecord.PolicyResult, auditrecord.PolicyResult
	expected.Execution = nil
	if _, err := v.Verify(sign(t, key, claims), expected, now); !errors.Is(err, ErrReceipt) {
		t.Fatal("governance receipt carried execution launch fields")
	}
}

func TestGateDoesNotConsumeUnverifiedArchiveAcknowledgment(t *testing.T) {
	v, key, claims, _, now := fixture(t)
	raw := clientEnvelope(now, 0, "")
	expected, envelope, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		t.Fatal(err)
	}
	claims.ID, claims.EventID = expected.EventID, expected.EventID
	claims.RecordSHA256, claims.ActorSHA256, claims.BindingSHA256 = expected.RecordSHA256, expected.ActorSHA256, expected.BindingSHA256
	claims.PolicySHA256 = expected.PolicySHA256
	for _, tc := range []struct {
		name    string
		receipt auditrecord.Receipt
		err     error
	}{
		{"archive_outage", auditrecord.Receipt{}, errors.New("archive unavailable")},
		{"bad_signature", auditrecord.Receipt{Token: "malformed", Manifest: claims.Manifest}, nil},
		{"different_manifest", auditrecord.Receipt{Token: sign(t, key, claims), Manifest: fakeReceipt(now).Manifest}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			consumer := &replayConsumer{}
			g := Gate{Preserver: receiptPreserver{r: tc.receipt, err: tc.err}, Verifier: v, Consumer: consumer, Now: func() time.Time { return now }}
			if _, err := g.Admit(context.Background(), raw, nil, *envelope.Execution, now.Add(time.Hour)); err == nil || consumer.used {
				t.Fatal("unverified archive acknowledgment reached launch claim")
			}
		})
	}
}
