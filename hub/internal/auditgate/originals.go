package auditgate

import (
	"context"
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type OriginalMetadataClient interface {
	Manifest(context.Context, string, string, auditrecord.ObjectRef) ([]byte, error)
	Lookup(context.Context, string, string) (auditrecord.Receipt, error)
}
type OriginalReader interface {
	ReadOriginal(context.Context, auditrecord.ObjectRef, string) (io.ReadCloser, error)
}

// OriginalArchive preserves read evidence and retrieves exact immutable versions.
// Reader must use a credential distinct from ingestion and administration.
type OriginalArchive struct {
	Ingest   Preserver
	Admin    OriginalMetadataClient
	Reader   OriginalReader
	Verifier *Verifier
}

func (c *Client) Manifest(ctx context.Context, event, hash string, ref auditrecord.ObjectRef) ([]byte, error) {
	if !auditrecord.ValidID(event) || !auditrecord.ValidHash(hash) || !ref.Valid() || ref.Key != "manifests/"+event || ref.Bytes > auditrecord.MaxEnvelopeBytes {
		return nil, ErrReceipt
	}
	q := url.Values{"sha256": {hash}, "version_id": {ref.VersionID}}
	b, err := c.get(ctx, "/v1/manifests/"+url.PathEscape(event)+"?"+q.Encode(), auditrecord.MaxEnvelopeBytes)
	if err != nil || int64(len(b)) != ref.Bytes || auditrecord.Hash(b) != ref.SHA256 {
		return nil, ErrReceipt
	}
	return b, nil
}

// VerifyArchivedAdmission validates a retained receipt at its original issuance
// solely to identify an immutable manifest. It never renews launch authority.
func (v *Verifier) VerifyArchivedAdmission(token string, e auditrecord.Expected, now time.Time) (auditrecord.Claims, error) {
	if e.EventType != auditrecord.ExecutionAdmission || e.Execution == nil {
		return auditrecord.Claims{}, ErrReceipt
	}
	return v.verifyRetained(token, e, now)
}

// VerifyReadEvidence reconciles archived read intent/results. Its returned
// claims cannot authorize an original read: that always uses Verify at live time.
func (v *Verifier) VerifyReadEvidence(token string, e auditrecord.Expected, now time.Time) (auditrecord.Claims, error) {
	if e.EventType != auditrecord.OriginalReadIntent && e.EventType != auditrecord.OriginalReadResult {
		return auditrecord.Claims{}, ErrReceipt
	}
	return v.verifyRetained(token, e, now)
}

func (v *Verifier) verifyRetained(token string, e auditrecord.Expected, now time.Time) (auditrecord.Claims, error) {
	var claims auditrecord.Claims
	if v == nil || len(token) > auditrecord.MaxReceiptBytes {
		return claims, ErrReceipt
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, ErrReceipt
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || auditrecord.Decode(payload, &claims, auditrecord.MaxReceiptBytes) != nil || claims.IssuedAt == nil || claims.IssuedAt.Time.After(now.Add(v.config.ClockSkew)) {
		return claims, ErrReceipt
	}
	return v.Verify(token, e, claims.IssuedAt.Time)
}
