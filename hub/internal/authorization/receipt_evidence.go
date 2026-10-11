package authorization

import (
	"context"
	"encoding/json"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
)

// ReceiptEvidence uses separate ingestion and governance credentials. Transport
// qualification is supplied by the compiled enforcement integration; it defaults
// to false, so partially deployed Enhanced features cannot be activated.
type ReceiptEvidence struct {
	Ingest         *auditgate.Client
	Admin          *auditgate.Client
	Verifier       *auditgate.Verifier
	TransportReady bool
	PolicyReady    func(context.Context, model.AuditPolicy) error
	Now            func() time.Time
}

func (e *ReceiptEvidence) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}
func (e *ReceiptEvidence) Ready(ctx context.Context, p model.AuditPolicy) error {
	if e == nil || !e.TransportReady || e.Ingest == nil || e.Admin == nil || e.Verifier == nil || e.PolicyReady == nil {
		return ErrNotReady
	}
	return e.PolicyReady(ctx, p)
}
func (e *ReceiptEvidence) Preserve(ctx context.Context, raw []byte) (string, error) {
	if e == nil || e.Ingest == nil || e.Admin == nil || e.Verifier == nil {
		return "", ErrNotReady
	}
	expected, envelope, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return "", err
	}
	receipt, err := e.Ingest.Preserve(ctx, raw, nil)
	if err != nil {
		receipt, err = e.Admin.Lookup(ctx, expected.EventID, expected.RecordSHA256)
		if err != nil {
			return "", err
		}
	}
	// History may outlive a short-lived receipt. A governance lookup attests durable
	// evidence again; it cannot renew execution or original-access permissions.
	claims, err := e.Verifier.Verify(receipt.Token, expected, e.now())
	if err != nil {
		receipt, err = e.Admin.Lookup(ctx, expected.EventID, expected.RecordSHA256)
		if err != nil {
			return "", err
		}
		claims, err = e.Verifier.Verify(receipt.Token, expected, e.now())
		if err != nil {
			return "", err
		}
	}
	if claims.EventType != envelope.EventType || auditrecord.Digest(claims.Manifest) != auditrecord.Digest(receipt.Manifest) {
		return "", auditgate.ErrReceipt
	}
	reference, err := json.Marshal(receipt.Manifest)
	return string(reference), err
}
func (e *ReceiptEvidence) Anchor(ctx context.Context, installation string) (PolicyAnchor, error) {
	if e == nil || e.Admin == nil {
		return PolicyAnchor{}, ErrNotReady
	}
	response, err := e.Admin.Anchor(ctx, installation)
	if err != nil {
		return PolicyAnchor{}, err
	}
	var envelope auditrecord.Envelope
	if auditrecord.Decode(response.Record, &envelope, auditrecord.MaxEnvelopeBytes) != nil || envelope.Details == nil || envelope.EventType != auditrecord.PolicyAnchor || envelope.Details.InstallationID != installation {
		return PolicyAnchor{}, ErrRecovery
	}
	return PolicyAnchor{InstallationID: installation, Version: envelope.PolicyVersion, SHA256: envelope.PolicySHA256, RequestID: envelope.Details.RequestID, RequestSHA256: envelope.Details.RequestSHA256}, nil
}
