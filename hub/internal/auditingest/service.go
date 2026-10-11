// Package auditingest implements the independent protected archive receipt service.
package auditingest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

var (
	ErrConflict    = errors.New("protected event conflicts with existing record")
	ErrUnavailable = errors.New("protected archive unavailable")
	ErrNotFound    = errors.New("protected archive record not found")
	ErrBusy        = errors.New("protected archive capacity exhausted")
)

type AttachmentInput = auditrecord.AttachmentInput

// Archive writes are conditional creations. Find resolves an existing key to an
// exact immutable version. Implementations must reconcile ambiguous responses and
// may never overwrite a key or authorize from local state.
type Archive interface {
	Ready(context.Context) error
	Qualification() Qualification
	Put(context.Context, string, []byte, time.Time) (auditrecord.ObjectRef, error)
	Find(context.Context, string) (auditrecord.ObjectRef, []byte, error)
	Verify(context.Context, auditrecord.ObjectRef, time.Time) error
	Read(context.Context, auditrecord.ObjectRef) ([]byte, error)
}

func (s *Service) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	if s.config.Archive.Ready(ctx) != nil || s.config.GovernanceArchive.Ready(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}

type Signer struct {
	KeyID string
	Key   *ecdsa.PrivateKey
}

type ServiceConfig struct {
	Issuer              string
	Audience            string
	Retention           time.Duration
	ReceiptTTL          time.Duration
	Timeout             time.Duration
	Concurrency         int
	Signer              Signer
	Archive             Archive
	GovernanceArchive   Archive
	GovernanceRetention time.Duration
	Now                 func() time.Time
}

type Service struct {
	config ServiceConfig
	slots  chan struct{}
}

func NewService(c ServiceConfig) (*Service, error) {
	if c.Issuer == "" || c.Audience == "" || c.Retention < time.Hour || c.ReceiptTTL < time.Second || c.ReceiptTTL > 5*time.Minute || c.Timeout <= 0 || c.Timeout > 10*time.Second || c.Concurrency < 1 || c.Concurrency > 4 || !auditrecord.ValidID(c.Signer.KeyID) || c.Signer.Key == nil || c.Signer.Key.Curve != elliptic.P256() || c.Signer.Key.D == nil || c.Archive == nil || c.Archive.Qualification().Validate() != nil {
		return nil, ErrUnavailable
	}
	if c.GovernanceArchive == nil || c.GovernanceArchive.Qualification().Validate() != nil || c.GovernanceArchive.Qualification().Bucket == c.Archive.Qualification().Bucket || c.GovernanceRetention < time.Hour || c.GovernanceRetention > 10*365*24*time.Hour || uint64(c.Retention/time.Second) > c.Archive.Qualification().DefaultRetentionSeconds || uint64(c.GovernanceRetention/time.Second) > c.GovernanceArchive.Qualification().DefaultRetentionSeconds {
		return nil, ErrUnavailable
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Service{config: c, slots: make(chan struct{}, c.Concurrency)}, nil
}

func (s *Service) Preserve(ctx context.Context, raw []byte, inputs []AttachmentInput) (auditrecord.Receipt, error) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return auditrecord.Receipt{}, ErrBusy
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	if len(raw) > auditrecord.MaxEnvelopeBytes {
		return auditrecord.Receipt{}, auditrecord.ErrSchema
	}
	raw = append([]byte(nil), raw...)
	expected, e, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return auditrecord.Receipt{}, auditrecord.ErrSchema
	}
	if len(inputs) != len(e.Attachments) {
		return auditrecord.Receipt{}, auditrecord.ErrSchema
	}
	// Freeze caller-owned bytes before hashing, signing or asynchronous I/O.
	manifestKey := "manifests/" + e.EventID
	archive := s.archiveFor(e.EventType)
	if idx, ledgerErr := s.readLedger(ctx, e.EventID); ledgerErr == nil {
		if idx.RecordSHA256 != expected.RecordSHA256 || idx.EventType != e.EventType {
			return auditrecord.Receipt{}, ErrConflict
		}
		bytes, readErr := archive.Read(ctx, idx.Manifest)
		if readErr != nil {
			return auditrecord.Receipt{}, ErrUnavailable
		}
		return s.reconcile(ctx, expected, e, idx.Manifest, bytes)
	} else if !errors.Is(ledgerErr, ErrNotFound) {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	ref, bytes, err := archive.Find(ctx, manifestKey)
	if err == nil {
		return s.reconcile(ctx, expected, e, ref, bytes)
	}
	if !errors.Is(err, ErrNotFound) {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	acceptedAt := s.config.Now().UTC()
	now := acceptedAt.Truncate(time.Second)
	expires := now.Add(s.config.ReceiptTTL)
	if e.EventType == auditrecord.ExecutionAdmission {
		if !acceptedAt.Before(e.Execution.PreparedUntil) {
			return auditrecord.Receipt{}, auditrecord.ErrSchema
		}
		if expires.After(e.Execution.PreparedUntil) {
			expires = e.Execution.PreparedUntil.Truncate(time.Second)
		}
	}
	if !expires.After(now) {
		return auditrecord.Receipt{}, auditrecord.ErrSchema
	}
	retain := acceptedAt.Add(s.retentionFor(e.EventType))
	m := auditrecord.Manifest{SchemaVersion: 1, EventID: e.EventID, RecordSHA256: expected.RecordSHA256, SigningKeyID: s.config.Signer.KeyID, IssuedAt: *jwt.NewNumericDate(now), ExpiresAt: *jwt.NewNumericDate(expires), RetainUntil: retain, QualificationSHA256: archive.Qualification().Digest}
	// Protected content is complete before the manifest is made visible.
	for i, a := range e.Attachments {
		if inputs[i].ID != a.ID || inputs[i].Reader == nil {
			return auditrecord.Receipt{}, auditrecord.ErrSchema
		}
		data, err := readExact(inputs[i].Reader, a.Bytes)
		if err != nil || int64(len(data)) != a.Bytes || auditrecord.Hash(data) != a.SHA256 {
			return auditrecord.Receipt{}, auditrecord.ErrSchema
		}
		if ctx.Err() != nil {
			return auditrecord.Receipt{}, ErrUnavailable
		}
		o, err := s.protectIn(ctx, archive, "attachments/"+e.EventID+"/"+expected.RecordSHA256+"/"+a.ID, data, retain)
		if err != nil {
			return auditrecord.Receipt{}, err
		}
		m.Attachments = append(m.Attachments, o)
	}
	m.Envelope, err = s.protectIn(ctx, archive, "envelopes/"+e.EventID+"/"+expected.RecordSHA256, raw, retain)
	if err != nil {
		return auditrecord.Receipt{}, err
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	ref, err = archive.Put(ctx, manifestKey, encoded, retain)
	if err != nil {
		// Lost replies and concurrent requests resolve the immutable winner; no retry
		// creates another manifest version or extends a prior execution permit.
		found, b, findErr := archive.Find(ctx, manifestKey)
		if findErr != nil {
			return auditrecord.Receipt{}, ErrUnavailable
		}
		return s.reconcile(ctx, expected, e, found, b)
	}
	return s.reconcile(ctx, expected, e, ref, encoded)
}

func (s *Service) protect(ctx context.Context, key string, data []byte, retain time.Time) (auditrecord.ObjectRef, error) {
	return s.protectIn(ctx, s.config.GovernanceArchive, key, data, retain)
}

func (s *Service) protectIn(ctx context.Context, archive Archive, key string, data []byte, retain time.Time) (auditrecord.ObjectRef, error) {
	ref, err := archive.Put(ctx, key, data, retain)
	if err != nil {
		found, b, findErr := archive.Find(ctx, key)
		if findErr != nil || auditrecord.Hash(b) != auditrecord.Hash(data) {
			return ref, ErrUnavailable
		}
		ref = found
	}
	if ref.SHA256 != auditrecord.Hash(data) || ref.Bytes != int64(len(data)) || archive.Verify(ctx, ref, retain) != nil {
		return ref, ErrUnavailable
	}
	return ref, nil
}

func (s *Service) reconcile(ctx context.Context, e auditrecord.Expected, envelope auditrecord.Envelope, ref auditrecord.ObjectRef, raw []byte) (auditrecord.Receipt, error) {
	var m auditrecord.Manifest
	archive := s.archiveFor(envelope.EventType)
	if auditrecord.Decode(raw, &m, auditrecord.MaxEnvelopeBytes) != nil || m.SchemaVersion != 1 || m.EventID != e.EventID || m.RecordSHA256 != e.RecordSHA256 {
		return auditrecord.Receipt{}, ErrConflict
	}
	historical := envelope.EventType != auditrecord.ExecutionAdmission && envelope.EventType != auditrecord.OriginalReadIntent
	if (!historical && (m.SigningKeyID != s.config.Signer.KeyID || m.QualificationSHA256 != archive.Qualification().Digest)) || m.Envelope.SHA256 != e.RecordSHA256 || m.Envelope.Bytes <= 0 || len(m.Attachments) != len(envelope.Attachments) || ref.SHA256 != auditrecord.Hash(raw) || ref.Bytes != int64(len(raw)) || !m.ExpiresAt.After(m.IssuedAt.Time) || m.ExpiresAt.Sub(m.IssuedAt.Time) > s.config.ReceiptTTL || m.RetainUntil.Before(m.ExpiresAt.Time) {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	if !historical && !s.config.Now().Before(m.ExpiresAt.Time) {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	if envelope.EventType == auditrecord.ExecutionAdmission && m.ExpiresAt.After(envelope.Execution.PreparedUntil) {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	for i, a := range m.Attachments {
		if a.SHA256 != envelope.Attachments[i].SHA256 || a.Bytes != envelope.Attachments[i].Bytes || !a.RetainUntil.Equal(m.RetainUntil) || archive.Verify(ctx, a, m.RetainUntil) != nil {
			return auditrecord.Receipt{}, ErrUnavailable
		}
	}
	if !m.Envelope.RetainUntil.Equal(m.RetainUntil) || !ref.RetainUntil.Equal(m.RetainUntil) || archive.Verify(ctx, m.Envelope, m.RetainUntil) != nil || archive.Verify(ctx, ref, m.RetainUntil) != nil {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	if err := s.ensureLedger(ctx, e, ref); err != nil {
		return auditrecord.Receipt{}, err
	}
	if ctx.Err() != nil {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	if envelope.EventType == auditrecord.PolicyAnchor {
		if err := s.ensureAnchor(ctx, envelope, ref, m.RetainUntil, e.RecordSHA256); err != nil {
			return auditrecord.Receipt{}, err
		}
	}
	iat, expires := m.IssuedAt, m.ExpiresAt
	if historical {
		iat = *jwt.NewNumericDate(s.config.Now().UTC().Truncate(time.Second))
		expires = *jwt.NewNumericDate(iat.Add(s.config.ReceiptTTL))
		if ref.RetainUntil.Before(expires.Time) {
			return auditrecord.Receipt{}, ErrUnavailable
		}
	}
	return s.sign(e, ref, iat, expires)
}

func (s *Service) sign(e auditrecord.Expected, ref auditrecord.ObjectRef, iat, expires jwt.NumericDate) (auditrecord.Receipt, error) {
	c := auditrecord.Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: s.config.Issuer, Audience: jwt.ClaimStrings{s.config.Audience}, ID: e.EventID, IssuedAt: &iat, NotBefore: &iat, ExpiresAt: &expires}, SchemaVersion: 1, KeyID: s.config.Signer.KeyID, EventID: e.EventID, EventType: e.EventType, RecordSHA256: e.RecordSHA256, ActorSHA256: e.ActorSHA256, BindingSHA256: e.BindingSHA256, PolicyVersion: e.PolicyVersion, PolicySHA256: e.PolicySHA256, Manifest: ref, QualificationSHA256: s.archiveFor(e.EventType).Qualification().Digest, LookupNonce: e.Nonce}
	if x := e.Execution; x != nil {
		c.ExecutionID = x.ExecutionID
		c.PreparationID = x.PreparationID
		c.BootID = x.BootID
		c.NodeID = x.NodeID
		c.IdentitySHA256 = x.Identity.IdentitySHA256
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	token.Header["kid"] = s.config.Signer.KeyID
	signed, err := token.SignedString(s.config.Signer.Key)
	if err != nil {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	return auditrecord.Receipt{Token: signed, Manifest: ref}, nil
}

// ReadOriginal releases only an exact object named by a preserved, valid access
// intent. The hub owns fresh MFA, permission rechecks and its one-use handle.
func (s *Service) ReadOriginal(ctx context.Context, ref auditrecord.ObjectRef, intent string) ([]byte, error) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return nil, ErrBusy
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	if !ref.Valid() || ref.Bytes > auditrecord.MaxAttachmentBytes || len(intent) > auditrecord.MaxReceiptBytes {
		return nil, auditrecord.ErrSchema
	}
	var claims auditrecord.Claims
	parts := strings.Split(intent, ".")
	if len(parts) != 3 {
		return nil, ErrUnavailable
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || auditrecord.Decode(payload, &claims, auditrecord.MaxReceiptBytes) != nil || claims.EventType != auditrecord.OriginalReadIntent || !auditrecord.ValidID(claims.EventID) {
		return nil, ErrUnavailable
	}
	manifestRef, b, err := s.config.Archive.Find(ctx, "manifests/"+claims.EventID)
	if err != nil {
		return nil, ErrUnavailable
	}
	var manifest auditrecord.Manifest
	if auditrecord.Decode(b, &manifest, auditrecord.MaxEnvelopeBytes) != nil || s.config.Archive.Verify(ctx, manifestRef, manifest.RetainUntil) != nil {
		return nil, ErrUnavailable
	}
	record, err := s.config.Archive.Read(ctx, manifest.Envelope)
	if err != nil {
		return nil, ErrUnavailable
	}
	expected, envelope, err := auditrecord.ExpectedFor(record)
	if err != nil || envelope.Details == nil {
		return nil, ErrUnavailable
	}
	verifier, err := auditgate.NewVerifier(auditgate.VerifierConfig{Issuer: s.config.Issuer, Audience: s.config.Audience, Keys: map[string]*ecdsa.PublicKey{s.config.Signer.KeyID: &s.config.Signer.Key.PublicKey}, QualificationSHA256: s.config.Archive.Qualification().Digest, MaxTTL: s.config.ReceiptTTL, ClockSkew: 5 * time.Second})
	if err != nil {
		return nil, ErrUnavailable
	}
	c, err := verifier.Verify(intent, expected, s.config.Now())
	age := s.config.Now().Sub(envelope.OccurredAt)
	if err != nil || auditrecord.Digest(c.Manifest) != auditrecord.Digest(manifestRef) || age > time.Minute || age < -5*time.Second {
		return nil, ErrUnavailable
	}
	for _, allowed := range envelope.Details.Originals {
		if auditrecord.Digest(allowed) == auditrecord.Digest(ref) {
			archive := s.archiveForObject(ref)
			if archive == nil {
				return nil, ErrUnavailable
			}
			return archive.Read(ctx, ref)
		}
	}
	return nil, ErrUnavailable
}
