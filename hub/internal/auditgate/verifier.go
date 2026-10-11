// Package auditgate validates independent protected archive receipts. It has no
// private signing key and never treats availability or a local queue as admission.
package auditgate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

var (
	ErrReceipt        = errors.New("protected archive receipt rejected")
	ErrReplay         = errors.New("execution receipt already consumed")
	ErrAnchorNotFound = errors.New("protected policy anchor not found")
)

type VerifierConfig struct {
	Issuer                        string
	Audience                      string
	Keys                          map[string]*ecdsa.PublicKey
	QualificationSHA256           string
	GovernanceQualificationSHA256 string
	MaxTTL                        time.Duration
	ClockSkew                     time.Duration
}

type Verifier struct{ config VerifierConfig }

func NewVerifier(c VerifierConfig) (*Verifier, error) {
	if c.Issuer == "" || c.Audience == "" || !auditrecord.ValidHash(c.QualificationSHA256) || c.MaxTTL <= 0 || c.MaxTTL > 5*time.Minute || c.ClockSkew < 0 || c.ClockSkew > 30*time.Second || len(c.Keys) == 0 {
		return nil, ErrReceipt
	}
	if c.GovernanceQualificationSHA256 != "" && !auditrecord.ValidHash(c.GovernanceQualificationSHA256) {
		return nil, ErrReceipt
	}
	keys := make(map[string]*ecdsa.PublicKey, len(c.Keys))
	for id, k := range c.Keys {
		if !auditrecord.ValidID(id) || k == nil || k.Curve != elliptic.P256() || k.X == nil || k.Y == nil || !k.Curve.IsOnCurve(k.X, k.Y) {
			return nil, ErrReceipt
		}
		copyKey := *k
		copyKey.X = new(big.Int).Set(k.X)
		copyKey.Y = new(big.Int).Set(k.Y)
		keys[id] = &copyKey
	}
	c.Keys = keys
	return &Verifier{c}, nil
}

func (v *Verifier) Verify(token string, e auditrecord.Expected, now time.Time) (auditrecord.Claims, error) {
	var c auditrecord.Claims
	if v == nil || len(token) > auditrecord.MaxReceiptBytes || len(token) == 0 {
		return c, ErrReceipt
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, ErrReceipt
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, ErrReceipt
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if auditrecord.Decode(h, &header, 1024) != nil || header.Algorithm != "ES256" || header.Type != "JWT" || v.config.Keys[header.KeyID] == nil {
		return c, ErrReceipt
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || auditrecord.Decode(payload, &c, auditrecord.MaxReceiptBytes) != nil {
		return c, ErrReceipt
	}
	parsed, err := jwt.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodES256 {
			return nil, ErrReceipt
		}
		return v.config.Keys[header.KeyID], nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(v.config.Issuer), jwt.WithAudience(v.config.Audience), jwt.WithExpirationRequired(), jwt.WithTimeFunc(func() time.Time { return now }), jwt.WithLeeway(v.config.ClockSkew))
	if err != nil || !parsed.Valid {
		return c, ErrReceipt
	}
	qualification := v.config.QualificationSHA256
	if strings.HasPrefix(e.EventType, "policy.") && v.config.GovernanceQualificationSHA256 != "" {
		qualification = v.config.GovernanceQualificationSHA256
	}
	if c.SchemaVersion != 1 || c.KeyID != header.KeyID || c.ID != e.EventID || c.EventID != e.EventID || c.EventType != e.EventType || c.RecordSHA256 != e.RecordSHA256 || c.ActorSHA256 != e.ActorSHA256 || c.BindingSHA256 != e.BindingSHA256 || c.PolicyVersion != e.PolicyVersion || c.PolicySHA256 != e.PolicySHA256 || c.QualificationSHA256 != qualification || len(c.Audience) != 1 || !c.Manifest.Valid() || c.Manifest.RetainUntil.Before(e.MinRetainUntil) || c.IssuedAt == nil || c.NotBefore == nil || c.ExpiresAt == nil {
		return c, ErrReceipt
	}
	if c.LookupNonce != e.Nonce {
		return c, ErrReceipt
	}
	if !now.Before(c.ExpiresAt.Time) || c.IssuedAt.Time.After(now.Add(v.config.ClockSkew)) || c.NotBefore.Time.After(now.Add(v.config.ClockSkew)) || !c.ExpiresAt.Time.After(c.IssuedAt.Time) || c.ExpiresAt.Time.Sub(c.IssuedAt.Time) > v.config.MaxTTL || c.NotBefore.Time.Before(c.IssuedAt.Time) || c.Manifest.RetainUntil.Before(c.ExpiresAt.Time) {
		return c, ErrReceipt
	}
	if e.Execution != nil {
		x := e.Execution
		if c.ExecutionID != x.ExecutionID || c.PreparationID != x.PreparationID || c.BootID != x.BootID || c.NodeID != x.NodeID || c.IdentitySHA256 != x.Identity.IdentitySHA256 {
			return c, ErrReceipt
		}
		if e.EventType == auditrecord.ExecutionAdmission && (!now.Before(x.PreparedUntil) || c.ExpiresAt.Time.After(x.PreparedUntil)) {
			return c, ErrReceipt
		}
	} else if c.ExecutionID != "" || c.PreparationID != "" || c.BootID != "" || c.NodeID != "" || c.IdentitySHA256 != "" {
		return c, ErrReceipt
	}
	return c, nil
}

// Consumer must atomically persist a one-use dispatch claim before execution.
// An implementation must never retry an uncertain claim as a new execution.
type Consumer interface {
	Claim(context.Context, string, string, string) error
}

func (v *Verifier) Consume(ctx context.Context, token string, e auditrecord.Expected, now time.Time, consumer Consumer) (auditrecord.Claims, error) {
	c, err := v.Verify(token, e, now)
	if err != nil {
		return c, err
	}
	if consumer == nil || e.EventType != auditrecord.ExecutionAdmission || e.Execution == nil {
		return c, ErrReceipt
	}
	if err = consumer.Claim(ctx, e.Execution.ExecutionID, e.Execution.PreparationID, auditrecord.Hash([]byte(token))); err != nil {
		return c, err
	}
	return c, nil
}
