package auditgate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/golang-jwt/jwt/v5"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Verifier, *ecdsa.PrivateKey, auditrecord.Claims, auditrecord.Expected, time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	x := &auditrecord.ExecutionBinding{ExecutionID: "exec", PreparationID: "prep", BootID: "boot", NodeID: "node", Identity: auditrecord.Identity{Username: "u", UID: 1000, GID: 1000, GroupsSHA256: auditrecord.Hash(nil), IdentitySHA256: auditrecord.Hash([]byte("identity")), Home: "/home/u", Shell: "/bin/sh", CWD: "/home/u"}, PreparedUntil: now.Add(time.Minute)}
	e := auditrecord.Expected{EventID: "event", EventType: auditrecord.ExecutionAdmission, RecordSHA256: auditrecord.Hash([]byte("record")), ActorSHA256: auditrecord.Hash([]byte("actor")), BindingSHA256: auditrecord.Hash([]byte("binding")), PolicyVersion: 1, PolicySHA256: auditrecord.Hash([]byte("policy")), Execution: x, MinRetainUntil: now.Add(time.Hour)}
	c := auditrecord.Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "ingest", Audience: jwt.ClaimStrings{"hub"}, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)), ID: e.EventID}, SchemaVersion: 1, KeyID: "key-1", EventID: e.EventID, EventType: e.EventType, RecordSHA256: e.RecordSHA256, ActorSHA256: e.ActorSHA256, BindingSHA256: e.BindingSHA256, PolicyVersion: e.PolicyVersion, PolicySHA256: e.PolicySHA256, ExecutionID: x.ExecutionID, PreparationID: x.PreparationID, BootID: x.BootID, NodeID: x.NodeID, IdentitySHA256: x.Identity.IdentitySHA256, Manifest: auditrecord.ObjectRef{Bucket: "archive", Key: "manifest/event", VersionID: "v1", SHA256: auditrecord.Hash([]byte("manifest")), Bytes: 1, RetainUntil: now.Add(time.Hour)}, QualificationSHA256: auditrecord.Hash([]byte("qualification"))}
	v, err := NewVerifier(VerifierConfig{Issuer: "ingest", Audience: "hub", Keys: map[string]*ecdsa.PublicKey{"key-1": &key.PublicKey}, QualificationSHA256: c.QualificationSHA256, MaxTTL: time.Minute, ClockSkew: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return v, key, c, e, now
}
func sign(t *testing.T, k *ecdsa.PrivateKey, c auditrecord.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	tok.Header["kid"] = c.KeyID
	s, e := tok.SignedString(k)
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func TestReceiptBindings(t *testing.T) {
	v, k, c, e, now := fixture(t)
	if _, err := v.Verify(sign(t, k, c), e, now); err != nil {
		t.Fatal(err)
	}
	changes := []func(*auditrecord.Claims){func(c *auditrecord.Claims) { c.EventID = "wrong" }, func(c *auditrecord.Claims) { c.RecordSHA256 = auditrecord.Hash(nil) }, func(c *auditrecord.Claims) { c.ActorSHA256 = auditrecord.Hash(nil) }, func(c *auditrecord.Claims) { c.BindingSHA256 = auditrecord.Hash(nil) }, func(c *auditrecord.Claims) { c.PolicyVersion++ }, func(c *auditrecord.Claims) { c.PolicySHA256 = auditrecord.Hash(nil) }, func(c *auditrecord.Claims) { c.ExecutionID = "wrong" }, func(c *auditrecord.Claims) { c.PreparationID = "wrong" }, func(c *auditrecord.Claims) { c.BootID = "wrong" }, func(c *auditrecord.Claims) { c.NodeID = "wrong" }, func(c *auditrecord.Claims) { c.IdentitySHA256 = auditrecord.Hash(nil) }, func(c *auditrecord.Claims) { c.ExpiresAt = jwt.NewNumericDate(now) }, func(c *auditrecord.Claims) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute)) }, func(c *auditrecord.Claims) { c.Manifest.VersionID = "null" }, func(c *auditrecord.Claims) { c.Manifest.RetainUntil = now }, func(c *auditrecord.Claims) { c.QualificationSHA256 = auditrecord.Hash(nil) }, func(c *auditrecord.Claims) { c.Audience = jwt.ClaimStrings{"other"} }, func(c *auditrecord.Claims) { c.KeyID = "unknown" }, func(c *auditrecord.Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(2 * time.Minute)) }}
	for i, change := range changes {
		bad := c
		change(&bad)
		if _, err := v.Verify(sign(t, k, bad), e, now); err == nil {
			t.Errorf("accepted wrong claim %d", i)
		}
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := v.Verify(sign(t, other, c), e, now); err == nil {
		t.Fatal("accepted untrusted signer")
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	tok.Header["kid"] = "key-1"
	s, _ := tok.SignedString([]byte("key"))
	if _, err := v.Verify(s, e, now); err == nil {
		t.Fatal("accepted wrong algorithm")
	}
	e.Execution.BootID = "new-boot"
	if _, err := v.Verify(sign(t, k, c), e, now); err == nil {
		t.Fatal("accepted previous boot")
	}
}

type replayConsumer struct{ used bool }

func (c *replayConsumer) Claim(_ context.Context, _, _, _ string) error {
	if c.used {
		return ErrReplay
	}
	c.used = true
	return nil
}
func TestConsume(t *testing.T) {
	v, k, c, e, now := fixture(t)
	consumer := &replayConsumer{}
	token := sign(t, k, c)
	if _, err := v.Consume(context.Background(), token, e, now, consumer); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Consume(context.Background(), token, e, now, consumer); err == nil {
		t.Fatal("receipt replay accepted")
	}
	if _, err := v.Consume(context.Background(), token, e, now, nil); err == nil {
		t.Fatal("local-only admission accepted")
	}
}
