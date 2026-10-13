package auditingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type KeyLister interface {
	ListKeys(context.Context, string) ([]string, error)
}
type anchorIndex struct {
	Manifest     auditrecord.ObjectRef `json:"manifest"`
	Version      uint64                `json:"version"`
	EventID      string                `json:"event_id"`
	RecordSHA256 string                `json:"record_sha256"`
}

func (s *Service) latestAnchor(ctx context.Context, installationID string) (anchorIndex, error) {
	lister, ok := s.config.GovernanceArchive.(KeyLister)
	if !ok || !auditrecord.ValidID(installationID) {
		return anchorIndex{}, ErrUnavailable
	}
	prefix := "anchors/" + installationID + "/"
	keys, err := lister.ListKeys(ctx, prefix)
	if err != nil {
		return anchorIndex{}, ErrUnavailable
	}
	if len(keys) == 0 {
		return anchorIndex{}, ErrNotFound
	}
	sort.Strings(keys)
	key := keys[len(keys)-1]
	if !strings.HasPrefix(key, prefix) || len(strings.TrimPrefix(key, prefix)) != 20 {
		return anchorIndex{}, ErrUnavailable
	}
	ref, b, err := s.config.GovernanceArchive.Find(ctx, key)
	var idx anchorIndex
	if err != nil || auditrecord.Decode(b, &idx, 16<<10) != nil || idx.Version == 0 || key != fmt.Sprintf("%s%020d", prefix, idx.Version) || !idx.Manifest.Valid() || !auditrecord.ValidID(idx.EventID) || !auditrecord.ValidHash(idx.RecordSHA256) || s.config.GovernanceArchive.Verify(ctx, ref, ref.RetainUntil) != nil {
		return idx, ErrUnavailable
	}
	return idx, nil
}

func (s *Service) ensureAnchor(ctx context.Context, e auditrecord.Envelope, manifest auditrecord.ObjectRef, retain time.Time, recordHash string) error {
	d := e.Details
	if d == nil {
		return ErrUnavailable
	}
	key := fmt.Sprintf("anchors/%s/%020d", d.InstallationID, e.PolicyVersion)
	if ref, b, err := s.config.GovernanceArchive.Find(ctx, key); err == nil {
		var idx anchorIndex
		if auditrecord.Decode(b, &idx, 16<<10) != nil || idx.RecordSHA256 != recordHash || auditrecord.Digest(idx.Manifest) != auditrecord.Digest(manifest) || s.config.GovernanceArchive.Verify(ctx, ref, retain) != nil {
			return ErrConflict
		}
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return ErrUnavailable
	}
	latest, err := s.latestAnchor(ctx, d.InstallationID)
	if errors.Is(err, ErrNotFound) {
		if d.ExpectedPolicyVersion != 1 {
			return ErrConflict
		}
	} else if err != nil {
		return ErrUnavailable
	} else if latest.Version != d.ExpectedPolicyVersion {
		return ErrConflict
	}
	idx := anchorIndex{Manifest: manifest, Version: e.PolicyVersion, EventID: e.EventID, RecordSHA256: recordHash}
	b, _ := json.Marshal(idx)
	_, err = s.protect(ctx, key, b, retain)
	return err
}

// Lookup is authenticated historical evidence reconciliation. Admission and
// original-read intent receipts retain their original expiry and cannot renew.
func (s *Service) Lookup(ctx context.Context, eventID, hash string) (auditrecord.Receipt, error) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return auditrecord.Receipt{}, ErrBusy
	}
	if !auditrecord.ValidID(eventID) || !auditrecord.ValidHash(hash) {
		return auditrecord.Receipt{}, auditrecord.ErrSchema
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	idx, err := s.readLedger(ctx, eventID)
	if err != nil {
		return auditrecord.Receipt{}, err
	}
	archive := s.archiveFor(idx.EventType)
	ref := idx.Manifest
	b, err := archive.Read(ctx, ref)
	if err != nil {
		return auditrecord.Receipt{}, err
	}
	var m auditrecord.Manifest
	if auditrecord.Decode(b, &m, auditrecord.MaxEnvelopeBytes) != nil || m.EventID != eventID || m.RecordSHA256 != hash {
		return auditrecord.Receipt{}, ErrConflict
	}
	raw, err := archive.Read(ctx, m.Envelope)
	if err != nil {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	expected, e, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return auditrecord.Receipt{}, ErrUnavailable
	}
	return s.reconcile(ctx, expected, e, ref, b)
}

// Anchor signs the latest protected policy anchor and the caller's unpredictable
// nonce. A retained older anchor cannot satisfy a fresh latest-state lookup.
func (s *Service) Anchor(ctx context.Context, installationID, nonce string) (auditrecord.AnchorResponse, error) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return auditrecord.AnchorResponse{}, ErrBusy
	}
	if !auditrecord.ValidID(installationID) || !auditrecord.ValidHash(nonce) {
		return auditrecord.AnchorResponse{}, auditrecord.ErrSchema
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	idx, err := s.latestAnchor(ctx, installationID)
	if err != nil {
		return auditrecord.AnchorResponse{}, err
	}
	mBytes, err := s.config.GovernanceArchive.Read(ctx, idx.Manifest)
	if err != nil {
		return auditrecord.AnchorResponse{}, ErrUnavailable
	}
	var m auditrecord.Manifest
	if auditrecord.Decode(mBytes, &m, auditrecord.MaxEnvelopeBytes) != nil {
		return auditrecord.AnchorResponse{}, ErrUnavailable
	}
	if !idx.Manifest.RetainUntil.Equal(m.RetainUntil) || !m.Envelope.RetainUntil.Equal(m.RetainUntil) || s.config.GovernanceArchive.Verify(ctx, idx.Manifest, m.RetainUntil) != nil || s.config.GovernanceArchive.Verify(ctx, m.Envelope, m.RetainUntil) != nil {
		return auditrecord.AnchorResponse{}, ErrUnavailable
	}
	record, err := s.config.GovernanceArchive.Read(ctx, m.Envelope)
	if err != nil {
		return auditrecord.AnchorResponse{}, ErrUnavailable
	}
	expected, e, err := auditrecord.ExpectedFor(record)
	if err != nil || e.EventType != auditrecord.PolicyAnchor || e.Details == nil || e.Details.InstallationID != installationID || e.PolicyVersion != idx.Version || e.EventID != idx.EventID || auditrecord.Hash(record) != idx.RecordSHA256 || auditrecord.Hash(record) != m.RecordSHA256 {
		return auditrecord.AnchorResponse{}, ErrUnavailable
	}
	expected.Nonce = nonce
	iat := *jwt.NewNumericDate(s.config.Now().UTC().Truncate(time.Second))
	expires := *jwt.NewNumericDate(iat.Add(s.config.ReceiptTTL))
	if idx.Manifest.RetainUntil.Before(expires.Time) {
		return auditrecord.AnchorResponse{}, ErrUnavailable
	}
	receipt, err := s.sign(expected, idx.Manifest, iat, expires)
	return auditrecord.AnchorResponse{Record: record, Receipt: receipt, Nonce: nonce}, err
}
