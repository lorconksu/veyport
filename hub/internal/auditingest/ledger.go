package auditingest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type eventIndex struct {
	EventID      string                `json:"event_id"`
	EventType    string                `json:"event_type"`
	RecordSHA256 string                `json:"record_sha256"`
	Manifest     auditrecord.ObjectRef `json:"manifest"`
}

func (s *Service) archiveFor(eventType string) Archive {
	if strings.HasPrefix(eventType, "policy.") {
		return s.config.GovernanceArchive
	}
	return s.config.Archive
}
func (s *Service) retentionFor(eventType string) time.Duration {
	if strings.HasPrefix(eventType, "policy.") {
		return s.config.GovernanceRetention
	}
	return s.config.Retention
}
func (s *Service) archiveForObject(ref auditrecord.ObjectRef) Archive {
	if ref.Bucket == s.config.GovernanceArchive.Qualification().Bucket {
		return s.config.GovernanceArchive
	}
	if ref.Bucket == s.config.Archive.Qualification().Bucket {
		return s.config.Archive
	}
	return nil
}

func (s *Service) readLedger(ctx context.Context, eventID string) (eventIndex, error) {
	ref, b, err := s.config.GovernanceArchive.Find(ctx, "events/"+eventID)
	if err != nil {
		return eventIndex{}, err
	}
	var idx eventIndex
	if auditrecord.Decode(b, &idx, 16<<10) != nil || idx.EventID != eventID || !auditrecord.ValidHash(idx.RecordSHA256) || !idx.Manifest.Valid() || s.archiveForObject(idx.Manifest) == nil || s.config.GovernanceArchive.Verify(ctx, ref, ref.RetainUntil) != nil {
		return idx, ErrUnavailable
	}
	return idx, nil
}

// A global external conditional ledger prevents event IDs from being reused
// across the original and governance buckets. It contains only hashes/references.
func (s *Service) ensureLedger(ctx context.Context, e auditrecord.Expected, manifest auditrecord.ObjectRef) error {
	wanted := eventIndex{EventID: e.EventID, EventType: e.EventType, RecordSHA256: e.RecordSHA256, Manifest: manifest}
	if idx, err := s.readLedger(ctx, e.EventID); err == nil {
		if auditrecord.Digest(idx) != auditrecord.Digest(wanted) {
			return ErrConflict
		}
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return ErrUnavailable
	}
	b, _ := json.Marshal(wanted)
	retain := s.config.Now().UTC().Add(s.config.GovernanceRetention)
	_, err := s.config.GovernanceArchive.Put(ctx, "events/"+e.EventID, b, retain)
	if err != nil {
		idx, lookupErr := s.readLedger(ctx, e.EventID)
		if lookupErr != nil {
			return ErrUnavailable
		}
		if auditrecord.Digest(idx) != auditrecord.Digest(wanted) {
			return ErrConflict
		}
		return nil
	}
	idx, err := s.readLedger(ctx, e.EventID)
	if err != nil || auditrecord.Digest(idx) != auditrecord.Digest(wanted) {
		return ErrUnavailable
	}
	return nil
}
