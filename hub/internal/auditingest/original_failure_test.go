package auditingest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func TestOriginalReadArchiveFailuresNeverReleaseBytes(t *testing.T) {
	for _, name := range []string{"manifest_missing", "manifest_corrupt", "manifest_unverified", "intent_envelope_unreadable", "intent_envelope_corrupt", "original_unreadable", "unknown_original_bucket"} {
		t.Run(name, func(t *testing.T) {
			s, a, _, now := testService(t)
			raw, _ := testRecord(t, now, nil)
			receipt, err := s.Preserve(context.Background(), raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			var m auditrecord.Manifest
			_ = json.Unmarshal(a.objects[receipt.Manifest.Key].data, &m)
			original := m.Envelope
			if name == "unknown_original_bucket" {
				original.Bucket = "untrusted-bucket"
			}
			intentRecord := auditrecord.Envelope{SchemaVersion: 1, EventID: "read-1", EventType: auditrecord.OriginalReadIntent, Actor: auditrecord.Actor{UserID: "reader", PersonID: "reader"}, PolicyVersion: 1, PolicySHA256: auditrecord.Hash(nil), OccurredAt: now, Details: &auditrecord.Details{CorrelationID: "access", Reason: "incident", SessionSHA256: auditrecord.Hash(nil), Originals: []auditrecord.ObjectRef{original}}}
			intentBytes, _ := json.Marshal(intentRecord)
			intent, err := s.Preserve(context.Background(), intentBytes, nil)
			if err != nil {
				t.Fatal(err)
			}
			if name == "manifest_unverified" {
				a.failVerify = "manifests/read-1"
			}
			s.config.Archive = interceptArchive{Archive: a, find: func(ctx context.Context, key string) (auditrecord.ObjectRef, []byte, error) {
				ref, b, err := a.Find(ctx, key)
				if key == "manifests/read-1" {
					if name == "manifest_missing" {
						return auditrecord.ObjectRef{}, nil, ErrNotFound
					}
					if name == "manifest_corrupt" {
						b = []byte(`{"schema_version":`)
					}
				}
				return ref, b, err
			}, read: func(ctx context.Context, ref auditrecord.ObjectRef) ([]byte, error) {
				if strings.HasPrefix(ref.Key, "envelopes/read-1/") {
					if name == "intent_envelope_unreadable" {
						return nil, ErrUnavailable
					}
					if name == "intent_envelope_corrupt" {
						return []byte(`{"schema_version":`), nil
					}
				}
				if name == "original_unreadable" && ref.Key == original.Key {
					return nil, ErrUnavailable
				}
				return a.Read(ctx, ref)
			}}
			a.readKeys = nil
			if b, err := s.ReadOriginal(context.Background(), original, intent.Token); b != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("failed original read released bytes", err)
			}
			for _, key := range a.readKeys {
				if key == original.Key {
					t.Fatal("failed access touched original content")
				}
			}
		})
	}
}

type faultPager struct {
	Archive
	keys []string
	more bool
	err  error
}

func (p faultPager) ExportKeys(context.Context, string, int) ([]string, bool, error) {
	return p.keys, p.more, p.err
}

func TestExportIndexRejectsUntrustedPagesAndRecoversExactCursor(t *testing.T) {
	for _, name := range []string{"missing_pager", "pager_outage", "too_many", "invalid_id", "before_cursor", "unknown_event", "wrong_manifest_key"} {
		t.Run(name, func(t *testing.T) {
			s, _, _, now := testService(t)
			raw, _ := testRecord(t, now, nil)
			if _, err := s.Preserve(context.Background(), raw, nil); err != nil {
				t.Fatal(err)
			}
			gov := s.config.GovernanceArchive.(*memoryArchive)
			pager := faultPager{Archive: gov, keys: []string{"event-1"}}
			after := ""
			switch name {
			case "missing_pager":
				s.config.GovernanceArchive = interceptArchive{Archive: gov}
			case "pager_outage":
				pager.err = ErrUnavailable
			case "too_many":
				pager.keys = []string{"event-1", "event-2"}
			case "invalid_id":
				pager.keys = []string{"../event"}
			case "before_cursor":
				after = "event-1"
			case "unknown_event":
				pager.keys = []string{"event-2"}
			case "wrong_manifest_key":
				gov.mu.Lock()
				o := gov.objects["events/event-1"]
				var idx eventIndex
				_ = json.Unmarshal(o.data, &idx)
				idx.Manifest.Key = "manifests/another-event"
				o.data, _ = json.Marshal(idx)
				o.ref.SHA256, o.ref.Bytes = auditrecord.Hash(o.data), int64(len(o.data))
				gov.objects["events/event-1"] = o
				gov.mu.Unlock()
			}
			if name != "missing_pager" {
				s.config.GovernanceArchive = pager
			}
			if page, err := s.ExportIndex(context.Background(), after, 1); !errors.Is(err, ErrUnavailable) || len(page.Records) != 0 {
				t.Fatal("untrusted index page returned", err)
			}
		})
	}
	s, _, _, now := testService(t)
	for _, event := range []string{"event-1", "event-2"} {
		raw, _ := testRecord(t, now, nil)
		var e auditrecord.Envelope
		_ = json.Unmarshal(raw, &e)
		e.EventID = event
		raw, _ = json.Marshal(e)
		if _, err := s.Preserve(context.Background(), raw, nil); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.ExportIndex(context.Background(), "", 1)
	if err != nil || len(first.Records) != 1 || first.Next != "event-1" {
		t.Fatal("first bounded page wrong", err)
	}
	second, err := s.ExportIndex(context.Background(), first.Next, 1)
	if err != nil || len(second.Records) != 1 || second.Records[0].EventID != "event-2" || second.Next != "" {
		t.Fatal("cursor skipped or replayed a different ledger event", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ExportIndex(ctx, "", 1); !errors.Is(err, ErrUnavailable) {
		t.Fatal("canceled enumeration accepted")
	}
}
