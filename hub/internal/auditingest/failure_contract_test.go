package auditingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type sourceFailure struct {
	data []byte
	err  error
}

func (r *sourceFailure) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

type cancelAfterRead struct {
	io.Reader
	cancel context.CancelFunc
}

func (r cancelAfterRead) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.cancel()
	return n, err
}

func TestPreserveRejectsIncompleteOrUnreadableAttachmentsBeforePublication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reader io.Reader
		id     string
	}{
		{"truncated", strings.NewReader("scr"), "script"},
		{"overlong", strings.NewReader("script!"), "script"},
		{"wrong_hash", strings.NewReader("xxxxxx"), "script"},
		{"read_error", &sourceFailure{data: []byte("scr"), err: io.ErrUnexpectedEOF}, "script"},
		{"read_error_at_bound", &sourceFailure{data: []byte("script"), err: errors.New("source unavailable")}, "script"},
		{"missing_reader", nil, "script"},
		{"wrong_id", strings.NewReader("script"), "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, a, _, now := testService(t)
			raw, _ := testRecord(t, now, []byte("script"))
			r, err := s.Preserve(context.Background(), raw, []AttachmentInput{{ID: tc.id, Reader: tc.reader}})
			if !errors.Is(err, auditrecord.ErrSchema) || r.Token != "" || len(a.order) != 0 {
				t.Fatalf("fault published protected content or authority: %v, writes=%v", err, a.order)
			}
		})
	}
	s, a, _, now := testService(t)
	raw, _ := testRecord(t, now, []byte("script"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := cancelAfterRead{Reader: strings.NewReader("script"), cancel: cancel}
	if r, err := s.Preserve(ctx, raw, []AttachmentInput{{ID: "script", Reader: reader}}); !errors.Is(err, ErrUnavailable) || r.Token != "" || len(a.order) != 0 {
		t.Fatal("canceled input published an archive object or permit", err)
	}
}

func TestPreservePreparationExpiryBounds(t *testing.T) {
	for _, offset := range []time.Duration{-time.Second, 500 * time.Millisecond, 20 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			s, a, _, now := testService(t)
			raw, _ := testRecord(t, now, nil)
			var e auditrecord.Envelope
			_ = json.Unmarshal(raw, &e)
			e.Execution.PreparedUntil = now.Add(offset)
			raw, _ = json.Marshal(e)
			r, err := s.Preserve(context.Background(), raw, nil)
			if offset < time.Second {
				if !errors.Is(err, auditrecord.ErrSchema) || r.Token != "" || len(a.order) != 0 {
					t.Fatal("unusable preparation admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var m auditrecord.Manifest
			_ = json.Unmarshal(a.objects[r.Manifest.Key].data, &m)
			if !m.ExpiresAt.Time.Equal(e.Execution.PreparedUntil) {
				t.Fatal("permit exceeded preparation deadline")
			}
		})
	}
}

type interceptArchive struct {
	Archive
	put  func(context.Context, string, []byte, time.Time) (auditrecord.ObjectRef, error)
	find func(context.Context, string) (auditrecord.ObjectRef, []byte, error)
	read func(context.Context, auditrecord.ObjectRef) ([]byte, error)
}

func (a interceptArchive) Put(ctx context.Context, key string, b []byte, retain time.Time) (auditrecord.ObjectRef, error) {
	if a.put != nil {
		return a.put(ctx, key, b, retain)
	}
	return a.Archive.Put(ctx, key, b, retain)
}
func (a interceptArchive) Find(ctx context.Context, key string) (auditrecord.ObjectRef, []byte, error) {
	if a.find != nil {
		return a.find(ctx, key)
	}
	return a.Archive.Find(ctx, key)
}
func (a interceptArchive) Read(ctx context.Context, ref auditrecord.ObjectRef) ([]byte, error) {
	if a.read != nil {
		return a.read(ctx, ref)
	}
	return a.Archive.Read(ctx, ref)
}

func TestGlobalLedgerAmbiguousWriteRequiresExactImmutableWinner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		alter   bool
		corrupt bool
		lost    bool
		missing bool
		want    error
	}{
		{name: "lost_reply_exact_winner", lost: true},
		{name: "lost_reply_conflicting_winner", alter: true, lost: true, want: ErrConflict},
		{name: "successful_write_conflicting_readback", alter: true, want: ErrUnavailable},
		{name: "lost_reply_corrupt_winner", corrupt: true, lost: true, want: ErrUnavailable},
		{name: "lost_reply_missing_readback", missing: true, lost: true, want: ErrUnavailable},
		{name: "successful_write_missing_readback", missing: true, want: ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, originals, _, now := testService(t)
			gov := s.config.GovernanceArchive.(*memoryArchive)
			putLedger := false
			writes := 0
			s.config.GovernanceArchive = interceptArchive{Archive: gov, put: func(ctx context.Context, key string, b []byte, retain time.Time) (auditrecord.ObjectRef, error) {
				if !strings.HasPrefix(key, "events/") {
					return gov.Put(ctx, key, b, retain)
				}
				putLedger = true
				writes++
				if tc.alter {
					var idx eventIndex
					_ = json.Unmarshal(b, &idx)
					idx.RecordSHA256 = auditrecord.Hash([]byte("other exact event"))
					b, _ = json.Marshal(idx)
				}
				if tc.corrupt {
					b = []byte(`{"event_id":`)
				}
				ref, err := gov.Put(ctx, key, b, retain)
				if err != nil {
					return ref, err
				}
				if tc.lost {
					return auditrecord.ObjectRef{}, ErrUnavailable
				}
				return ref, nil
			}, find: func(ctx context.Context, key string) (auditrecord.ObjectRef, []byte, error) {
				if putLedger && tc.missing && strings.HasPrefix(key, "events/") {
					return auditrecord.ObjectRef{}, nil, ErrNotFound
				}
				return gov.Find(ctx, key)
			}}
			raw, _ := testRecord(t, now, nil)
			r, err := s.Preserve(context.Background(), raw, nil)
			if !errors.Is(err, tc.want) || writes != 1 || len(originals.order) != 2 {
				t.Fatalf("ambiguous ledger contract changed: receipt=%+v err=%v writes=%d", r, err, writes)
			}
			if tc.want != nil && r.Token != "" {
				t.Fatal("uncertain ledger issued launch authority")
			}
			if tc.want == nil {
				lookedUp, err := s.Lookup(context.Background(), "event-1", auditrecord.Hash(raw))
				if err != nil || auditrecord.Digest(lookedUp.Manifest) != auditrecord.Digest(r.Manifest) || writes != 1 {
					t.Fatal("lost reply required another immutable write", err)
				}
			}
		})
	}
}

func TestPreserveRejectsCorruptLedgerAndManifestWithoutNewWrites(t *testing.T) {
	for _, target := range []string{"ledger", "manifest", "manifest_read_error", "ledger_verify_error"} {
		t.Run(target, func(t *testing.T) {
			s, a, _, now := testService(t)
			raw, _ := testRecord(t, now, nil)
			if _, err := s.Preserve(context.Background(), raw, nil); err != nil {
				t.Fatal(err)
			}
			gov := s.config.GovernanceArchive.(*memoryArchive)
			if target == "ledger" {
				s.config.GovernanceArchive = interceptArchive{Archive: gov, find: func(ctx context.Context, key string) (auditrecord.ObjectRef, []byte, error) {
					ref, b, err := gov.Find(ctx, key)
					if strings.HasPrefix(key, "events/") {
						b = []byte(`{"event_id":"event-1","event_id":"event-1"}`)
					}
					return ref, b, err
				}}
			} else if target == "ledger_verify_error" {
				gov.failVerify = "events/"
			} else {
				s.config.Archive = interceptArchive{Archive: a, read: func(ctx context.Context, ref auditrecord.ObjectRef) ([]byte, error) {
					if strings.HasPrefix(ref.Key, "manifests/") {
						if target == "manifest_read_error" {
							return nil, ErrUnavailable
						}
						return []byte(`{"schema_version":`), nil
					}
					return a.Read(ctx, ref)
				}}
			}
			r, err := s.Preserve(context.Background(), raw, nil)
			if err == nil || r.Token != "" || len(a.order) != 2 || len(gov.order) != 1 {
				t.Fatal("corrupt authority was replaced or accepted", err)
			}
		})
	}
}

func TestReadOriginalMalformedIntentCannotReadArchive(t *testing.T) {
	s, a, _, now := testService(t)
	ref := auditrecord.ObjectRef{Bucket: a.q.Bucket, Key: "original", VersionID: "v1", SHA256: auditrecord.Hash(nil), RetainUntil: now.Add(time.Hour)}
	for _, token := range []string{"not-a-jwt", "header.!.signature", "header.e30.signature"} {
		if b, err := s.ReadOriginal(context.Background(), ref, token); b != nil || !errors.Is(err, ErrUnavailable) || len(a.readKeys) != 0 {
			t.Fatal("malformed intent read archive", err)
		}
	}
	ref.Bytes = auditrecord.MaxAttachmentBytes + 1
	if _, err := s.ReadOriginal(context.Background(), ref, "not-a-jwt"); !errors.Is(err, auditrecord.ErrSchema) {
		t.Fatal("original size bound missing")
	}
	if _, err := s.Preserve(context.Background(), bytes.Repeat([]byte("x"), auditrecord.MaxEnvelopeBytes+1), nil); !errors.Is(err, auditrecord.ErrSchema) {
		t.Fatal("oversized envelope accepted")
	}
}
