package auditingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type projectionReaderFunc func(context.Context, auditrecord.ObjectRef) ([]byte, error)

func (f projectionReaderFunc) Read(ctx context.Context, ref auditrecord.ObjectRef) ([]byte, error) {
	return f(ctx, ref)
}

func TestExporterFailureKeepsCursorAndBackoffUntilReplay(t *testing.T) {
	for _, name := range []string{"index_outage", "oversized_page", "invalid_reference", "out_of_order", "missing_archive", "manifest_read_error", "envelope_read_error", "invalid_projection"} {
		t.Run(name, func(t *testing.T) {
			s, archive, _, now := testService(t)
			raw, _ := testRecord(t, now, nil)
			receipt, err := s.Preserve(context.Background(), raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			ref := ExportReference{"event-1", auditrecord.ExecutionAdmission, auditrecord.Hash(raw), receipt.Manifest}
			page := ExportPage{Records: []ExportReference{ref}}
			index := brokenIndex{page: page}
			failure := "index_invalid"
			archives := map[string]ProjectionReader{archive.q.Bucket: archive}
			switch name {
			case "index_outage":
				index.err = ErrUnavailable
				failure = "index_unavailable"
			case "oversized_page":
				index.page.Records = make([]ExportReference, MaxExportPage+1)
				failure = "index_unavailable"
			case "invalid_reference":
				index.page.Records[0].Manifest.VersionID = "null"
			case "out_of_order":
				index.page.Records = append(index.page.Records, ref)
			case "missing_archive":
				archives = map[string]ProjectionReader{"other": archive}
				failure = "archive_unavailable"
			default:
				failure = "archive_invalid"
				if name == "envelope_read_error" {
					failure = "archive_unavailable"
				}
				if name == "invalid_projection" {
					failure = "projection_invalid"
				}
				archives[archive.q.Bucket] = projectionReaderFunc(func(ctx context.Context, object auditrecord.ObjectRef) ([]byte, error) {
					if name == "manifest_read_error" && strings.HasPrefix(object.Key, "manifests/") {
						return nil, ErrUnavailable
					}
					if strings.HasPrefix(object.Key, "envelopes/") {
						if name == "envelope_read_error" {
							return nil, ErrUnavailable
						}
						if name == "invalid_projection" {
							return []byte(`{"secret":"CANARY"}`), nil
						}
					}
					return archive.Read(ctx, object)
				})
			}
			sink := &memorySink{docs: map[string]Projection{}}
			path := filepath.Join(t.TempDir(), "checkpoint.json")
			e := &Exporter{Index: index, Archives: archives, Sink: sink, Now: func() time.Time { return now }, CheckpointPath: path}
			if err := e.Step(context.Background()); !errors.Is(err, ErrUnavailable) || e.Checkpoint.Cursor != "" || e.Checkpoint.Failure != failure || e.Checkpoint.Failures != 1 {
				t.Fatalf("failure advanced cursor or lost retry state: %+v, %v", e.Checkpoint, err)
			}
			restarted := &Exporter{CheckpointPath: path}
			if restarted.LoadCheckpoint() != nil || restarted.Checkpoint.Failure != failure || !restarted.Checkpoint.RetryAt.Equal(now.Add(2*time.Second)) {
				t.Fatal("restart lost failure/backoff")
			}
			if !errors.Is(e.Step(context.Background()), ErrBusy) {
				t.Fatal("outage retried without backoff")
			}
			e.Index = brokenIndex{page: ExportPage{Records: []ExportReference{ref}}}
			e.Archives = map[string]ProjectionReader{archive.q.Bucket: archive}
			now = now.Add(3 * time.Second)
			if err := e.Step(context.Background()); err != nil || len(sink.docs) != 1 || e.Checkpoint.Failure != "" || e.Checkpoint.Failures != 0 {
				t.Fatal("repaired archive did not replay failed cursor", err)
			}
		})
	}
}

func TestExporterSkipsOldSearchProjectionWithoutReadingAttachments(t *testing.T) {
	s, a, _, occurred := testService(t)
	raw, attachments := testRecord(t, occurred, []byte("SECRET_SCRIPT"))
	if _, err := s.Preserve(context.Background(), raw, attachments); err != nil {
		t.Fatal(err)
	}
	// Extend only the fixture's retention so the projection's independent seven
	// day window, rather than object expiry, decides whether search is populated.
	now := occurred.Add(8 * 24 * time.Hour)
	page, err := s.ExportIndex(context.Background(), "", 8)
	if err != nil {
		t.Fatal(err)
	}
	ref := page.Records[0]
	ref.Manifest.RetainUntil = now.Add(time.Hour)
	manifestBytes, err := a.Read(context.Background(), page.Records[0].Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var m auditrecord.Manifest
	_ = json.Unmarshal(manifestBytes, &m)
	m.RetainUntil, m.Envelope.RetainUntil = ref.Manifest.RetainUntil, ref.Manifest.RetainUntil
	manifestBytes, _ = json.Marshal(m)
	reader := projectionReaderFunc(func(_ context.Context, object auditrecord.ObjectRef) ([]byte, error) {
		if strings.HasPrefix(object.Key, "attachments/") {
			t.Fatal("exporter read script original")
		}
		if strings.HasPrefix(object.Key, "manifests/") {
			return manifestBytes, nil
		}
		return raw, nil
	})
	sink := &memorySink{docs: map[string]Projection{}}
	e := &Exporter{Index: brokenIndex{page: ExportPage{Records: []ExportReference{ref}}}, Archives: map[string]ProjectionReader{a.q.Bucket: reader}, Sink: sink, Now: func() time.Time { return now }}
	if err := e.Step(context.Background()); err != nil || e.Checkpoint.Skipped != 1 || len(sink.docs) != 0 {
		t.Fatal("old search projection was indexed", err)
	}
}

func TestExporterCheckpointFailuresArePrivateAndRecoverable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte
		mode    os.FileMode
	}{
		{"ambiguous", []byte(`{"cursor":"one","cursor":"two"}`), 0600},
		{"invalid_cursor", []byte(`{"cursor":"../raw"}`), 0600},
		{"unbounded_backoff", []byte(`{"cursor":"","failures":8}`), 0600},
		{"oversized", bytes.Repeat([]byte("x"), 4097), 0600},
		{"public", []byte(`{"cursor":""}`), 0644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "checkpoint.json")
			if os.WriteFile(path, tc.content, tc.mode) != nil {
				t.Fatal("fixture write")
			}
			if !errors.Is((&Exporter{CheckpointPath: path}).LoadCheckpoint(), ErrUnavailable) {
				t.Fatal("invalid/private checkpoint accepted")
			}
		})
	}
	if (&Exporter{CheckpointPath: filepath.Join(t.TempDir(), "absent")}).LoadCheckpoint() != nil {
		t.Fatal("fresh exporter required an existing checkpoint")
	}
	if (&Exporter{}).LoadCheckpoint() != nil {
		t.Fatal("memory checkpoint rejected")
	}
	for _, target := range []string{"missing_parent", "existing_directory", "unencodable_timestamp"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "checkpoint.json")
			if target == "missing_parent" {
				path = filepath.Join(dir, "absent", "checkpoint.json")
			}
			if target == "existing_directory" && os.Mkdir(path, 0700) != nil {
				t.Fatal("fixture mkdir")
			}
			e := &Exporter{Index: brokenIndex{}, Archives: map[string]ProjectionReader{"archive": newMemoryArchive()}, Sink: &memorySink{docs: map[string]Projection{}}, CheckpointPath: path}
			if target == "unencodable_timestamp" {
				e.Checkpoint.LastAcceptedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			if err := e.Step(context.Background()); !errors.Is(err, ErrUnavailable) || e.Checkpoint.Failure != "checkpoint_unavailable" {
				t.Fatal("checkpoint failure reported successful export", err)
			}
			leaked, err := filepath.Glob(filepath.Join(dir, ".export-checkpoint-*"))
			if err != nil || len(leaked) != 0 {
				t.Fatal("checkpoint temporary file leaked")
			}
		})
	}
}

type exportRoundTrip func(*http.Request) (*http.Response, error)

func (f exportRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type closedResponse struct {
	io.Reader
	closes int
}

func (b *closedResponse) Close() error { b.closes++; return nil }

func TestExporterHTTPMalformedResponsesAndTransportFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reader io.Reader
	}{
		{"read_error", &sourceFailure{err: io.ErrUnexpectedEOF}},
		{"oversized", strings.NewReader(strings.Repeat("x", (128<<10)+1))},
		{"ambiguous", strings.NewReader(`{"records":[],"records":[]}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &closedResponse{Reader: tc.reader}
			client := &http.Client{Transport: exportRoundTrip(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
			})}
			if _, err := (HTTPProjectionIndex{Client: client, Endpoint: "https://index.invalid"}).Page(context.Background(), "", 1); !errors.Is(err, ErrUnavailable) || body.closes != 1 {
				t.Fatal("malformed index response accepted/leaked", err)
			}
		})
	}
	for _, endpoint := range []string{"https://export.invalid", "://bad"} {
		client := &http.Client{Transport: exportRoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("PRIVATE_CANARY transport") })}
		if _, err := (HTTPProjectionIndex{Client: client, Endpoint: endpoint}).Page(context.Background(), "", 1); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "PRIVATE_CANARY") {
			t.Fatal("index request failure leaked")
		}
		if err := (HTTPProjectionSink{Client: client, Endpoint: endpoint}).Send(context.Background(), Projection{}); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "PRIVATE_CANARY") {
			t.Fatal("sink request failure leaked")
		}
	}
	if _, err := (HTTPProjectionIndex{}).Page(context.Background(), "", 1); !errors.Is(err, ErrUnavailable) {
		t.Fatal("index missing client accepted")
	}
	for _, p := range []Projection{{}, {ActorName: strings.Repeat("x", 8193)}, {Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}} {
		if err := (HTTPProjectionSink{}).Send(context.Background(), p); !errors.Is(err, ErrUnavailable) {
			t.Fatal("unusable sink accepted projection")
		}
	}
}
