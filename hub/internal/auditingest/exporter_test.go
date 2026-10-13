package auditingest

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func (a *memoryArchive) ExportKeys(ctx context.Context, after string, limit int) ([]string, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || a.failFind {
		return nil, false, ErrUnavailable
	}
	var ids []string
	for key := range a.objects {
		if strings.HasPrefix(key, "events/") && strings.TrimPrefix(key, "events/") > after {
			ids = append(ids, strings.TrimPrefix(key, "events/"))
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		return ids[:limit], true, nil
	}
	return ids, false, nil
}

type serviceIndex struct{ s *Service }

func (i serviceIndex) Page(ctx context.Context, after string, limit int) (ExportPage, error) {
	return i.s.ExportIndex(ctx, after, limit)
}

type memorySink struct {
	docs        map[string]Projection
	unavailable bool
}

func (s *memorySink) Send(_ context.Context, p Projection) error {
	if s.unavailable {
		return ErrUnavailable
	}
	s.docs[p.DocumentID()] = p
	return nil
}

func TestProjectionCanariesAndAllowlist(t *testing.T) {
	s, _, _, now := testService(t)
	canary := "VEYPORT_SECRET_CANARY_7fdc8d"
	commands := []string{
		"env API_KEY=" + canary + " curl https://example.invalid",
		"curl --password " + canary, "curl --token=" + canary,
		"API_KEY=" + canary + " true", "curl https://user:" + canary + "@example.invalid",
		"printf '%s' '" + canary + "'", "curl -H 'Authorization: Bearer " + canary + "'",
		"echo first\necho " + canary, "echo \"$(printf '" + canary + "')\"",
		"curl\t--token\t" + canary, "'" + canary + "' --safe",
	}
	for n, command := range commands {
		raw, _ := testRecord(t, now, nil)
		var e auditrecord.Envelope
		_ = json.Unmarshal(raw, &e)
		e.EventID = "canary-" + string(rune('a'+n))
		e.Actor.Name = "Operator"
		e.Command = []byte(command)
		e.Execution.CommandBytes = int64(len(e.Command))
		e.Execution.CommandSHA256 = auditrecord.Hash(e.Command)
		e.Details = &auditrecord.Details{CorrelationID: "correlation", Reason: canary, State: canary, ApprovedChange: []byte(canary), SessionSHA256: auditrecord.Hash([]byte(canary))}
		raw, _ = json.Marshal(e)
		receipt, err := s.Preserve(context.Background(), raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		ref := ExportReference{e.EventID, e.EventType, auditrecord.Hash(raw), receipt.Manifest}
		p, err := Project(raw, ref)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := p.JSON()
		if strings.Contains(string(b), canary) || strings.Contains(string(b), "approved_change") || strings.Contains(string(b), "session_sha256") || len(p.CommandSummary) > 80 || p.RedactionRuleVersion != RedactionRuleVersion {
			t.Fatal("sensitive content reached projection")
		}
	}
	if CommandSummary([]byte("id")) != "id [arguments redacted]" || CommandSummary([]byte("/bin/bash -s")) != "bash [arguments redacted]" || CommandSummary([]byte("custom SECRET")) != "[command redacted]" {
		t.Fatal("summary vocabulary changed")
	}
}

func TestExporterReplayDeletionOutageAndNoScriptRead(t *testing.T) {
	s, a, _, now := testService(t)
	raw, attachments := testRecord(t, now, []byte("VEYPORT_SECRET_SCRIPT_CANARY"))
	if _, err := s.Preserve(context.Background(), raw, attachments); err != nil {
		t.Fatal(err)
	}
	gov := s.config.GovernanceArchive.(*memoryArchive)
	sink := &memorySink{docs: map[string]Projection{}}
	worker := &Exporter{Index: serviceIndex{s}, Archives: map[string]ProjectionReader{a.q.Bucket: a, gov.q.Bucket: gov}, Sink: sink, Now: func() time.Time { return now }, CheckpointPath: filepath.Join(t.TempDir(), "checkpoint.json")}
	if worker.Step(context.Background()) != nil || len(sink.docs) != 1 {
		t.Fatal("initial export failed")
	}
	for _, key := range a.readKeys {
		if strings.HasPrefix(key, "attachments/") {
			t.Fatal("redactor read script bytes")
		}
	}
	sink.docs = map[string]Projection{}
	now = now.Add(6 * time.Second)
	if worker.Step(context.Background()) != nil || len(sink.docs) != 1 {
		t.Fatal("empty search index was not replayed")
	}
	sink.unavailable = true
	now = now.Add(6 * time.Second)
	if worker.Step(context.Background()) == nil || worker.Checkpoint.Failure != "search_unavailable" || worker.Checkpoint.PendingOccurredAt.IsZero() {
		t.Fatal("outage/lag not reported")
	}
	if !errors.Is(worker.Step(context.Background()), ErrBusy) {
		t.Fatal("retry has no backoff")
	}
	// Search failure has no authority over archival or execution admission.
	raw, _ = testRecord(t, now, nil)
	var e auditrecord.Envelope
	_ = json.Unmarshal(raw, &e)
	e.EventID = "event-2"
	raw, _ = json.Marshal(e)
	if _, err := s.Preserve(context.Background(), raw, nil); err != nil {
		t.Fatal("search outage gated independent archive")
	}
	sink.unavailable = false
	now = now.Add(6 * time.Second)
	if worker.Step(context.Background()) != nil || len(sink.docs) != 2 {
		t.Fatal("outage recovery failed")
	}
	stat, err := os.Stat(worker.CheckpointPath)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("checkpoint not private")
	}
	restored := &Exporter{CheckpointPath: worker.CheckpointPath}
	if restored.LoadCheckpoint() != nil || restored.Checkpoint.Accepted != worker.Checkpoint.Accepted {
		t.Fatal("checkpoint lost")
	}
}

func TestExportIndexScopeAndCursorBounds(t *testing.T) {
	h, s, _, now := testHandler(t)
	auth, err := NewAuthenticator([]Credential{{ID: "export", TokenSHA256: auditrecord.Hash([]byte(strings.Repeat("e", 32))), Scope: ScopeExport}, {ID: "ingest", TokenSHA256: auditrecord.Hash([]byte(strings.Repeat("i", 32))), Scope: ScopeIngest}})
	if err != nil {
		t.Fatal(err)
	}
	h.auth = auth
	raw, _ := testRecord(t, now, nil)
	if _, err := s.Preserve(context.Background(), raw, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/export-index?limit=33", "/v1/export-index?after=../envelopes", "/v1/export-index?prefix=envelopes/", "/v1/export-index?limit=1&limit=2"} {
		if callHandler(h, "GET", path, strings.Repeat("e", 32), nil).Code != 400 {
			t.Fatal("unbounded/arbitrary enumeration accepted")
		}
	}
	if callHandler(h, "GET", "/v1/export-index", strings.Repeat("i", 32), nil).Code != 401 || callHandler(h, "GET", "/v1/ready", strings.Repeat("e", 32), nil).Code != 401 || callHandler(h, "POST", "/v1/records", strings.Repeat("e", 32), raw).Code != 401 || callHandler(h, "POST", "/v1/originals", strings.Repeat("e", 32), raw).Code != 401 {
		t.Fatal("scopes crossed")
	}
	w := callHandler(h, "GET", "/v1/export-index?limit=1", strings.Repeat("e", 32), nil)
	var page ExportPage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Records) != 1 || strings.Contains(w.Body.String(), "SYNTHETIC_SECRET_actor") || strings.Contains(w.Body.String(), "command") {
		t.Fatal("index exposed raw content")
	}
}

func TestProjectionOptionalIdentityAndDenialSubmission(t *testing.T) {
	now := time.Now().UTC()
	actor := auditrecord.Actor{UserID: "operator", PersonID: "person", Name: "Operator"}
	for _, typ := range []string{auditrecord.PolicyResult, auditrecord.ExecutionDenial} {
		e := auditrecord.Envelope{SchemaVersion: 1, EventID: "result", EventType: typ, Actor: actor, PolicyVersion: 1, PolicySHA256: auditrecord.Hash(nil), OccurredAt: now, Details: &auditrecord.Details{CorrelationID: "correlation", RequestID: "request", RequestSHA256: auditrecord.Hash(nil), State: "denied"}}
		if typ == auditrecord.ExecutionDenial {
			e.Details.Submission = &auditrecord.SubmissionBinding{NodeID: "target", NodeName: "Target", CommandBytes: 4, CommandSHA256: auditrecord.Hash([]byte("true"))}
		}
		raw, _ := json.Marshal(e)
		ref := ExportReference{e.EventID, e.EventType, auditrecord.Hash(raw), auditrecord.ObjectRef{Bucket: "archive", Key: "manifests/result", VersionID: "v1", SHA256: auditrecord.Hash(nil), RetainUntil: now.Add(time.Hour)}}
		p, err := Project(raw, ref)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := p.JSON()
		if p.UID != nil || p.GID != nil || strings.Contains(string(body), `"uid"`) || p.RunAs != "" {
			t.Fatal("absent identity presented as root")
		}
		if typ == auditrecord.ExecutionDenial && (p.NodeID != "target" || p.CommandBytes != 4 || p.CommandSHA256 == "" || p.ProcessState != "denied") {
			t.Fatal("denial target/hash omitted")
		}
	}
	if metadataText("operator\nsecret", 256) != "[metadata omitted]" || metadataText(strings.Repeat("x", 257), 256) != "[metadata omitted]" {
		t.Fatal("unbounded metadata")
	}
}
