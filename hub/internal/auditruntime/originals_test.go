package auditruntime_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auditruntime"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/testaudit"
)

func TestOriginalArchiveUsesDistinctReaderAndExactHistoricalDestinationWithoutTransport(t *testing.T) {
	f := testaudit.New(t, nil)
	next := testaudit.New(t, f.Clock)
	oldCredential, _ := json.Marshal(f.Credential)
	newCredential, _ := json.Marshal(next.Credential)
	runtime, err := auditruntime.Load(f.ConfigFile(t, next.Config), auditruntime.Options{
		Now: f.Clock.Now, // No spool, gateway, agents or execution store are available.
		ResolveSecret: func(ref string) (string, string, error) {
			switch ref {
			case "old-credential":
				return "destination", string(oldCredential), nil
			case "new-credential":
				return "destination", string(newCredential), nil
			default:
				return "", "", os.ErrNotExist
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	policy := model.AuditPolicy{Profile: "enhanced", Nodes: []string{"retired-node"}, RuntimeSeconds: 60, RetentionHours: 24, Destination: f.Config.Endpoint, CredentialRef: "old-credential", TrustKeyIDs: []string{"fixture-key"}, QualificationSHA256: f.Config.QualificationSHA256}
	old := model.PolicyVersion{Version: 2, Policy: policy, SHA256: auditrecord.Digest(policy)}
	ctx := context.Background()
	archive, err := runtime.ResolveOriginalArchive(ctx, old)
	if err != nil || archive.Ingest == nil || archive.Admin == nil || archive.Reader == nil || archive.Verifier == nil {
		t.Fatalf("historical read required execution transport: %+v %v", archive, err)
	}
	now := f.Clock.Now()
	command := []byte("true # synthetic fixture; no process launched")
	admission := auditrecord.Envelope{SchemaVersion: 1, EventID: "synthetic-historical-admission", EventType: auditrecord.ExecutionAdmission, Actor: auditrecord.Actor{UserID: "fixture-actor", PersonID: "fixture-person"}, PolicyVersion: old.Version, PolicySHA256: old.SHA256, OccurredAt: now, Command: command, Execution: &auditrecord.ExecutionBinding{ExecutionID: "fixture-execution", PreparationID: "fixture-preparation", BootID: "fixture-boot", NodeID: "retired-node", Identity: auditrecord.Identity{Username: "fixture", UID: 1000, GID: 1000, Groups: []uint32{1000}, GroupsSHA256: auditrecord.Hash([]byte("groups")), IdentitySHA256: auditrecord.Hash([]byte("identity")), Home: "/home/fixture", Shell: "/bin/sh", CWD: "/home/fixture"}, CommandSHA256: auditrecord.Hash(command), CommandBytes: int64(len(command)), PreparedUntil: now.Add(time.Minute), Limits: auditrecord.Limits{MaxFrameBytes: 64 << 10, MaxBufferBytes: 2 << 20, RuntimeSeconds: 60, TermGraceSeconds: 3, BlockedConsumerSeconds: 30}}}
	payload, _ := json.Marshal(admission)
	admissionReceipt, err := archive.Ingest.Preserve(ctx, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	admissionExpected, _, err := auditrecord.ExpectedFor(payload)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := archive.Admin.Manifest(ctx, admission.EventID, admissionExpected.RecordSHA256, admissionReceipt.Manifest)
	if err != nil || auditrecord.Hash(manifest) != admissionReceipt.Manifest.SHA256 {
		t.Fatalf("exact historical manifest: %v", err)
	}
	var metadata auditrecord.Manifest
	if err := json.Unmarshal(manifest, &metadata); err != nil {
		t.Fatal(err)
	}
	ref := metadata.Envelope
	envelope := auditrecord.Envelope{SchemaVersion: 1, EventID: "historical-read-intent", EventType: auditrecord.OriginalReadIntent, Actor: auditrecord.Actor{UserID: "reader", PersonID: "person-reader"}, PolicyVersion: old.Version, PolicySHA256: old.SHA256, OccurredAt: now, Details: &auditrecord.Details{CorrelationID: "synthetic-investigation", SessionSHA256: auditrecord.Hash([]byte("test-session")), Reason: "Investigate exact synthetic historical original", Originals: []auditrecord.ObjectRef{ref}, State: "requested"}}
	raw, _ := json.Marshal(envelope)
	receipt, err := archive.Ingest.Preserve(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected, _, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Verifier.Verify(receipt.Token, expected, now); err != nil {
		t.Fatal(err)
	}
	read, err := archive.Reader.ReadOriginal(ctx, ref, receipt.Token)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(read)
	read.Close()
	if err != nil || string(b) != string(payload) {
		t.Fatalf("exact original mismatch: %q %v", b, err)
	}
	for _, client := range []*auditgate.Client{archive.Ingest.(*auditgate.Client), archive.Admin.(*auditgate.Client)} {
		if reader, err := client.ReadOriginal(ctx, ref, receipt.Token); err == nil {
			reader.Close()
			t.Fatal("write/admin credential retrieved an original")
		}
	}
	if _, err := archive.Reader.(*auditgate.Client).Preserve(ctx, raw, nil); err == nil {
		t.Fatal("original reader credential preserved a record")
	}
	if _, err := archive.Reader.(*auditgate.Client).Manifest(ctx, admission.EventID, admissionExpected.RecordSHA256, admissionReceipt.Manifest); err == nil {
		t.Fatal("original reader credential retrieved administrative metadata")
	}
	newPolicy := policy
	newPolicy.Destination, newPolicy.CredentialRef = next.Config.Endpoint, "new-credential"
	newVersion := model.PolicyVersion{Version: 3, Policy: newPolicy, SHA256: auditrecord.Digest(newPolicy)}
	newArchive, err := runtime.ResolveOriginalArchive(ctx, newVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newArchive.Admin.Manifest(ctx, admission.EventID, admissionExpected.RecordSHA256, admissionReceipt.Manifest); err == nil {
		t.Fatal("new destination supplied old destination's manifest")
	}
	next.SetFault("ready")
	if _, err := runtime.ResolveOriginalArchive(ctx, old); err != nil {
		t.Fatalf("new destination outage broke historical resolution: %v", err)
	}
	if len(next.Originals.Envelopes()) != 0 || len(f.Governance.Envelopes()) != 0 {
		t.Fatal("historical intent redirected to new destination or fixed governance bucket")
	}
	f.SetFault("ready")
	if _, err := runtime.ResolveOriginalArchive(ctx, old); err == nil {
		t.Fatal("old destination outage fell back to another destination")
	}
	f.SetFault("")
	f.Clock.Advance(2 * time.Minute)
	if reader, err := archive.Reader.ReadOriginal(ctx, ref, receipt.Token); err == nil {
		reader.Close()
		t.Fatal("historical resolution renewed an expired original-read permission")
	}
}

func TestOriginalArchiveMissingAndSharedReaderCredentialsFailClosed(t *testing.T) {
	f := testaudit.New(t, nil)
	for _, mode := range []string{"reader-is-admin", "reader-is-ingest", "partial-reader"} {
		t.Run(mode, func(t *testing.T) {
			cfg := f.Config
			switch mode {
			case "reader-is-admin":
				cfg.Clients.OriginalReader = cfg.Clients.Admin
			case "reader-is-ingest":
				cfg.Clients.OriginalReader = cfg.Clients.Ingest
			case "partial-reader":
				cfg.Clients.OriginalReader.KeyPath = ""
			}
			raw, _ := json.Marshal(auditruntime.FileConfig{EndpointConfig: cfg})
			path := filepath.Join(t.TempDir(), "runtime.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if runtime, err := auditruntime.Load(path, auditruntime.Options{}); err == nil {
				runtime.Close()
				t.Fatal("shared or partial original-reader credential accepted")
			}
		})
	}
	h := newHarness(t)
	version := model.PolicyVersion{Version: 2, Policy: h.policy, SHA256: auditrecord.Digest(h.policy)}
	for _, mutate := range []func(*model.PolicyVersion){
		func(p *model.PolicyVersion) { p.Version = 0 },
		func(p *model.PolicyVersion) { p.SHA256 = auditrecord.Hash([]byte("edited")) },
		func(p *model.PolicyVersion) {
			p.Policy.CredentialRef = "missing"
			p.SHA256 = auditrecord.Digest(p.Policy)
		},
		func(p *model.PolicyVersion) {
			p.Policy.TrustKeyIDs = []string{"unknown"}
			p.SHA256 = auditrecord.Digest(p.Policy)
		},
	} {
		candidate := version
		mutate(&candidate)
		if _, err := h.runtime.ResolveOriginalArchive(context.Background(), candidate); err == nil {
			t.Fatal("modified historical policy authority accepted")
		}
	}
	for _, files := range []auditruntime.ClientFiles{h.fixture.Config.Clients.Admin, h.fixture.Config.Clients.OriginalReader} {
		certificate, err := os.ReadFile(files.CertificatePath)
		if err != nil {
			t.Fatal(err)
		}
		key, err := os.ReadFile(files.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(auditruntime.DestinationCredential{CertificatePEM: string(certificate), PrivateKeyPEM: string(key)})
		h.credential = string(raw)
		if _, err := h.runtime.ResolveOriginalArchive(context.Background(), version); err == nil {
			t.Fatal("destination credential substituted an administrative/read principal")
		}
	}
	// Reader absence affects original access, while execution preservation remains
	// independently configured and Standard can still run standalone.
	f.Config.Clients.OriginalReader = auditruntime.ClientFiles{}
	credential, _ := json.Marshal(f.Credential)
	runtime, err := auditruntime.Load(f.ConfigFile(t), auditruntime.Options{ResolveSecret: func(string) (string, string, error) { return "destination", string(credential), nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	version.Policy.Destination = f.Config.Endpoint
	version.SHA256 = auditrecord.Digest(version.Policy)
	if _, err := runtime.ResolveArchive(context.Background(), version); err != nil {
		t.Fatalf("missing reader blocked independent execution archive: %v", err)
	}
	if _, err := runtime.ResolveOriginalArchive(context.Background(), version); err == nil {
		t.Fatal("missing reader silently borrowed another credential")
	}
}
