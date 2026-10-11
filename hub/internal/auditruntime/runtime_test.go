package auditruntime_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auditruntime"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/sshgw"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/testaudit"
	"github.com/wyiu/veyport/hub/internal/userca"
	"github.com/wyiu/veyport/proto/protectedinput"
)

type testSpool struct{ unavailable bool }

func (s *testSpool) Ready() error {
	if s.unavailable {
		return protectedinput.ErrUnavailable
	}
	return nil
}
func (*testSpool) Create() (protectedinput.File, error) { return nil, protectedinput.ErrUnavailable }

type harness struct {
	fixture    *testaudit.Fixture
	runtime    *auditruntime.Runtime
	store      *store.Store
	spool      *testSpool
	protected  map[string]bool
	credential string
	policy     model.AuditPolicy
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	f := testaudit.New(t, nil)
	st, err := store.New(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err = st.CreateServer(&model.Server{ID: "node", Name: "synthetic node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	h := &harness{fixture: f, store: st, spool: &testSpool{}, protected: map[string]bool{"node": true}}
	raw, _ := json.Marshal(f.Credential)
	h.credential = string(raw)
	h.runtime, err = auditruntime.Load(f.ConfigFile(t), auditruntime.Options{Store: st, Spool: h.spool, GatewayReady: func() bool { return true }, SupportsProtected: func(node string) bool { return h.protected[node] }, ResolveSecret: func(ref string) (string, string, error) {
		if ref != "secret-1" {
			return "", "", os.ErrNotExist
		}
		return "destination", h.credential, nil
	}, Now: f.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	h.policy = model.AuditPolicy{Profile: "enhanced", Nodes: []string{"node"}, RuntimeSeconds: 60, RetentionHours: 24, Destination: f.Config.Endpoint, CredentialRef: "secret-1", TrustKeyIDs: []string{"fixture-key"}, QualificationSHA256: f.Config.QualificationSHA256}
	return h
}

func TestReadinessIsReadOnlyAndExplicitQualificationPreservesSyntheticEvidence(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for range 3 {
		if err := h.runtime.Evidence().Ready(ctx, h.policy); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.fixture.Originals.Envelopes()) != 0 || len(h.fixture.Governance.Envelopes()) != 0 {
		t.Fatal("readiness polling wrote protected records")
	}
	if err := h.runtime.Evidence().Qualify(ctx, h.policy); err != nil {
		t.Fatal(err)
	}
	records := h.fixture.Originals.Envelopes()
	if len(records) != 1 || records[0].EventType != auditrecord.ExecutionLifecycle || records[0].Details.State != "synthetic-readiness-no-process" || len(records[0].Command) != 0 || len(records[0].Attachments) != 0 {
		t.Fatalf("probe looked like execution admission: %+v", records)
	}
	version := model.PolicyVersion{Version: 2, Policy: h.policy, SHA256: auditrecord.Digest(h.policy)}
	gate, err := h.runtime.ResolveArchive(ctx, version)
	if err != nil || gate.Preserver == nil || gate.Verifier == nil {
		t.Fatalf("archive resolver: %v", err)
	}
	version.SHA256 = auditrecord.Hash([]byte("edited"))
	if _, err = h.runtime.ResolveArchive(ctx, version); err == nil {
		t.Fatal("edited stored policy accepted")
	}
}

func TestTransportReadinessCoversActorOrNodeAndActualSpool(t *testing.T) {
	h := newHarness(t)
	user := &model.User{ID: "admin-actor", Username: "admin-actor", Email: "admin@test.invalid", Role: model.RoleAdmin, TOTPEnabled: true}
	if err := h.store.CreateUser(user); err != nil {
		t.Fatal(err)
	}
	if err := h.store.CreateServer(&model.Server{ID: "second", Name: "second", Status: "offline", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	p := h.policy
	p.Actors = []string{user.ID}
	p.Nodes = nil
	if err := h.runtime.Evidence().Ready(context.Background(), p); !errors.Is(err, authorization.ErrNotReady) {
		t.Fatalf("actor-only skipped authorized unprotected node: %v", err)
	}
	h.protected["second"] = true
	if err := h.runtime.Evidence().Ready(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	h.spool.unavailable = true
	if err := h.runtime.Evidence().Ready(context.Background(), p); !errors.Is(err, authorization.ErrNotReady) {
		t.Fatalf("unencrypted spool ready: %v", err)
	}
	h.spool.unavailable = false
	p.Nodes = []string{"missing"}
	if err := h.runtime.Evidence().Ready(context.Background(), p); err == nil {
		t.Fatal("unknown scoped node ready")
	}
}

func TestRuntimeReadinessTracksActualGatewayBindFailureAndStop(t *testing.T) {
	h := newHarness(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { occupied.Close() })
	ca, err := userca.InitUserCA(h.store, "synthetic-runtime-storage-key")
	if err != nil {
		t.Fatal(err)
	}
	key, err := userca.InitHostKey(h.store, "synthetic-runtime-storage-key")
	if err != nil {
		t.Fatal(err)
	}
	gateway := sshgw.New(sshgw.Config{Store: h.store, UserCA: ca, HostKey: key, Enabled: true, Addr: occupied.Addr().String()})
	runtime, err := auditruntime.Load(h.fixture.ConfigFile(t), auditruntime.Options{Store: h.store, Spool: h.spool, GatewayReady: gateway.Ready, SupportsProtected: func(string) bool { return true }, ResolveSecret: func(string) (string, string, error) { return "destination", h.credential, nil }, Now: h.fixture.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.Start(); err == nil {
		t.Fatal("occupied SSH listener unexpectedly bound")
	}
	if err := runtime.Evidence().Ready(context.Background(), h.policy); !errors.Is(err, authorization.ErrNotReady) {
		t.Fatalf("failed SSH listener reported ready: %v", err)
	}
	occupied.Close()
	served := make(chan error, 1)
	go func() { served <- gateway.Start() }()
	t.Cleanup(func() { gateway.Stop(context.Background()) })
	deadline := time.Now().Add(time.Second)
	for !gateway.Ready() {
		select {
		case err := <-served:
			t.Fatalf("SSH listener stopped before becoming ready: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("SSH listener did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	if err := runtime.Evidence().Ready(context.Background(), h.policy); err != nil {
		t.Fatalf("live SSH listener not ready: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gateway.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if err := runtime.Evidence().Ready(context.Background(), h.policy); !errors.Is(err, authorization.ErrNotReady) {
		t.Fatalf("closed SSH listener reported ready: %v", err)
	}
}

func TestCandidateDestinationFailuresCannotCreateAdmission(t *testing.T) {
	h := newHarness(t)
	for _, test := range []struct {
		name   string
		change func(*model.AuditPolicy)
	}{
		{"unlisted destination", func(p *model.AuditPolicy) { p.Destination = "https://127.0.0.1:1" }},
		{"qualification substitution", func(p *model.AuditPolicy) { p.QualificationSHA256 = auditrecord.Hash([]byte("wrong")) }},
		{"unapproved signing key", func(p *model.AuditPolicy) { p.TrustKeyIDs = []string{"wrong-key"} }},
		{"duplicate signing key", func(p *model.AuditPolicy) { p.TrustKeyIDs = []string{"fixture-key", "fixture-key"} }},
		{"unknown credential", func(p *model.AuditPolicy) { p.CredentialRef = "secret-missing" }},
		{"insufficient retention", func(p *model.AuditPolicy) { p.RetentionHours = 48 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := h.policy
			test.change(&p)
			if err := h.runtime.Test(context.Background(), p); err == nil {
				t.Fatal("unsafe candidate passed")
			}
		})
	}
	for _, credential := range []string{`{"bearer":"short"}`, `{"bearer":"` + strings.Repeat("a", 32) + `","certificate_pem":"mixed"}`, `{"certificate_pem":"invalid","private_key_pem":"invalid"}`, `{"Bearer":"` + strings.Repeat("a", 32) + `"}`, `{"bearer":"one","bearer":"two"}`} {
		h.credential = credential
		if err := h.runtime.Test(context.Background(), h.policy); err == nil {
			t.Fatalf("unsafe credential passed: %s", credential)
		}
	}
	if len(h.fixture.Originals.Envelopes()) != 0 {
		t.Fatal("invalid candidates produced execution evidence")
	}
}

func TestCandidateServiceFailureAndInvalidReceiptFailClosed(t *testing.T) {
	for _, fault := range []string{"ready", "ingest", "receipt"} {
		t.Run(fault, func(t *testing.T) {
			h := newHarness(t)
			h.fixture.SetFault(fault)
			if err := h.runtime.Test(context.Background(), h.policy); err == nil {
				t.Fatal("failed destination passed")
			}
		})
	}
}

func TestGovernanceAuthorityDoesNotFollowExecutionDestination(t *testing.T) {
	h := newHarness(t)
	second := testaudit.New(t, h.fixture.Clock)
	raw, _ := json.Marshal(second.Credential)
	runtime, err := auditruntime.Load(h.fixture.ConfigFile(t, second.Config), auditruntime.Options{Store: h.store, Spool: h.spool, GatewayReady: func() bool { return true }, SupportsProtected: func(string) bool { return true }, ResolveSecret: func(ref string) (string, string, error) {
		if ref == "secret-1" {
			return "destination", h.credential, nil
		}
		return "destination", string(raw), nil
	}, Now: h.fixture.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	evidence := runtime.Evidence()
	anchor := auditrecord.Envelope{SchemaVersion: 1, EventID: "change-policy.anchor", EventType: auditrecord.PolicyAnchor, Actor: auditrecord.Actor{UserID: "officer", PersonID: "person-officer"}, PolicyVersion: 2, PolicySHA256: auditrecord.Digest(h.policy), OccurredAt: h.fixture.Clock.Now(), Details: &auditrecord.Details{CorrelationID: "change", RequestID: "change", RequestSHA256: auditrecord.Hash([]byte("exact approved change")), InstallationID: "installation", ExpectedPolicyVersion: 1, NewPolicyVersion: 2}}
	anchorRaw, _ := json.Marshal(anchor)
	if _, err = evidence.Preserve(context.Background(), anchorRaw); err != nil {
		t.Fatal(err)
	}
	p := h.policy
	p.Destination = second.Config.Endpoint
	p.CredentialRef = "secret-2"
	if err = runtime.Test(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(second.Originals.Envelopes()) != 1 || len(second.Governance.Envelopes()) != 0 {
		t.Fatal("execution test redirected governance")
	}
	old := model.PolicyVersion{Version: 2, Policy: h.policy, SHA256: auditrecord.Digest(h.policy)}
	if _, err = runtime.ResolveArchive(context.Background(), old); err != nil {
		t.Fatalf("old immutable archive configuration lost: %v", err)
	}
	if err = runtime.Test(context.Background(), old.Policy); err != nil {
		t.Fatalf("old lifecycle preservation lost old credential: %v", err)
	}
	if len(h.fixture.Originals.Envelopes()) != 1 || len(second.Originals.Envelopes()) != 1 {
		t.Fatal("old destination evidence was redirected")
	}
	h.fixture.Originals.SetFailed(true)
	if err = runtime.Evidence().Ready(context.Background(), p); err != nil {
		t.Fatalf("fixed governance inherited retired originals outage: %v", err)
	}
	latest, err := evidence.Anchor(context.Background(), "installation")
	if err != nil || latest.Version != 2 || latest.SHA256 != anchor.PolicySHA256 {
		t.Fatalf("lost fixed authority anchor: %+v %v", latest, err)
	}
	second.SetFault("anchor")
	if _, err = evidence.Anchor(context.Background(), "installation"); err != nil {
		t.Fatalf("new archive outage redirected authority: %v", err)
	}
	h.fixture.SetFault("anchor")
	if _, err = evidence.Anchor(context.Background(), "installation"); err == nil || errors.Is(err, auditgate.ErrAnchorNotFound) {
		t.Fatalf("authority outage used empty new destination: %v", err)
	}
}

func TestPrivateConfigurationRejectsUnsafeFilesAndAmbiguousJSON(t *testing.T) {
	f := testaudit.New(t, nil)
	path := f.ConfigFile(t)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := auditruntime.Load(path, auditruntime.Options{}); err == nil {
		t.Fatal("public private configuration accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "runtime-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := auditruntime.Load(link, auditruntime.Options{}); err == nil {
		t.Fatal("symlink configuration accepted")
	}
	for _, raw := range []string{`{"endpoint":"first","endpoint":"second"}`, `{"Endpoint":"https://127.0.0.1:1"}`, `{"unknown":true}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := auditruntime.Load(path, auditruntime.Options{}); err == nil {
			t.Fatal("ambiguous operator configuration accepted")
		}
	}
	if _, err := auditruntime.Load(f.ConfigFile(t, f.Config), auditruntime.Options{}); err == nil {
		t.Fatal("duplicate destination accepted")
	}
}

func TestPrivateConfigurationRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := auditruntime.Load(path, auditruntime.Options{})
		finished <- err
	}()
	select {
	case err := <-finished:
		if !errors.Is(err, auditruntime.ErrConfiguration) {
			t.Fatalf("FIFO configuration accepted: %v", err)
		}
	case <-time.After(time.Second):
		// Unblock an incorrectly blocking reader before reporting the regression.
		f, _ := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if f != nil {
			f.Close()
		}
		t.Fatal("configuration loader waited for a FIFO writer")
	}
}

func TestArchiveClientReuseIsBoundedAndRechecksImmutableSecret(t *testing.T) {
	h := newHarness(t)
	available := true
	credential := h.credential
	runtime, err := auditruntime.Load(h.fixture.ConfigFile(t), auditruntime.Options{Store: h.store, Spool: h.spool, GatewayReady: func() bool { return true }, SupportsProtected: func(string) bool { return true }, ResolveSecret: func(string) (string, string, error) {
		if !available {
			return "", "", os.ErrNotExist
		}
		return "destination", credential, nil
	}, Now: h.fixture.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	for range 5 {
		if err := runtime.Test(context.Background(), h.policy); err != nil {
			t.Fatal(err)
		}
	}
	if count, _ := h.fixture.Connections(); count != 2 {
		t.Fatalf("same immutable policy recreated TLS connections: %d", count)
	}
	available = false
	version := model.PolicyVersion{Version: 2, Policy: h.policy, SHA256: auditrecord.Digest(h.policy)}
	if _, err := runtime.ResolveArchive(context.Background(), version); err == nil {
		t.Fatal("cached client bypassed missing restored credential reference")
	}
	available = true
	credential = `{"bearer":"short"}`
	if _, err := runtime.ResolveArchive(context.Background(), version); err == nil {
		t.Fatal("cached client substituted old credential bytes")
	}
	credential = h.credential
	for i := range 40 {
		p := h.policy
		p.CredentialRef = fmt.Sprintf("secret:synthetic-cache-%d", i)
		if err := runtime.Test(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	_, live := h.fixture.Connections()
	for live > 33 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		_, live = h.fixture.Connections()
	}
	if live > 33 {
		t.Fatalf("evicted clients retained idle TLS connections: %d", live)
	}
	runtime.Close()
	deadline = time.Now().Add(time.Second)
	_, live = h.fixture.Connections()
	for live != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		_, live = h.fixture.Connections()
	}
	if live != 0 {
		t.Fatalf("runtime shutdown retained idle connections: %d", live)
	}
}

func TestOperatorTrustAndCredentialSeparationCannotBeOverridden(t *testing.T) {
	f := testaudit.New(t, nil)
	for _, test := range []struct {
		name   string
		change func(*auditruntime.EndpointConfig)
	}{
		{"invalid URL", func(c *auditruntime.EndpointConfig) { c.Endpoint = "https://%invalid" }},
		{"HTTP", func(c *auditruntime.EndpointConfig) { c.Endpoint = "http://127.0.0.1:1" }},
		{"path", func(c *auditruntime.EndpointConfig) { c.Endpoint += "/elsewhere" }},
		{"query", func(c *auditruntime.EndpointConfig) { c.Endpoint += "?override=true" }},
		{"unreadable CA", func(c *auditruntime.EndpointConfig) { c.CAPath = "missing.pem" }},
		{"invalid CA", func(c *auditruntime.EndpointConfig) { c.CAPath = c.SigningPublicKeyPath }},
		{"private signing material", func(c *auditruntime.EndpointConfig) { c.SigningPublicKeyPath = c.Clients.Ingest.KeyPath }},
		{"unknown public key file", func(c *auditruntime.EndpointConfig) { c.SigningPublicKeyPath = "missing.pem" }},
		{"duplicate signing trust", func(c *auditruntime.EndpointConfig) {
			c.SigningPublicKeys = []auditruntime.PublicKeyFile{{ID: c.SigningKeyID, Path: c.SigningPublicKeyPath}}
		}},
		{"wrong qualification pin", func(c *auditruntime.EndpointConfig) { c.QualificationSHA256 = "invalid" }},
		{"DNS without address pin", func(c *auditruntime.EndpointConfig) {
			c.Endpoint = "https://archive.invalid:443"
			c.AllowedAddresses = nil
		}},
		{"link-local address pin", func(c *auditruntime.EndpointConfig) { c.AllowedAddresses = []string{"169.254.169.254"} }},
		{"missing admin credential", func(c *auditruntime.EndpointConfig) { c.Clients.Admin.KeyPath = "missing.pem" }},
		{"invalid admin credential", func(c *auditruntime.EndpointConfig) { c.Clients.Admin.KeyPath = c.CAPath }},
		{"shared write-admin principal", func(c *auditruntime.EndpointConfig) { c.Clients.Admin = c.Clients.Ingest }},
		{"missing ingestion credential", func(c *auditruntime.EndpointConfig) { c.Clients.Ingest.CertificatePath = "missing.pem" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := f.Config
			test.change(&config)
			raw, _ := json.Marshal(auditruntime.FileConfig{EndpointConfig: config})
			path := filepath.Join(t.TempDir(), "runtime.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := auditruntime.Load(path, auditruntime.Options{}); err == nil {
				t.Fatal("unsafe operator trust accepted")
			}
		})
	}
}

func TestActorPermissionScopeAndPagedGlobalReadiness(t *testing.T) {
	h := newHarness(t)
	u := &model.User{ID: "assigned-actor", Username: "assigned-actor", Email: "assigned@test.invalid", Role: model.RoleViewer}
	if err := h.store.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.DB().Exec("INSERT INTO permissions(id,user_id,server_id,path) VALUES('assignment',?,'node','/')", u.ID); err != nil {
		t.Fatal(err)
	}
	p := h.policy
	p.Nodes = nil
	p.Actors = []string{u.ID}
	for n := range 260 {
		id := fmt.Sprintf("page-node-%03d", n)
		if err := h.store.CreateServer(&model.Server{ID: id, Name: id, Status: "online", Labels: "{}"}); err != nil {
			t.Fatal(err)
		}
		h.protected[id] = true
	}
	h.protected["page-node-259"] = false
	if err := h.runtime.Evidence().Ready(context.Background(), p); err != nil {
		t.Fatalf("unassigned node blocked actor-only scope: %v", err)
	}
	p.Actors = nil
	if err := h.runtime.Evidence().Ready(context.Background(), p); err == nil {
		t.Fatal("global readiness skipped failing node beyond first page")
	}
	h.protected["page-node-259"] = true
	if err := h.runtime.Evidence().Ready(context.Background(), p); err != nil {
		t.Fatalf("qualified global scope: %v", err)
	}
}
