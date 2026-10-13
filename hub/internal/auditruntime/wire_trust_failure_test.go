package auditruntime_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auditruntime"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/testaudit"
)

func TestValidOperatorTrustSubstitutionCannotPassActualTLSOrQualification(t *testing.T) {
	h := newHarness(t)
	other := testaudit.New(t, nil)
	for _, mismatch := range []struct {
		name   string
		change func(*auditruntime.EndpointConfig)
	}{
		{"different_real_ca", func(c *auditruntime.EndpointConfig) { c.CAPath = other.Config.CAPath }},
		{"different_original_qualification", func(c *auditruntime.EndpointConfig) {
			c.QualificationSHA256 = auditrecord.Hash([]byte("other-qualified-originals"))
		}},
		{"different_governance_qualification", func(c *auditruntime.EndpointConfig) {
			c.GovernanceQualificationSHA256 = auditrecord.Hash([]byte("other-qualified-governance"))
		}},
	} {
		t.Run(mismatch.name, func(t *testing.T) {
			config := h.fixture.Config
			mismatch.change(&config)
			raw, err := json.Marshal(auditruntime.FileConfig{EndpointConfig: config})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "runtime.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			runtime, err := auditruntime.Load(path, auditruntime.Options{ResolveSecret: func(string) (string, string, error) { return "destination", h.credential, nil }, Now: h.fixture.Clock.Now})
			if err != nil {
				t.Fatalf("structurally valid configuration did not reach wire trust validation: %v", err)
			}
			t.Cleanup(runtime.Close)
			policy := h.policy
			policy.QualificationSHA256 = config.QualificationSHA256
			openedBefore, _ := h.fixture.Connections()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := runtime.Evidence().GovernanceReady(ctx); err == nil {
				t.Fatal("real service accepted substituted authority trust")
			}
			if err := runtime.Test(ctx, policy); err == nil {
				t.Fatal("real qualified-write test accepted substituted trust")
			}
			if _, err := runtime.ResolveArchive(ctx, model.PolicyVersion{Version: 7, Policy: policy, SHA256: auditrecord.Digest(policy)}); err == nil {
				t.Fatal("historical execution archive substituted unverified trust")
			}
			openedAfter, _ := h.fixture.Connections()
			if openedAfter <= openedBefore {
				t.Fatal("test never reached the actual scoped TLS endpoint")
			}
			if len(h.fixture.Originals.Envelopes()) != 0 || len(h.fixture.Governance.Envelopes()) != 0 {
				t.Fatal("failed wire trust produced retained evidence")
			}
		})
	}
	if err := h.runtime.Test(context.Background(), h.policy); err != nil {
		t.Fatalf("restored exact operator trust did not recover qualification: %v", err)
	}
	if originals := h.fixture.Originals.Envelopes(); len(originals) != 1 || originals[0].EventType != auditrecord.ExecutionLifecycle || originals[0].Details.State != "synthetic-readiness-no-process" || len(h.fixture.Governance.Envelopes()) != 0 {
		t.Fatal("recovery did not preserve only an explicitly synthetic readiness record")
	}
}
