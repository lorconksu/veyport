package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestGovernanceHTTPInitialSnapshotCannotEraseExternalEnrollment(t *testing.T) {
	h := newGovernanceHTTP(t)
	snapshot := filepath.Join(t.TempDir(), "initial.db")
	if _, err := h.s.store.DB().Exec("VACUUM INTO ?", snapshot); err != nil {
		t.Fatal(err)
	}
	tokens := make(map[string]string, len(h.tokens))
	for id, token := range h.tokens {
		tokens[id] = token
	}
	h.apply(t, h.approve(t, h.request(t, h.bootstrapPayload(), 1)), 200)
	latest, err := h.runtime.Evidence().Anchor(context.Background(), h.s.securityTransition.InstallationID)
	if err != nil || latest.Version != 2 {
		t.Fatalf("independent enrolled authority: %+v %v", latest, err)
	}
	before := len(h.archive.Governance.Envelopes())
	for _, fault := range []string{"", "anchor", "admin-auth"} {
		t.Run("latest-anchor-"+fault, func(t *testing.T) {
			// Each copy is the exact pre-enrollment SQLite snapshot. Its restored
			// private directory has the same installation ID and no marker.
			raw, err := os.ReadFile(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "restored.db")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			st, err := store.New(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			s := New(Config{Store: st, JWTSecret: h.s.jwtSecret, StorageKey: h.s.storageKey, IsDev: true})
			s.SetClock(h.clock.Now)
			t.Cleanup(func() { s.Shutdown(context.Background()) })
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			s.securityTransition = authorization.TransitionConfig{Evidence: h.runtime.Evidence(), InstallationID: h.s.securityTransition.InstallationID, EnrollmentPath: filepath.Join(dir, "enhanced-enrollment.json")}
			h.archive.SetFault(fault)
			t.Cleanup(func() { h.archive.SetFault("") })
			api := httptest.NewServer(s.routes())
			t.Cleanup(api.Close)
			restored := &governanceHTTP{s: s, api: api, tokens: tokens, clients: h.clients}
			response := restored.call(t, "GET", "/api/audit-policy", "officer", nil, 200)
			var result struct {
				GovernanceEnrolled bool            `json:"governance_enrolled"`
				Readiness          map[string]bool `json:"readiness"`
			}
			decodeResult(t, response, &result)
			state, err := st.GetPolicyState()
			if err != nil || state.Active.Version != 1 || state.State != "standard" || result.GovernanceEnrolled || result.Readiness["governance"] || result.Readiness["enrollment_marker"] || len(h.archive.Governance.Envelopes()) != before {
				t.Fatalf("restored readiness bypassed anchor or mutated state: %s state=%+v err=%v", response, state, err)
			}
			service := authorization.New(st)
			if err := service.Startup(context.Background(), s.securityTransition); !errors.Is(err, authorization.ErrRecovery) {
				t.Fatalf("restored initial snapshot reopened Standard: %v", err)
			}
			state, err = st.GetPolicyState()
			if err != nil || state.State != "recovery_required" {
				t.Fatalf("startup did not freeze restored policy: %+v %v", state, err)
			}
			if _, err := service.PolicyForExecution("officer", "synthetic-node"); !errors.Is(err, authorization.ErrRecovery) {
				t.Fatalf("restored initial policy admitted execution: %v", err)
			}
		})
	}
}
