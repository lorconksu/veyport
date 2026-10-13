package store_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestInitialStandardPolicyIsTheOnlyDigestlessCompatibilityRecord(t *testing.T) {
	for _, corruption := range []struct {
		name string
		sql  string
	}{
		{"later_standard", "INSERT INTO audit_policy_versions(version,payload,digest) SELECT 2,payload,'' FROM audit_policy_versions WHERE version=1"},
		{"later_enhanced", `INSERT INTO audit_policy_versions(version,payload,digest) VALUES(2,'{"profile":"enhanced"}','')`},
		{"initial_approved_request", "UPDATE audit_policy_versions SET request_id='claimed-approved-request' WHERE version=1"},
		{"initial_enhanced", `UPDATE audit_policy_versions SET payload='{"profile":"enhanced"}' WHERE version=1`},
		{"initial_missing_fields", `UPDATE audit_policy_versions SET payload='{"profile":"standard"}' WHERE version=1`},
		{"initial_reencoded", "UPDATE audit_policy_versions SET payload=payload||' ' WHERE version=1"},
		{"initial_changed_runtime", `UPDATE audit_policy_versions SET payload=json_set(payload,'$.runtime_seconds',1) WHERE version=1`},
		{"initial_invalid_json", `UPDATE audit_policy_versions SET payload='{' WHERE version=1`},
	} {
		t.Run(corruption.name, func(t *testing.T) {
			s := testStore(t)
			initial, err := s.GetPolicyVersion(1)
			if err != nil || initial.Policy.Profile != "standard" || initial.Policy.RuntimeSeconds != 3600 || initial.Policy.RetentionHours != 24 || initial.SHA256 == "" {
				t.Fatalf("genuine migration policy rejected: %+v %v", initial, err)
			}
			settings := s.GetAuditSettings()
			settings.RetentionDays++
			if err := s.UpdateAuditSettings(settings); err != nil {
				t.Fatalf("initial Standard settings compatibility lost: %v", err)
			}
			var original []byte
			if err := s.DB().QueryRow("SELECT payload FROM audit_policy_versions WHERE version=1").Scan(&original); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec(corruption.sql); err != nil {
				t.Fatal(err)
			}
			version := uint64(1)
			if corruption.name == "later_standard" || corruption.name == "later_enhanced" {
				version = 2
			}
			if _, err := s.GetPolicyVersion(version); !errors.Is(err, store.ErrPolicyIntegrity) {
				t.Fatalf("noninitial digestless policy accepted: %v", err)
			}
			if enrolled, err := s.GovernanceEnrolled(); !errors.Is(err, store.ErrPolicyIntegrity) || enrolled {
				t.Fatalf("unverified history supplied enrollment authority: %v %v", enrolled, err)
			}
			settings.RetentionDays++
			if err := s.UpdateAuditSettings(settings); !errors.Is(err, store.ErrPolicyIntegrity) {
				t.Fatalf("legacy settings mutation accepted unverified history: %v", err)
			}
			if got := s.GetAuditSettings(); got.RetentionDays == settings.RetentionDays {
				t.Fatal("refused mutation changed retention settings")
			}
			if _, err := s.DB().Exec("DELETE FROM audit_policy_versions WHERE version>1"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest='',request_id='' WHERE version=1", original); err != nil {
				t.Fatal(err)
			}
			if repaired, err := s.GetPolicyVersion(1); err != nil || repaired.SHA256 != initial.SHA256 {
				t.Fatalf("exact original policy repair rejected: %+v %v", repaired, err)
			}
			if err := s.UpdateAuditSettings(settings); err != nil {
				t.Fatalf("exact repair did not restore initial settings compatibility: %v", err)
			}
			var digest string
			if err := s.DB().QueryRow("SELECT digest FROM audit_policy_versions WHERE version=1").Scan(&digest); err != nil || digest != "" {
				t.Fatalf("reader modified the legacy record: %q %v", digest, err)
			}
		})
	}
}

func TestExecutionPolicyValidatorImmutableBindingAllowsLocalReentry(t *testing.T) {
	s := testStore(t)
	state, err := s.GetPolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateExecutionPolicy(state); err != nil {
		t.Fatalf("standalone initial policy refused: %v", err)
	}
	var calls atomic.Int32
	var reentryErr atomic.Bool
	const authority = "immutable-installation-and-private-directory"
	if err := s.InstallExecutionPolicyValidator(authority, func(policy model.PolicyState) error {
		calls.Add(1)
		// Both reads and a same-key construction may reenter the store; no
		// database transaction or binding mutex can be held around this call.
		if _, err := s.GetPolicyState(); err != nil {
			reentryErr.Store(true)
		}
		if err := s.InstallExecutionPolicyValidator(authority, func(model.PolicyState) error { panic("binding replaced") }); err != nil {
			reentryErr.Store(true)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			if err := s.InstallExecutionPolicyValidator(authority, func(model.PolicyState) error { panic("binding replaced") }); err != nil {
				reentryErr.Store(true)
			}
			if err := s.InstallExecutionPolicyValidator("substituted-authority", func(model.PolicyState) error { panic("binding replaced") }); !errors.Is(err, store.ErrPolicyIntegrity) {
				reentryErr.Store(true)
			}
			if err := s.ValidateExecutionPolicy(state); err != nil {
				reentryErr.Store(true)
			}
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("local policy validation deadlocked during reentry")
	}
	if reentryErr.Load() || calls.Load() != 24 {
		t.Fatalf("concurrent constructors replaced or blocked the validator: calls=%d errors=%v", calls.Load(), reentryErr.Load())
	}
	if err := s.InstallExecutionPolicyValidator("", nil); !errors.Is(err, store.ErrPolicyIntegrity) {
		t.Fatalf("validator binding could be cleared: %v", err)
	}
	if err := s.WithInteractivePolicy(func() error { return s.ValidateExecutionPolicy(state) }); err != nil {
		t.Fatalf("validator could not run inside ordered interactive admission: %v", err)
	}
}

func TestUnconfiguredNoninitialPolicyCannotSupplyExecutionAuthority(t *testing.T) {
	s := testStore(t)
	var raw []byte
	if err := s.DB().QueryRow("SELECT payload FROM audit_policy_versions WHERE version=1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec("INSERT INTO audit_policy_versions(version,payload,digest) VALUES(2,?,?)", raw, store.SecurityDigest(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec("UPDATE audit_policy_state SET active_version=2 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	state, err := s.GetPolicyState()
	if err != nil {
		t.Fatalf("status cannot inspect unconfigured policy: %v", err)
	}
	if err := s.ValidateExecutionPolicy(state); !errors.Is(err, store.ErrPolicyIntegrity) {
		t.Fatalf("unconfigured later Standard reopened execution: %v", err)
	}
	if _, err := s.DB().Exec("UPDATE audit_policy_state SET active_version=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	state, err = s.GetPolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateExecutionPolicy(state); !errors.Is(err, store.ErrPolicyIntegrity) {
		t.Fatalf("historical enrollment was mistaken for standalone initial policy: %v", err)
	}
}
