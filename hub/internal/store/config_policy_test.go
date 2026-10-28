package store

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/lockout"
)

func TestAccountPolicyDefaultsOnlyForMissingKeys(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	policy, err := s.AccountPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy != lockout.Defaults() {
		t.Fatalf("missing keys did not use defaults: %#v", policy)
	}
	for _, query := range []string{
		"ALTER TABLE _config RENAME TO unavailable_account_policy_config",
		"CREATE VIEW _config AS SELECT key,value FROM missing_account_policy_config",
	} {
		if _, err := s.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AccountPolicy(); err == nil {
		t.Fatal("unavailable policy store silently used defaults")
	}
}
