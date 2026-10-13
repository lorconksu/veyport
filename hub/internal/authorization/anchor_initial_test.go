package authorization

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestInitialStandardRequiresAuthenticatedAbsenceWhenGovernanceConfigured(t *testing.T) {
	for _, tc := range []struct {
		name       string
		evidence   *fakeEvidence
		configured bool
		allowed    bool
	}{
		{"standalone", nil, false, true},
		{"authenticated-absence", &fakeEvidence{}, true, true},
		{"outage", &fakeEvidence{anchorErr: errors.New("connection unavailable")}, true, false},
		{"invalid-response", &fakeEvidence{anchorErr: auditgate.ErrReceipt}, true, false},
		{"existing-enrollment", &fakeEvidence{anchor: PolicyAnchor{InstallationID: "installation", Version: 2}}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := store.New(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			cfg := TransitionConfig{InstallationID: "installation", EnrollmentPath: filepath.Join(dir, "marker.json")}
			if tc.configured {
				cfg.Evidence = tc.evidence
			}
			s := New(st)
			err = s.ValidateAnchor(context.Background(), cfg)
			if (err == nil) != tc.allowed {
				t.Fatalf("initial anchor validation: %v", err)
			}
			state, err := st.GetPolicyState()
			if err != nil || state.State != "standard" {
				t.Fatalf("read-only validation mutated initial policy: %+v %v", state, err)
			}
		})
	}
}
