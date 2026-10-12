package updateutil

import (
	"strings"
	"testing"
)

func TestBootstrapOriginalRequiresCompleteComparableExactIdentity(t *testing.T) {
	for _, o := range []BootstrapOriginal{{}, {Version: "0.1.0", SHA256: strings.Repeat("a", 64)}, {Version: "v0.1.0", SHA256: strings.Repeat("0", 64)}, {Version: "0.1.0+" + strings.Repeat("a", 121), SHA256: strings.Repeat("a", 64)}} {
		if err := o.Validate(); err != nil {
			t.Fatal(o, err)
		}
	}
	for _, o := range []BootstrapOriginal{{Version: "0.1.0"}, {SHA256: strings.Repeat("a", 64)}, {Version: "dev", SHA256: strings.Repeat("a", 64)}, {Version: "0.1.0", SHA256: strings.Repeat("A", 64)}, {Version: "0.1.0", SHA256: strings.Repeat("z", 64)}, {Version: "0.1.0", SHA256: "a"}, {Version: "0.1.0+" + strings.Repeat("a", 122), SHA256: strings.Repeat("a", 64)}} {
		if err := o.Validate(); err == nil {
			t.Fatal("ambiguous original assertion accepted", o)
		}
	}
}
