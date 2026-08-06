package commands

import (
	"testing"
)

// TestContext_RequireHub_CachesResolution covers RequireHub's cache-hit
// branch (c.HubURL != ""): every other test in this package calls
// RequireHub at most once per Context, so the second-call short-circuit is
// otherwise never exercised.
func TestContext_RequireHub_CachesResolution(t *testing.T) {
	c, _, _ := newCmdContext("https://hub.example.com", t.TempDir(), false, nil)

	first, err := c.RequireHub()
	if err != nil {
		t.Fatalf("RequireHub (first call): %v", err)
	}
	if first != "https://hub.example.com" {
		t.Fatalf("first RequireHub() = %q, want %q", first, "https://hub.example.com")
	}
	if c.HubSource != "flag" {
		t.Fatalf("HubSource = %q, want %q", c.HubSource, "flag")
	}

	// Blank out hubFlag's effect indirectly: mutate HubSource so a
	// re-resolution (were it to happen) would be observable, then confirm
	// the second call returns the cached value without re-deriving it.
	c.HubSource = "mutated-to-detect-recomputation"
	second, err := c.RequireHub()
	if err != nil {
		t.Fatalf("RequireHub (second call): %v", err)
	}
	if second != first {
		t.Fatalf("second RequireHub() = %q, want the cached %q", second, first)
	}
	if c.HubSource != "mutated-to-detect-recomputation" {
		t.Errorf("HubSource = %q, want it left untouched by the cached second call", c.HubSource)
	}
}
