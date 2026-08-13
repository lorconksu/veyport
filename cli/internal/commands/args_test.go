package commands

// Coverage for the shared no-argument guard (args.go) and login's
// default-hub persistence (login.go persistDefaultHub). Both pin fixes for a
// real field failure (T026 staging run, 2026-08-12): `vey login --hub <url>`
// placed the global flag after the subcommand and login silently ignored it,
// and even a correctly-flagged login left the config file untouched, so the
// very next bare command failed with ErrNoHub.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/config"
)

// TestNoArgCommandsRejectStrayArguments pins the guard for every command
// whose surface is "no arguments, no flags": a stray positional or a
// misplaced global flag is a usage error, never silently ignored.
func TestNoArgCommandsRejectStrayArguments(t *testing.T) {
	cases := []struct {
		name string
		run  func(*Context) int
		args []string
		want string // substring of the stderr diagnostic
	}{
		{"login positional", RunLogin, []string{"extra"}, "takes no arguments"},
		{"login misplaced --hub", RunLogin, []string{"--hub", "https://h.example.com"}, "before the subcommand"},
		{"logout positional", RunLogout, []string{"extra"}, "takes no arguments"},
		{"logout misplaced --hub", RunLogout, []string{"--hub", "https://h.example.com"}, "before the subcommand"},
		{"status positional", RunStatus, []string{"extra"}, "takes no arguments"},
		{"status misplaced --json", RunStatus, []string{"--json"}, "before the subcommand"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Hub deliberately configured: the arg guard must fire before
			// hub resolution, store construction, or any network use.
			ctx, stdout, stderr := newCmdContext("https://h.example.com", t.TempDir(), false, tc.args)
			code := tc.run(ctx)
			if code != cmdutil.ExitUsage {
				t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q",
					code, cmdutil.ExitUsage, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.want)
			}
		})
	}
}

// TestPersistDefaultHub_WritesConfigFile: after a successful login the hub
// must be recorded as default_hub so follow-up bare commands resolve it —
// the exact gap hit on staging (login OK, then `vey ssh-cert` → ErrNoHub).
func TestPersistDefaultHub_WritesConfigFile(t *testing.T) {
	ctx, _, stderr := newCmdContext("https://h.example.com", t.TempDir(), false, nil)
	if _, err := ctx.RequireHub(); err != nil {
		t.Fatalf("RequireHub: %v", err)
	}

	persistDefaultHub(ctx)

	cfg, err := config.Load(ctx.ConfigPath())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultHub != "https://h.example.com" {
		t.Errorf("default_hub = %q, want %q; stderr=%q", cfg.DefaultHub, "https://h.example.com", stderr.String())
	}
}

// TestPersistDefaultHub_NoRewriteWhenAlreadyCurrent: logging into the hub
// that is already the default must not rewrite the config file (idempotent
// re-login, mirroring the store's replace-in-place semantics).
func TestPersistDefaultHub_NoRewriteWhenAlreadyCurrent(t *testing.T) {
	seeded := config.Config{DefaultHub: "https://h.example.com"}
	ctx, _, _ := newCmdContext("", t.TempDir(), false, nil)
	ctx.Config = seeded
	if err := config.Save(ctx.ConfigPath(), seeded); err != nil {
		t.Fatalf("seed Save: %v", err)
	}
	before := mustStat(t, ctx.ConfigPath())

	if _, err := ctx.RequireHub(); err != nil { // resolves from config
		t.Fatalf("RequireHub: %v", err)
	}
	persistDefaultHub(ctx)

	after := mustStat(t, ctx.ConfigPath())
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("config file was rewritten for an unchanged default_hub")
	}
}

// TestPersistDefaultHub_UpdatesStaleDefault: logging into a different hub
// moves default_hub to the hub just signed into (last-login-wins; the old
// hub's credentials remain stored and reachable via --hub).
func TestPersistDefaultHub_UpdatesStaleDefault(t *testing.T) {
	ctx, _, _ := newCmdContext("https://new.example.com", t.TempDir(), false, nil)
	ctx.Config = config.Config{DefaultHub: "https://old.example.com"}
	if err := config.Save(ctx.ConfigPath(), ctx.Config); err != nil {
		t.Fatalf("seed Save: %v", err)
	}
	if _, err := ctx.RequireHub(); err != nil {
		t.Fatalf("RequireHub: %v", err)
	}

	persistDefaultHub(ctx)

	cfg, err := config.Load(ctx.ConfigPath())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultHub != "https://new.example.com" {
		t.Errorf("default_hub = %q, want the newly signed-in hub", cfg.DefaultHub)
	}
}

// TestPersistDefaultHub_SaveFailureWarnsButDoesNotFail: the login itself
// succeeded and credentials are stored, so a config-write failure degrades
// to a stderr warning carrying the manual remediation — never a failed
// login (persistDefaultHub has no error return by design).
func TestPersistDefaultHub_SaveFailureWarnsButDoesNotFail(t *testing.T) {
	ctx, _, stderr := newCmdContext("https://h.example.com", t.TempDir(), false, nil)
	if _, err := ctx.RequireHub(); err != nil {
		t.Fatalf("RequireHub: %v", err)
	}
	// A regular file where ConfigDir should be: Save's MkdirAll fails.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ctx.ConfigDir = filepath.Join(blocker, "vey")

	persistDefaultHub(ctx)

	if !strings.Contains(stderr.String(), "default_hub") {
		t.Errorf("stderr = %q, want a warning mentioning default_hub", stderr.String())
	}
}

// mustStat is a fatal-on-error os.Stat for modtime comparisons.
func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi
}
