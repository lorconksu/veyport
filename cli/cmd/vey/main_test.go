package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// captureOutput redirects os.Stdout and os.Stderr for the duration of fn and
// returns what was written to each, mirroring the pattern used by
// hub/cmd/veyport's admin_test.go.
func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()

	origOut, origErr := os.Stdout, os.Stderr

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}

	os.Stdout, os.Stderr = outW, errW
	defer func() {
		os.Stdout, os.Stderr = origOut, origErr
	}()

	fn()

	outW.Close()
	errW.Close()

	outBytes, err := io.ReadAll(outR)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	errBytes, err := io.ReadAll(errR)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(outBytes), string(errBytes)
}

// TestRun_UnknownCommand verifies an unrecognized subcommand exits 2 with a
// stderr message naming the command plus a usage hint
// (specs/004-cli-connector/tasks.md T008).
func TestRun_UnknownCommand(t *testing.T) {
	var code int
	_, stderr := captureOutput(t, func() {
		code = run([]string{"bogus"})
	})

	if code != cmdutil.ExitUsage {
		t.Errorf("exit code = %d, want %d (ExitUsage)", code, cmdutil.ExitUsage)
	}
	if !strings.Contains(stderr, `unknown command "bogus"`) {
		t.Errorf("stderr = %q, want it to contain unknown command message", stderr)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("stderr = %q, want it to contain a usage hint", stderr)
	}
}

// TestRun_Version verifies --version exits 0 and prints the version.
func TestRun_Version(t *testing.T) {
	var code int
	stdout, _ := captureOutput(t, func() {
		code = run([]string{"--version"})
	})

	if code != cmdutil.ExitOK {
		t.Errorf("exit code = %d, want %d (ExitOK)", code, cmdutil.ExitOK)
	}
	if !strings.Contains(stdout, "vey ") {
		t.Errorf("stdout = %q, want it to contain the version string", stdout)
	}
}

// TestRun_Version_ShortFlag verifies -v is accepted as an alias for
// --version.
func TestRun_Version_ShortFlag(t *testing.T) {
	var code int
	captureOutput(t, func() {
		code = run([]string{"-v"})
	})

	if code != cmdutil.ExitOK {
		t.Errorf("exit code = %d, want %d (ExitOK)", code, cmdutil.ExitOK)
	}
}

// TestRun_Bare verifies invoking vey with no arguments exits 2 with usage on
// stderr.
func TestRun_Bare(t *testing.T) {
	var code int
	_, stderr := captureOutput(t, func() {
		code = run(nil)
	})

	if code != cmdutil.ExitUsage {
		t.Errorf("exit code = %d, want %d (ExitUsage)", code, cmdutil.ExitUsage)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("stderr = %q, want it to contain usage", stderr)
	}
}

// TestRun_Help verifies --help exits 0 and prints usage to stdout (not
// stderr).
func TestRun_Help(t *testing.T) {
	var code int
	stdout, stderr := captureOutput(t, func() {
		code = run([]string{"--help"})
	})

	if code != cmdutil.ExitOK {
		t.Errorf("exit code = %d, want %d (ExitOK)", code, cmdutil.ExitOK)
	}
	if !strings.Contains(stdout, "usage:") {
		t.Errorf("stdout = %q, want it to contain usage", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty on --help", stderr)
	}
}

// TestRun_KnownCommandsDispatch verifies every registered command name
// reaches its stub (currently "not implemented") rather than being rejected
// as unknown, and that the global --hub/--json flags are accepted ahead of
// the subcommand.
func TestRun_KnownCommandsDispatch(t *testing.T) {
	for _, name := range []string{"login", "logout", "status", "servers", "files", "logs", "audit"} {
		t.Run(name, func(t *testing.T) {
			var code int
			_, stderr := captureOutput(t, func() {
				code = run([]string{"--hub", "https://hub.example.com", "--json", name})
			})

			if code == cmdutil.ExitUsage {
				t.Errorf("exit code = %d (ExitUsage), want the command to be recognized (stderr: %q)", code, stderr)
			}
			if strings.Contains(stderr, "unknown command") {
				t.Errorf("stderr = %q, want no unknown-command message for registered command %q", stderr, name)
			}
		})
	}
}
