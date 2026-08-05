package commands

// Coverage for `vey login` (login.go RunLogin) beyond the non-TTY path
// already pinned in json_test.go (TestJSONLogin_NonTTY_NoPromptNoNetwork).
//
// RunLogin's TTY branch (store/client construction, then the full
// auth.Login three-leg flow) can only be entered when os.Stdin is attached
// to a real terminal — cmdutil.IsTTY(os.Stdin) checks the fd directly via
// term.IsTerminal, and auth.Login repeats an equivalent check internally
// before it will build a prompter. There is no Prompter seam at the
// RunLogin/auth.Login boundary (auth.Login always builds its own
// NewTerminalPrompter when the caller supplies none), so a fake prompter
// is not available at this level and the full interactive success path
// (username/password/TOTP round trip) is not exercised here.
//
// What is reachable without a real terminal or fake prompter:
//   - RequireHub failing before the TTY check is ever reached.
//   - Opening a real pty (openTestPTY below) to make cmdutil.IsTTY(os.Stdin)
//     true, which lets two of RunLogin's TTY-gated branches run for real:
//     credential-store construction failing, and it succeeding followed by
//     auth.Login itself failing (here, on an immediate EOF read for the
//     username prompt, which is the cheapest deterministic way to end the
//     flow without needing to feed prompt answers with the write-then-read
//     synchronization a full flow would require).
//
// login.go's success-print path (a completed sign-in) remains unreachable
// under this constraint and is reported as such by the coverage sweep.

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// TestLogin_NoHubExitUsage covers RunLogin's RequireHub failure branch: no
// hub configured, which fails before the TTY check or any store/client
// construction.
func TestLogin_NoHubExitUsage(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")
	ctx, stdout, stderr := newCmdContext("", t.TempDir(), false, nil)
	code := RunLogin(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

// openTestPTY allocates a real pty pair (master, slave) using only
// golang.org/x/sys/unix (already a direct module dependency), so
// cmdutil.IsTTY sees a genuine terminal fd without needing an external pty
// library. The master is closed by the caller (directly, or implicitly by
// t.Cleanup) to signal EOF to readers on the slave.
func openTestPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("cannot open /dev/ptmx (no pty support in this environment): %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		t.Skipf("cannot unlock pty: %v", err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		master.Close()
		t.Skipf("cannot read pty number: %v", err)
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", n)
	slave, err = os.OpenFile(slavePath, os.O_RDWR, 0)
	if err != nil {
		master.Close()
		t.Skipf("cannot open pty slave %s: %v", slavePath, err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

// withStdin swaps os.Stdin for f for the duration of the test, restoring
// the original on cleanup.
func withStdin(t *testing.T, f *os.File) {
	t.Helper()
	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old })
}

// TestLogin_TTY_EmptyConfigDir_StoreConstructionError covers RunLogin's
// store-construction error branch: with a real TTY attached, IsTTY is true
// and auth.NewStore is reached, which fails outright when ConfigDir is
// empty (auth.NewStore: "config directory is empty") — the cheapest
// deterministic way to fail store construction without touching the
// filesystem's permission bits.
func TestLogin_TTY_EmptyConfigDir_StoreConstructionError(t *testing.T) {
	master, slave := openTestPTY(t)
	defer master.Close()
	withStdin(t, slave)

	if !cmdutil.IsTTY(os.Stdin) {
		t.Skip("pty slave did not present as a TTY in this environment")
	}

	ctx, stdout, stderr := newCmdContext("https://hub.example.com", "", false, nil)
	code := RunLogin(ctx)
	if code != cmdutil.ExitError {
		t.Fatalf("exit code = %d, want %d (ExitError); stdout=%q stderr=%q", code, cmdutil.ExitError, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

// TestLogin_TTY_StoreConstructionSucceeds_EOFAtPrompt covers RunLogin's
// success continuation after store/client construction (ConfigDir valid):
// execution reaches auth.Login, which fails once the username prompt reads
// a blank line. The master is written to (a bare newline, queued in the
// pty's canonical-mode buffer) before RunLogin ever runs, and stays open
// for the rest of the test — closing it would deallocate the pty pair and
// make the slave stop presenting as a terminal, defeating the TTY check
// this test exists to exercise.
func TestLogin_TTY_StoreConstructionSucceeds_EOFAtPrompt(t *testing.T) {
	master, slave := openTestPTY(t)
	defer master.Close()
	withStdin(t, slave)

	if !cmdutil.IsTTY(os.Stdin) {
		t.Skip("pty slave did not present as a TTY in this environment")
	}
	if _, err := master.Write([]byte("\n")); err != nil {
		t.Fatalf("writing blank username line to pty master: %v", err)
	}

	ctx, stdout, stderr := newCmdContext("https://hub.example.com", t.TempDir(), false, nil)
	code := RunLogin(ctx)
	// auth.Login rejects the blank username as a usage error ("username is
	// required"), proving store/client construction (and the call into
	// auth.Login) both ran for real.
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}
