package commands

// Coverage for the keyring-fallback warning's scope: it must print only
// during `vey login` (login_test.go's
// TestLogin_TTY_StoreConstructionSucceeds_EOFAtPrompt covers that side),
// and never from any other command, even when the credential store falls
// back to the file backend. Every other command reaches auth.NewStore
// through the shared newAuthContext helper (status.go), which now passes a
// nil warnW; a headless CI box that reruns any of these commands on every
// invocation must not see the warning repeated per-process.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// errKeyringUnavailableForTest is a distinct sentinel (not shared with
// internal/auth's own tests, which run in a separate process) so a failure
// here is unambiguously traceable to this file's mock.
var errKeyringUnavailableForTest = errors.New("mock: keyring unavailable (commands package tests)")

// TestNonLoginCommands_NoKeyringWarningOnStderr forces the file backend
// deterministically (keyring.MockInitWithError, mirroring the pattern
// internal/auth's own tests use) and then drives every command that shares
// newAuthContext far enough to construct a credential store, asserting none
// of them ever write the fallback warning. The hub is a real (empty)
// httptest server so the post-store-construction network calls a few of
// these commands make fail fast with a 404 instead of hanging on DNS.
func TestNonLoginCommands_NoKeyringWarningOnStderr(t *testing.T) {
	// api_token mode would skip newAuthContext's precedence logic in ways
	// unrelated to this test; pin the environment so every case resolves
	// however its own args and stub server dictate, not an inherited
	// ambient token.
	t.Setenv("VEYPORT_TOKEN", "")
	keyring.MockInitWithError(errKeyringUnavailableForTest)

	srv := httptest.NewServer(http.NewServeMux())
	defer srv.Close()

	cases := map[string]struct {
		args []string
		run  func(ctx *Context) int
	}{
		"status":  {nil, RunStatus},
		"servers": {[]string{"list"}, RunServers},
		"logout":  {nil, RunLogout},
		"files":   {[]string{"ls", "srv-1", "/var/log"}, RunFiles},
		"logs":    {[]string{"tail", "srv-1", "/var/log/app.log"}, RunLogs},
		"audit":   {[]string{"export"}, RunAudit},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assertNoKeyringWarning(t, srv.URL, tc.args, tc.run)
		})
	}
}

// assertNoKeyringWarning runs one command to completion (its exit code is
// irrelevant here — reaching newAuthContext's store construction is enough
// to have triggered the warning were it not suppressed) and fails the test
// if the fallback warning reached stderr.
func assertNoKeyringWarning(t *testing.T, hubURL string, args []string, run func(ctx *Context) int) {
	t.Helper()
	ctx, _, stderr := newCmdContext(hubURL, t.TempDir(), false, args)
	_ = run(ctx)

	const warning = "OS keyring unavailable"
	if strings.Contains(stderr.String(), warning) {
		t.Errorf("stderr = %q, must not contain the keyring-fallback warning outside vey login", stderr.String())
	}
}
