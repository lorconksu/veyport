package auth_test

// Secret-hygiene sweep (spec 004-cli-connector T032, FR-017 / SC-006):
// "credentials MUST never be written to logs, error messages, or --json
// output", and "zero credential material appears in any log, error output, or
// structured output across the full automated test suite".
//
// This is the end-to-end assertion layer, not a re-implementation of any
// redaction logic (auth.scrubSecret in login.go already covers the one
// channel the CLI does not control — the hub's {"error": "..."} text). Every
// command path is driven against a stub hub with recording stdout/stderr
// writers, in both human and --json mode, and afterwards every stream, every
// error string, and the on-disk credential store are scanned for every piece
// of secret material that was in play:
//
//	password, one-time code, TOTP challenge token, TOTP setup token,
//	API token, access token, every refresh token the stub minted, and the
//	SSH private key `vey ssh-cert` generates or reuses.
//
// Refresh tokens and the SSH private key are the two kinds allowed to reach
// disk (004 data-model.md "StoredSession", 005 data-model.md "Stored SSH
// material"); nothing is allowed to reach stdout or stderr.
//
// Placement: this file lives in package auth_test (the external test package
// of internal/auth) and imports internal/commands. That is legal and
// cycle-free — commands depends on auth, auth does not depend on commands,
// and an external test package may import a package that depends on the
// package under test. It keeps the file at the path T032 specifies while
// still driving the real command entry points.
//
// One deliberate seam: `vey login`'s happy path cannot be driven through
// commands.RunLogin, because RunLogin requires os.Stdin to be a real terminal
// (cmdutil.IsTTY) and standing up a PTY is platform-specific. The three-leg
// flow is therefore driven through auth.Login — the exact function RunLogin
// calls — with a prompter that writes the same prompt text to the recording
// stderr, and the resulting error is rendered through a real cmdutil.Printer
// exactly as RunLogin renders it. RunLogin's own non-TTY path is exercised
// end to end, and the real terminal prompter's writer output is exercised
// separately (the login/terminal-prompter-no-echo-failure scenario).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/commands"
	"github.com/wyiu/veyport/cli/internal/config"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

// --- sentinels ------------------------------------------------------------
//
// Every value here is long and distinctive so a substring hit in captured
// output is a genuine leak rather than a coincidence. The one short value is
// the six-digit one-time code, which is short because real ones are.

const (
	sentinelUsername = "alice"
	sentinelRole     = "admin"

	sentinelPassword = "hunter2-Sup3rSecret!"
	sentinelTOTPCode = "918273"

	// sentinelTOTPToken and sentinelSetupToken are the hub's intermediate
	// login credentials. Neither is persisted and neither may be echoed.
	sentinelTOTPToken  = "ttk-EphemeralChallenge-77281f0a"
	sentinelSetupToken = "stk-EnrollmentRedirect-55219b3c"

	// The two API-token sources auth.Resolve consults (R6 precedence):
	// VEYPORT_TOKEN and the hub profile's api_token.
	sentinelEnvAPIToken    = "adt_deadbeefcafe1234567890abcdef"
	sentinelConfigAPIToken = "adt_c0nf1gfacefeed0987654321fedc"

	// apiTokenPrefixLen is the number of leading characters `vey status` is
	// allowed to show (auth.AuthContext.TokenPrefix, and the
	// Secrets row of contracts/cli-commands.md: "token *prefix* only").
	apiTokenPrefixLen = 8
)

// --- secret registry ------------------------------------------------------

// secretKind names a class of credential for failure messages. The kind is
// reported, never the value.
type secretKind string

const (
	kindPassword     secretKind = "password"
	kindTOTPCode     secretKind = "one-time code"
	kindTOTPToken    secretKind = "TOTP challenge token"
	kindSetupToken   secretKind = "TOTP setup token"
	kindAPIToken     secretKind = "API token"
	kindAccessToken  secretKind = "access token"
	kindRefreshToken secretKind = "refresh token"
	// kindSSHPrivateKey is 005-ssh-gateway's addition: the ed25519 key
	// `vey ssh-cert` generates. Like the refresh token it legitimately
	// reaches the credential store (data-model.md "Stored SSH material") and,
	// like the refresh token, it may never reach stdout, stderr, or an error.
	kindSSHPrivateKey secretKind = "SSH private key"
)

// secret is one piece of credential material in play for a scenario.
type secret struct {
	kind  secretKind
	value string
	// onDiskOK marks the two kinds that legitimately reach the credential
	// store: the refresh token and the SSH private key (data-model.md —
	// access tokens, passwords, one-time codes and API tokens are never
	// persisted by the CLI).
	onDiskOK bool
}

// vault collects the secrets a scenario put in play, including the ones the
// stub hub mints at request time.
type vault struct {
	mu sync.Mutex
	s  []secret
}

// newVault seeds the static sentinels every scenario shares.
func newVault() *vault {
	v := &vault{}
	v.add(kindPassword, sentinelPassword, false)
	v.add(kindTOTPCode, sentinelTOTPCode, false)
	v.add(kindTOTPToken, sentinelTOTPToken, false)
	v.add(kindSetupToken, sentinelSetupToken, false)
	v.add(kindAPIToken, sentinelEnvAPIToken, false)
	v.add(kindAPIToken, sentinelConfigAPIToken, false)
	return v
}

func (v *vault) add(kind secretKind, value string, onDiskOK bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.s = append(v.s, secret{kind: kind, value: value, onDiskOK: onDiskOK})
}

func (v *vault) snapshot() []secret {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]secret, len(v.s))
	copy(out, v.s)
	return out
}

// redact renders a secret for a failure message: an 8-character prefix at
// most, so a failing test names the leak without republishing it. Values at
// or below the prefix length are withheld entirely.
func redact(s string) string {
	if len(s) <= apiTokenPrefixLen {
		return fmt.Sprintf("<%d-byte value withheld>", len(s))
	}
	return s[:apiTokenPrefixLen] + "…"
}

// scan fails when any secret appears verbatim in haystack. skipOnDiskOK drops
// the refresh token from the sweep, for the one destination it is allowed to
// reach.
func scan(t *testing.T, scenario, where, haystack string, secrets []secret, skipOnDiskOK bool) {
	t.Helper()
	for _, s := range secrets {
		if skipOnDiskOK && s.onDiskOK {
			continue
		}
		if s.value == "" {
			continue
		}
		if strings.Contains(haystack, s.value) {
			t.Errorf("SECRET LEAK in scenario %s: a %s (%d bytes, starts %q) appears in %s",
				scenario, s.kind, len(s.value), redact(s.value), where)
		}
	}
}

// scanDir sweeps every regular file under dir. Only the credential store and
// its lock file live there, but the walk is deliberately indiscriminate: a
// stray temp file or debug dump would be just as much of a leak.
func scanDir(t *testing.T, scenario, dir string, secrets []secret) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scan(t, scenario, "the on-disk file "+filepath.Base(path), string(data), secrets, true)
		return nil
	})
	if err != nil {
		t.Fatalf("%s: walking the credential directory: %v", scenario, err)
	}
}

// --- stub hub -------------------------------------------------------------

// stubHub is the recording hub every scenario runs against. It mints the
// access/refresh tokens itself and registers each one in the vault, so the
// sweep covers the values that actually crossed the wire rather than a
// hardcoded guess.
//
// Two of its handlers are deliberately hostile: POST /api/auth/login and
// POST /api/auth/login/totp echo the submitted password and one-time code
// back inside their {"error": "..."} envelope. That is the exact channel
// auth.scrubSecret documents itself as guarding, so the sweep proves the
// guard rather than assuming it.
type stubHub struct {
	v   *vault
	mux *http.ServeMux
	srv *httptest.Server

	mu sync.Mutex
	// gen counts token rotations, so every minted pair is distinguishable in
	// a leak report.
	gen int
	// bearers is the set of Authorization values the hub currently accepts.
	bearers map[string]bool
	// refresh is the refresh token the hub considers live; anything else is
	// a revoked/rotated token.
	refresh string

	// Scenario knobs, all read under mu.
	wantPassword  string
	wantCode      string
	setupRedirect bool
	refreshStatus int
}

func newStubHub(t *testing.T, v *vault) *stubHub {
	t.Helper()

	h := &stubHub{
		v:            v,
		mux:          http.NewServeMux(),
		bearers:      map[string]bool{},
		refresh:      "rtk-gen0-SeededOnDisk-4b19ca77",
		wantPassword: sentinelPassword,
		wantCode:     sentinelTOTPCode,
	}
	v.add(kindRefreshToken, h.refresh, true)

	// Both API tokens are accepted so an api_token-mode scenario can pick
	// either source without extra wiring.
	h.bearers[sentinelEnvAPIToken] = true
	h.bearers[sentinelConfigAPIToken] = true

	h.mux.HandleFunc("POST /api/auth/login", h.handleLogin)
	h.mux.HandleFunc("POST /api/auth/login/totp", h.handleLoginTOTP)
	h.mux.HandleFunc("POST /api/auth/refresh", h.handleRefresh)
	h.mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h.mux.HandleFunc("GET /api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		if !h.authorized(r) {
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		writeJSON(w, http.StatusOK, api.Me{Username: sentinelUsername, Role: sentinelRole})
	})

	h.srv = httptest.NewServer(h.mux)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *stubHub) URL() string { return h.srv.URL }

// handle registers a scenario-specific route.
func (h *stubHub) handle(pattern string, fn http.HandlerFunc) { h.mux.HandleFunc(pattern, fn) }

// mint rotates the token pair, revoking the previous access token, and
// registers both halves in the vault.
func (h *stubHub) mint() (access, refresh string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.gen++
	access = fmt.Sprintf("atk-gen%d-InMemoryOnly-9f3c0e%02d", h.gen, h.gen)
	refresh = fmt.Sprintf("rtk-gen%d-RotatedOnDisk-1d7b45%02d", h.gen, h.gen)

	for b := range h.bearers {
		if strings.HasPrefix(b, "atk-") {
			delete(h.bearers, b)
		}
	}
	h.bearers[access] = true
	h.refresh = refresh

	h.v.add(kindAccessToken, access, false)
	h.v.add(kindRefreshToken, refresh, true)
	return access, refresh
}

// authorized reports whether r carries a currently valid bearer.
func (h *stubHub) authorized(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.bearers[token]
}

func (h *stubHub) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)

	h.mu.Lock()
	setup, want := h.setupRedirect, h.wantPassword
	h.mu.Unlock()

	if setup {
		writeJSON(w, http.StatusOK, map[string]any{
			"requires_totp_setup": true,
			"setup_token":         sentinelSetupToken,
		})
		return
	}
	if body["password"] != want {
		// Hostile on purpose: the hub reflects the rejected password.
		writeHubError(w, http.StatusUnauthorized,
			fmt.Sprintf("invalid credentials for %s (password %q was rejected)", body["username"], body["password"]))
		return
	}
	writeJSON(w, http.StatusAccepted, api.LoginTOTPPending{TOTPToken: sentinelTOTPToken})
}

func (h *stubHub) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)

	h.mu.Lock()
	want := h.wantCode
	h.mu.Unlock()

	if body["code"] != want {
		// Hostile on purpose, in both directions: the stub reflects the
		// user-supplied code AND the hub-issued challenge token back in its
		// error envelope.
		//
		// The real hub does neither (hub/internal/server/handlers_auth.go
		// handleLoginTOTP answers with the fixed literals "invalid TOTP
		// code" / "invalid or expired TOTP token"), so this is the
		// defense-in-depth layer auth.scrubSecret exists for: the hub's
		// {"error": "..."} text is the one channel the CLI does not control
		// but does surface verbatim. Reflecting both halves here is what
		// permanently pins login.go's scrubSecret(scrubSecret(err, code),
		// totpToken).
		writeHubError(w, http.StatusUnauthorized,
			fmt.Sprintf("one-time code %s is not valid for challenge %s", body["code"], body["totp_token"]))
		return
	}
	access, refresh := h.mint()
	writeJSON(w, http.StatusOK, api.TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		User:         api.User{Username: sentinelUsername, Role: sentinelRole},
	})
}

func (h *stubHub) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	h.mu.Lock()
	status, live := h.refreshStatus, h.refresh
	h.mu.Unlock()

	if status != 0 {
		// Hostile on purpose: the stub reflects the refresh token it was
		// handed. The real hub never does (handlers_auth.go handleRefresh
		// answers with fixed literals), so this is the defense-in-depth
		// layer that pins postRefresh's scrubSecret — and it matters most
		// for a non-401 status, which refresh() surfaces verbatim instead of
		// replacing with errSessionExpired.
		writeHubError(w, status, fmt.Sprintf("refresh token %s was rejected", body.RefreshToken))
		return
	}
	if body.RefreshToken != live {
		writeHubError(w, http.StatusUnauthorized,
			fmt.Sprintf("refresh token %s has been revoked", body.RefreshToken))
		return
	}
	access, refresh := h.mint()
	writeJSON(w, http.StatusOK, api.TokenPair{AccessToken: access, RefreshToken: refresh})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeHubError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- scenario environment -------------------------------------------------

// env is one scenario's world: a stub hub, a private config directory backed
// by the file credential store, and the recording writers every command's
// Printer is bound to.
type env struct {
	hub       *stubHub
	vault     *vault
	configDir string
	cfg       config.Config
	jsonMode  bool

	stdout  *bytes.Buffer
	stderr  *bytes.Buffer
	printer *cmdutil.Printer
}

// newEnv builds a scenario environment. The OS keyring is mocked into
// unavailability so the credential store is always the file backend — that
// is the backend whose bytes this sweep can actually inspect on disk
// (auth.CredentialsFileName under configDir).
func newEnv(t *testing.T, jsonMode bool) *env {
	t.Helper()
	keyring.MockInitWithError(errors.New("mock: keyring unavailable"))
	t.Setenv("VEYPORT_TOKEN", "")

	v := newVault()
	var stdout, stderr bytes.Buffer
	return &env{
		hub:       newStubHub(t, v),
		vault:     v,
		configDir: t.TempDir(),
		jsonMode:  jsonMode,
		stdout:    &stdout,
		stderr:    &stderr,
		printer:   cmdutil.NewPrinter(&stdout, &stderr, jsonMode),
	}
}

// store opens the credential store for this scenario's config directory,
// exactly as the commands do.
func (e *env) store(t *testing.T) auth.Store {
	t.Helper()
	s, err := auth.NewStore(e.configDir, io.Discard)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if s.Backend() != auth.BackendFile {
		t.Fatalf("credential store backend = %q, want %q so the on-disk sweep has something to read",
			s.Backend(), auth.BackendFile)
	}
	return s
}

// seedSession persists the hub's seed refresh token, putting the scenario in
// session auth mode.
func (e *env) seedSession(t *testing.T) {
	t.Helper()
	e.hub.mu.Lock()
	seed := e.hub.refresh
	e.hub.mu.Unlock()

	if err := e.store(t).Save(e.hub.URL(), auth.StoredSession{
		RefreshToken: seed,
		Username:     sentinelUsername,
		Role:         sentinelRole,
		ObtainedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seeding session: %v", err)
	}
}

// useEnvAPIToken / useConfigAPIToken put the scenario in api_token mode via
// each of the two sources auth.Resolve consults.
func (e *env) useEnvAPIToken(t *testing.T) {
	t.Helper()
	t.Setenv("VEYPORT_TOKEN", sentinelEnvAPIToken)
}

func (e *env) useConfigAPIToken() {
	e.cfg = config.Config{Hubs: map[string]config.HubProfile{
		e.hub.URL(): {APIToken: sentinelConfigAPIToken},
	}}
}

// run invokes a command entry point through a real commands.Context wired to
// the recording writers, and asserts the documented exit code so a
// mis-wired stub can never make the sweep vacuously clean.
func (e *env) run(t *testing.T, name string, fn func(*commands.Context) int, wantExit int, args ...string) {
	t.Helper()
	ctx := commands.NewContext(e.hub.URL(), "", e.cfg, e.configDir, e.printer, args)
	if got := fn(ctx); got != wantExit {
		t.Fatalf("%s: exit code = %d, want %d (stdout=%q stderr=%q)",
			name, got, wantExit, e.stdout.String(), e.stderr.String())
	}
}

// --- login scaffolding ----------------------------------------------------

// recordingPrompter answers the three login prompts, writing the same prompt
// text the production terminal prompter writes to the same stream (stderr).
// The answers themselves are never echoed — term.ReadPassword suppresses the
// password and the code is read from the terminal, not printed — so the
// prompt text is all a real run puts on the stream.
type recordingPrompter struct {
	out                      io.Writer
	username, password, code string
	usernameErr, passwordErr error
	codeErr                  error
}

func (p *recordingPrompter) Username(defaultUser string) (string, error) {
	fmt.Fprint(p.out, "Username: ")
	return p.username, p.usernameErr
}

func (p *recordingPrompter) Password() (string, error) {
	fmt.Fprint(p.out, "Password: ")
	return p.password, p.passwordErr
}

func (p *recordingPrompter) TOTPCode() (string, error) {
	fmt.Fprint(p.out, "One-time code (valid for 60 seconds): ")
	return p.code, p.codeErr
}

func (e *env) prompter() auth.LoginPrompter {
	return &recordingPrompter{
		out:      e.stderr,
		username: sentinelUsername,
		password: sentinelPassword,
		code:     sentinelTOTPCode,
	}
}

// login drives the real three-leg flow (auth.Login, the function RunLogin
// calls) and renders any failure through the recording Printer exactly the
// way RunLogin does (`ctx.Printer.Error(err)`).
func (e *env) login(t *testing.T) (*api.TokenPair, error) {
	t.Helper()
	pair, err := auth.Login(context.Background(), auth.LoginOptions{
		Client:   api.NewClient(e.hub.URL(), ""),
		HubURL:   e.hub.URL(),
		Store:    e.store(t),
		Prompter: e.prompter(),
	})
	if err != nil {
		e.printer.Error(err)
	}
	return pair, err
}

// withNonTTYStdin swaps os.Stdin for a plain file, which is what a piped
// invocation (`echo | vey login`) presents. RunLogin reads the package
// variable directly, so the non-TTY contract can only be exercised through
// it.
func withNonTTYStdin(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old })
	return f
}

// --- scenarios ------------------------------------------------------------

// scenario is one command path, run once per output mode.
type scenario struct {
	name string
	run  func(t *testing.T, e *env)
}

// mountServer registers the by-ID server lookup most non-auth commands need
// in order to resolve their <server> argument.
func mountServer(e *env, id, name string) {
	e.hub.handle("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !e.hub.authorized(r) {
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		if r.PathValue("id") != id {
			writeHubError(w, http.StatusNotFound, "server not found")
			return
		}
		writeJSON(w, http.StatusOK, api.Server{ID: id, Name: name, Status: "online"})
	})
}

// hygieneScenarios lists every command path the sweep exercises. Each run
// func is a top-level function (scenarioXxx below), not an inline closure:
// with ~30 scenarios in one literal, inline closures pushed this function's
// cognitive complexity far past the threshold, since every branch inside a
// nested closure counts against the enclosing function. Naming them keeps
// each scenario's own branching scoped to its own (small) function and
// leaves this one a flat table.
func hygieneScenarios() []scenario {
	return []scenario{
		// --- vey login -------------------------------------------------
		{name: "login/happy-path", run: scenarioLoginHappyPath},
		{name: "login/bad-totp-code", run: scenarioLoginBadTOTPCode},
		{name: "login/bad-password", run: scenarioLoginBadPassword},
		{name: "login/totp-setup-redirect", run: scenarioLoginTOTPSetupRedirect},
		{name: "login/non-tty-fast-fail", run: scenarioLoginNonTTYFastFail},
		{name: "login/terminal-prompter-no-echo-failure", run: scenarioLoginTerminalPrompterNoEchoFailure},

		// --- vey status ------------------------------------------------
		{name: "status/session-mode", run: scenarioStatusSessionMode},
		{name: "status/api-token-mode-env", run: scenarioStatusAPITokenModeEnv},
		{name: "status/api-token-mode-config", run: scenarioStatusAPITokenModeConfig},
		{name: "status/not-signed-in", run: scenarioStatusNotSignedIn},

		// --- vey servers -----------------------------------------------
		{name: "servers/list-ok", run: scenarioServersListOK},
		{name: "servers/list-forbidden", run: scenarioServersListForbidden},
		{name: "servers/get-ok", run: scenarioServersGetOK},
		{name: "servers/get-not-found", run: scenarioServersGetNotFound},
		{name: "servers/get-ambiguous", run: scenarioServersGetAmbiguous},

		// --- vey files -------------------------------------------------
		{name: "files/ls-ok", run: scenarioFilesLsOK},
		{name: "files/ls-forbidden", run: scenarioFilesLsForbidden},
		{name: "files/cat-ok", run: scenarioFilesCatOK},
		{name: "files/cat-not-found", run: scenarioFilesCatNotFound},

		// --- vey logs --------------------------------------------------
		{name: "logs/tail-brief-stream", run: scenarioLogsTailBriefStream},

		// --- vey audit -------------------------------------------------
		{name: "audit/export-forbidden", run: scenarioAuditExportForbidden},
		{name: "audit/export-ok", run: scenarioAuditExportOK},

		// --- vey ssh-cert ----------------------------------------------
		{name: "ssh-cert/issue", run: scenarioSSHCertIssue},
		{name: "ssh-cert/reuse-stored-key", run: scenarioSSHCertReuseStoredKey},
		{name: "ssh-cert/api-token-refused", run: scenarioSSHCertAPITokenRefused},
		{name: "ssh-cert/hub-refusal", run: scenarioSSHCertHubRefusal},

		// --- vey ssh -----------------------------------------------------
		{name: "ssh/no-certificate", run: scenarioSSHNoCertificate},
		{name: "ssh/expired-certificate", run: scenarioSSHExpiredCertificate},
		{name: "ssh/unknown-server", run: scenarioSSHUnknownServer},

		// --- vey logout ------------------------------------------------
		{name: "logout/session-mode", run: scenarioLogoutSessionMode},
		{name: "logout/api-token-mode", run: scenarioLogoutAPITokenMode},

		// --- transparent refresh ---------------------------------------
		{name: "refresh/retry-after-401-then-success", run: scenarioRefreshRetryAfter401ThenSuccess},
		{name: "refresh/terminal-failure", run: scenarioRefreshTerminalFailure},
		{name: "refresh/hub-error-reflects-token", run: scenarioRefreshHubErrorReflectsToken},
		{name: "refresh/rate-limited-reflects-token", run: scenarioRefreshRateLimitedReflectsToken},
	}
}

func scenarioLoginHappyPath(t *testing.T, e *env) {
	pair, err := e.login(t)
	if err != nil {
		t.Fatalf("auth.Login: %v", err)
	}
	// RunLogin renders exactly {hub, username, role} on success
	// (commands/login.go loginPayload); assert those three values
	// carry no credential material of their own.
	rendered := fmt.Sprintf("hub=%s username=%s role=%s",
		e.hub.URL(), pair.User.Username, pair.User.Role)
	scan(t, "login/happy-path", "the values vey login prints on success",
		rendered, e.vault.snapshot(), false)
}

func scenarioLoginBadTOTPCode(t *testing.T, e *env) {
	e.hub.mu.Lock()
	e.hub.wantCode = "000000" // anything but the code the user types
	e.hub.mu.Unlock()

	_, err := e.login(t)
	if err == nil {
		t.Fatal("auth.Login succeeded with a rejected one-time code, want an error")
	}
	if cmdutil.Code(err) != cmdutil.ExitAuth {
		t.Errorf("exit code = %d, want %d (ExitAuth)", cmdutil.Code(err), cmdutil.ExitAuth)
	}
	scan(t, "login/bad-totp-code", "the error returned up the stack",
		err.Error(), e.vault.snapshot(), false)
}

func scenarioLoginBadPassword(t *testing.T, e *env) {
	e.hub.mu.Lock()
	e.hub.wantPassword = "a-different-password"
	e.hub.mu.Unlock()

	_, err := e.login(t)
	if err == nil {
		t.Fatal("auth.Login succeeded with a rejected password, want an error")
	}
	if cmdutil.Code(err) != cmdutil.ExitAuth {
		t.Errorf("exit code = %d, want %d (ExitAuth)", cmdutil.Code(err), cmdutil.ExitAuth)
	}
	scan(t, "login/bad-password", "the error returned up the stack",
		err.Error(), e.vault.snapshot(), false)
}

func scenarioLoginTOTPSetupRedirect(t *testing.T, e *env) {
	e.hub.mu.Lock()
	e.hub.setupRedirect = true
	e.hub.mu.Unlock()

	_, err := e.login(t)
	if err == nil {
		t.Fatal("auth.Login succeeded against an enrollment redirect, want an error")
	}
	if !strings.Contains(err.Error(), "web interface") {
		t.Errorf("error = %q, want the web-UI enrollment guidance", err.Error())
	}
	scan(t, "login/totp-setup-redirect", "the error returned up the stack",
		err.Error(), e.vault.snapshot(), false)
}

func scenarioLoginNonTTYFastFail(t *testing.T, e *env) {
	f := withNonTTYStdin(t)
	// Whatever a script might pipe in must not reappear anywhere.
	if _, err := f.WriteString(sentinelPassword + "\n" + sentinelTOTPCode + "\n"); err != nil {
		t.Fatalf("seeding piped stdin: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewinding piped stdin: %v", err)
	}
	e.run(t, "login non-tty", commands.RunLogin, cmdutil.ExitAuth)
}

func scenarioLoginTerminalPrompterNoEchoFailure(t *testing.T, e *env) {
	// The production prompter over a non-terminal file: the
	// username/code prompts still write their text, and the
	// no-echo password read fails. Neither the prompt text nor
	// the failure may carry the bytes that were read.
	f := withNonTTYStdin(t)
	if _, err := f.WriteString(sentinelPassword + "\n" + sentinelTOTPCode + "\n"); err != nil {
		t.Fatalf("seeding prompter input: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewinding prompter input: %v", err)
	}

	p := auth.NewTerminalPrompter(f, e.stderr)
	if _, err := p.Username(""); err != nil {
		t.Fatalf("Username: %v", err)
	}
	if _, err := p.Password(); err == nil {
		t.Fatal("no-echo password read succeeded on a non-terminal, want an error")
	} else {
		scan(t, "login/terminal-prompter-no-echo-failure", "the password-read error",
			err.Error(), e.vault.snapshot(), false)
	}
	if _, err := p.TOTPCode(); err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
}

func scenarioStatusSessionMode(t *testing.T, e *env) {
	e.seedSession(t)
	e.run(t, "status session", commands.RunStatus, cmdutil.ExitOK)
}

func scenarioStatusAPITokenModeEnv(t *testing.T, e *env) {
	e.useEnvAPIToken(t)
	e.run(t, "status api-token env", commands.RunStatus, cmdutil.ExitOK)
	assertTokenPrefixOnly(t, e, sentinelEnvAPIToken)
}

func scenarioStatusAPITokenModeConfig(t *testing.T, e *env) {
	e.useConfigAPIToken()
	e.run(t, "status api-token config", commands.RunStatus, cmdutil.ExitOK)
	assertTokenPrefixOnly(t, e, sentinelConfigAPIToken)
}

func scenarioStatusNotSignedIn(t *testing.T, e *env) {
	e.run(t, "status none", commands.RunStatus, cmdutil.ExitAuth)
}

func scenarioServersListOK(t *testing.T, e *env) {
	e.seedSession(t)
	e.hub.handle("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		if !e.hub.authorized(r) {
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		writeJSON(w, http.StatusOK, api.ServersPage{
			Servers: []api.Server{{ID: "srv-1", Name: "web-01", Status: "online"}},
			Total:   1, Limit: 20,
		})
	})
	e.run(t, "servers list", commands.RunServers, cmdutil.ExitOK, "list")
}

func scenarioServersListForbidden(t *testing.T, e *env) {
	e.seedSession(t)
	e.hub.handle("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		writeHubError(w, http.StatusForbidden, "your role may not list servers")
	})
	e.run(t, "servers list 403", commands.RunServers, cmdutil.ExitForbidden, "list")
}

func scenarioServersGetOK(t *testing.T, e *env) {
	e.seedSession(t)
	mountServer(e, "srv-1", "web-01")
	e.run(t, "servers get", commands.RunServers, cmdutil.ExitOK, "get", "srv-1")
}

func scenarioServersGetNotFound(t *testing.T, e *env) {
	e.seedSession(t)
	mountServer(e, "srv-1", "web-01")
	e.hub.handle("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, api.ServersPage{})
	})
	e.run(t, "servers get 404", commands.RunServers, cmdutil.ExitNotFound, "get", "ghost")
}

func scenarioServersGetAmbiguous(t *testing.T, e *env) {
	e.seedSession(t)
	mountServer(e, "srv-1", "web-01")
	e.hub.handle("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, api.ServersPage{
			Servers: []api.Server{{ID: "srv-2", Name: "web"}, {ID: "srv-3", Name: "web"}},
			Total:   2,
		})
	})
	e.run(t, "servers get ambiguous", commands.RunServers, cmdutil.ExitUsage, "get", "web")
}

func scenarioFilesLsOK(t *testing.T, e *env) {
	e.seedSession(t)
	mountServer(e, "srv-1", "web-01")
	e.hub.handle("GET /api/servers/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		if !e.hub.authorized(r) {
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		writeJSON(w, http.StatusOK, api.FileListing{Files: []api.FileEntry{
			{Name: "app.log", Size: 2048, Readable: true},
			{Name: "archive", IsDir: true},
		}})
	})
	e.run(t, "files ls", commands.RunFiles, cmdutil.ExitOK, "ls", "srv-1", "/var/log")
}

func scenarioFilesLsForbidden(t *testing.T, e *env) {
	e.seedSession(t)
	mountServer(e, "srv-1", "web-01")
	e.hub.handle("GET /api/servers/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		writeHubError(w, http.StatusForbidden, "path /root is outside your allowed roots")
	})
	e.run(t, "files ls 403", commands.RunFiles, cmdutil.ExitForbidden, "ls", "srv-1", "/root")
}

func scenarioFilesCatOK(t *testing.T, e *env) {
	e.seedSession(t)
	mountServer(e, "srv-1", "web-01")
	e.hub.handle("GET /api/servers/{id}/files/read", func(w http.ResponseWriter, r *http.Request) {
		if !e.hub.authorized(r) {
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "listen_addr = 0.0.0.0:8443\nworkers = 4\n")
	})
	e.run(t, "files cat", commands.RunFiles, cmdutil.ExitOK, "cat", "srv-1", "/etc/app.conf")
}

func scenarioFilesCatNotFound(t *testing.T, e *env) {
	e.seedSession(t)
	mountServer(e, "srv-1", "web-01")
	e.hub.handle("GET /api/servers/{id}/files/read", func(w http.ResponseWriter, r *http.Request) {
		writeHubError(w, http.StatusNotFound, "no such file: /etc/nope.conf")
	})
	e.run(t, "files cat 404", commands.RunFiles, cmdutil.ExitNotFound, "cat", "srv-1", "/etc/nope.conf")
}

func scenarioLogsTailBriefStream(t *testing.T, e *env) {
	e.seedSession(t)
	mountServer(e, "srv-1", "web-01")
	e.hub.handle("GET /api/servers/{id}/logs/tail", func(w http.ResponseWriter, r *http.Request) {
		if !e.hub.authorized(r) {
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		// The hub base64-encodes each frame and frames are not
		// line-aligned (handlers_logs.go / logtailer).
		for _, chunk := range []string{"boot: ok\npoll ", "cycle 1 complete\n"} {
			fmt.Fprintf(w, "data: %s\n\n", base64.StdEncoding.EncodeToString([]byte(chunk)))
			flusher.Flush()
		}
		// Returning closes the stream: `vey logs tail` reports
		// that as an unexpected close (exit 6).
	})
	e.run(t, "logs tail", commands.RunLogs, cmdutil.ExitConn, "tail", "srv-1", "/var/log/app.log")
}

func scenarioAuditExportForbidden(t *testing.T, e *env) {
	e.seedSession(t)
	e.hub.handle("GET /api/audit-logs/export", func(w http.ResponseWriter, r *http.Request) {
		writeHubError(w, http.StatusForbidden, "audit export requires the admin or auditor role")
	})
	e.run(t, "audit export 403", commands.RunAudit, cmdutil.ExitForbidden, "export")
}

func scenarioAuditExportOK(t *testing.T, e *env) {
	e.seedSession(t)
	e.hub.handle("GET /api/audit-logs/export", func(w http.ResponseWriter, r *http.Request) {
		if !e.hub.authorized(r) {
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"manifest": map[string]any{"count": 1},
			"entries":  []map[string]any{{"action": "login", "actor": sentinelUsername}},
		})
	})
	e.run(t, "audit export", commands.RunAudit, cmdutil.ExitOK, "export")
}

// --- vey ssh-cert ---------------------------------------------------------
//
// The SSH private key is the second piece of long-lived secret material vey
// persists. It is generated locally rather than minted by the hub, so a
// scenario registers it in the vault either up front (when it seeds the key
// itself) or by reading back what the command stored — never by guessing a
// value the command might not have used.

const sshHygieneExpiry = "2030-01-02T03:04:05Z"

// mountSSHGateway registers the two routes `vey ssh-cert` calls. The
// certificate it returns is public material and is deliberately *not* a
// secret: what must never surface is the private key that signs against it.
func mountSSHGateway(e *env) {
	mountSSHHostKey(e)
	mountSSHIssuance(e)
}

// mountSSHHostKey registers only the pinning endpoint, for scenarios that
// supply their own issuance handler (a ServeMux pattern can be registered
// exactly once).
func mountSSHHostKey(e *env) {
	e.hub.handle("GET /api/ssh/host-key", func(w http.ResponseWriter, r *http.Request) {
		if !e.hub.authorized(r) {
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"fingerprint": "SHA256:hygiene-gateway-host-key",
			"public_key":  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHygieneHostKey gateway",
			"port":        2222,
		})
	})
}

func mountSSHIssuance(e *env) {
	e.hub.handle("POST /api/ssh/certificates", func(w http.ResponseWriter, r *http.Request) {
		if !e.hub.authorized(r) {
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"certificate":          "ssh-ed25519-cert-v01@openssh.com AAAAhygiene-cert " + sentinelUsername,
			"principal":            sentinelUsername,
			"expires_at":           sshHygieneExpiry,
			"host_key_fingerprint": "SHA256:hygiene-gateway-host-key",
			"gateway_port":         2222,
		})
	})
}

// newSentinelSSHKey generates a real ed25519 key in the openssh form the CLI
// stores, so a scenario can seed the store with a key `vey ssh-cert` has to
// read back and reuse — and the sweep can then hunt for that exact value.
func newSentinelSSHKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a sentinel SSH key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("encoding the sentinel SSH key: %v", err)
	}
	return string(pem.EncodeToMemory(block))
}

// registerStoredSSHKey adds whatever private key ended up in the credential
// store to the vault, so the sweep scans for the value the command actually
// used rather than a hardcoded guess. It fails the scenario if nothing was
// stored, which would make this half of the sweep vacuous.
func registerStoredSSHKey(t *testing.T, e *env) {
	t.Helper()
	material, ok, err := e.store(t).LoadSSH(e.hub.URL())
	if err != nil {
		t.Fatalf("reading back the stored SSH material: %v", err)
	}
	if !ok || material.PrivateKey == "" {
		t.Fatal("vey ssh-cert stored no SSH private key; the SSH half of the sweep would be vacuous")
	}
	e.vault.add(kindSSHPrivateKey, material.PrivateKey, true)
}

func scenarioSSHCertIssue(t *testing.T, e *env) {
	e.seedSession(t)
	mountSSHGateway(e)
	e.run(t, "ssh-cert", commands.RunSSHCert, cmdutil.ExitOK)
	registerStoredSSHKey(t, e)
}

func scenarioSSHCertReuseStoredKey(t *testing.T, e *env) {
	e.seedSession(t)
	mountSSHGateway(e)

	// Seeded up front and registered before the run: this covers the read
	// path (FR-004 reuse), where the key comes out of the store and back
	// through the command's own code rather than being freshly generated.
	seeded := newSentinelSSHKey(t)
	e.vault.add(kindSSHPrivateKey, seeded, true)
	if err := e.store(t).SaveSSH(e.hub.URL(), auth.StoredSSH{PrivateKey: seeded}); err != nil {
		t.Fatalf("seeding SSH material: %v", err)
	}

	e.run(t, "ssh-cert reuse", commands.RunSSHCert, cmdutil.ExitOK)

	material, ok, err := e.store(t).LoadSSH(e.hub.URL())
	if err != nil || !ok {
		t.Fatalf("LoadSSH after re-issuance = (ok %v, err %v)", ok, err)
	}
	if material.PrivateKey != seeded {
		t.Error("vey ssh-cert replaced a usable stored keypair instead of reusing it (FR-004)")
	}
}

func scenarioSSHCertAPITokenRefused(t *testing.T, e *env) {
	e.useEnvAPIToken(t)
	mountSSHGateway(e)
	// Refused locally, before any request: nothing is generated and nothing
	// is stored, so the only secrets in play are the static sentinels.
	e.run(t, "ssh-cert api-token", commands.RunSSHCert, cmdutil.ExitAuth)
}

func scenarioSSHCertHubRefusal(t *testing.T, e *env) {
	e.seedSession(t)
	mountSSHHostKey(e)
	// Hostile on purpose: the hub reflects the whole request body in its
	// refusal. The body carries the *public* key, but this is the channel
	// through which a hub message reaches stderr verbatim (issueSSHCertificate
	// surfaces the hub's 403 text), so the sweep watches it.
	e.hub.handle("POST /api/ssh/certificates", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		writeHubError(w, http.StatusForbidden,
			fmt.Sprintf("interactive login required (request was %s)", body))
	})
	e.run(t, "ssh-cert refused", commands.RunSSHCert, cmdutil.ExitAuth)
}

// --- vey ssh ----------------------------------------------------------
//
// `vey ssh` reads back the same SSH private key `vey ssh-cert` stores
// (commands/ssh.go RunSSH's preflight, loadSSHCredential), so it is a second
// reader of that secret material rather than a second source of it. The
// three scenarios below only exercise the paths that fail *before*
// commands.execSSH — the one seam that actually spawns a process — since
// execSSH and sshStdinIsTTY are unexported package-level vars in package
// commands and this file lives in package auth_test, so neither can be
// stubbed from here. That is not a gap: every preflight/resolution failure
// is itself a documented exit code (contracts/cli-commands.md `vey ssh`),
// and none of them ever reaches the TTY check or execSSH, so a real ssh
// process is never at risk of being spawned by this sweep either.

// newSentinelSSHUserCert mints a real, parseable ed25519 user certificate for
// principal, signed by a fresh throwaway CA, expiring at expiry. It mirrors
// the shape internal/commands/ssh_test.go's makeTestUserCert produces (that
// helper is unexported in package commands, so this external test package
// mints its own rather than reaching into it). Returns the PEM private key
// and the authorized_keys-form certificate line the credential store holds.
func newSentinelSSHUserCert(t *testing.T, principal string, expiry time.Time) (privatePEM, certLine string) {
	t.Helper()

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sentinel CA key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("building sentinel CA signer: %v", err)
	}

	userPub, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sentinel user key: %v", err)
	}
	sshUserPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatalf("wrapping sentinel user public key: %v", err)
	}

	cert := &ssh.Certificate{
		Key:             sshUserPub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           principal,
		ValidPrincipals: []string{principal},
		ValidAfter:      0,
		ValidBefore:     uint64(expiry.Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("signing sentinel certificate: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(userPriv, "")
	if err != nil {
		t.Fatalf("encoding sentinel private key: %v", err)
	}
	return string(pem.EncodeToMemory(block)), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}

// seedSSHMaterialForRun stores principal's certificate (expiring at expiry)
// and its private key under hubURL, registers the private key in the vault
// (it legitimately reaches the store, per kindSSHPrivateKey's contract), and
// returns it so a scenario can assert against the exact value the command
// will read back.
func seedSSHMaterialForRun(t *testing.T, e *env, principal string, expiry time.Time) (privatePEM string) {
	t.Helper()
	privatePEM, certLine := newSentinelSSHUserCert(t, principal, expiry)
	e.vault.add(kindSSHPrivateKey, privatePEM, true)
	if err := e.store(t).SaveSSH(e.hub.URL(), auth.StoredSSH{
		PrivateKey:    privatePEM,
		Certificate:   certLine,
		CertExpiresAt: expiry,
	}); err != nil {
		t.Fatalf("seeding SSH material: %v", err)
	}
	return privatePEM
}

// scenarioSSHNoCertificate covers the Preflight row's first half
// (loadSSHCredential): no SSH material stored at all → exit 3, guidance
// names `vey ssh-cert`. No SSH private key is in play for this scenario, so
// only the static sentinels are swept.
func scenarioSSHNoCertificate(t *testing.T, e *env) {
	e.seedSession(t)
	e.run(t, "ssh no cert", commands.RunSSH, cmdutil.ExitAuth, "bastion1")
}

// scenarioSSHExpiredCertificate covers the Preflight row's other half: a
// certificate whose *stored* expiry has already passed is refused exactly
// like a missing one (exit 3) without ever parsing the certificate or
// resolving the server — so the stored private key must survive on disk but
// never reach stdout/stderr/the error string.
func scenarioSSHExpiredCertificate(t *testing.T, e *env) {
	e.seedSession(t)
	seedSSHMaterialForRun(t, e, sentinelUsername, time.Now().Add(-1*time.Hour))
	e.run(t, "ssh expired cert", commands.RunSSH, cmdutil.ExitAuth, "bastion1")
}

// scenarioSSHUnknownServer covers server resolution parity with `vey servers
// get`'s "unknown → exit 5" row: a valid, unexpired stored certificate gets
// past the preflight, but the <server> argument resolves to nothing (direct
// GET 404s, the search fallback returns no matches). This is still entirely
// pre-exec — resolveSSHServer runs before the host-key fetch, the TTY check,
// and execSSH — so the stored private key is again in play only for the
// on-disk half of the sweep.
func scenarioSSHUnknownServer(t *testing.T, e *env) {
	e.seedSession(t)
	seedSSHMaterialForRun(t, e, sentinelUsername, time.Now().Add(2*time.Hour))
	mountServer(e, "srv-1", "web-01")
	e.hub.handle("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, api.ServersPage{})
	})
	e.run(t, "ssh unknown server", commands.RunSSH, cmdutil.ExitNotFound, "ghost")
}

func scenarioLogoutSessionMode(t *testing.T, e *env) {
	e.seedSession(t)
	e.run(t, "logout session", commands.RunLogout, cmdutil.ExitOK)
}

func scenarioLogoutAPITokenMode(t *testing.T, e *env) {
	e.useEnvAPIToken(t)
	e.run(t, "logout api-token", commands.RunLogout, cmdutil.ExitAuth)
}

func scenarioRefreshRetryAfter401ThenSuccess(t *testing.T, e *env) {
	e.seedSession(t)
	var mu sync.Mutex
	calls := 0
	e.hub.handle("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			// The access token aged out mid-invocation: exactly
			// one transparent refresh + replay is expected.
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		if !e.hub.authorized(r) {
			writeHubError(w, http.StatusUnauthorized, "access token is expired")
			return
		}
		writeJSON(w, http.StatusOK, api.ServersPage{
			Servers: []api.Server{{ID: "srv-1", Name: "web-01", Status: "online"}},
			Total:   1, Limit: 20,
		})
	})
	e.run(t, "servers list with refresh retry", commands.RunServers, cmdutil.ExitOK, "list")

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 2 {
		t.Fatalf("GET /api/servers called %d time(s), want 2 (original + one replay after refresh)", got)
	}
	// A rotation must have happened, so the sweep is checking a
	// token the hub actually minted mid-command.
	e.hub.mu.Lock()
	gen := e.hub.gen
	e.hub.mu.Unlock()
	if gen < 2 {
		t.Fatalf("token generation = %d, want at least 2 (initial refresh + the retry refresh)", gen)
	}
}

func scenarioRefreshTerminalFailure(t *testing.T, e *env) {
	// A 401 on refresh: the hub's (reflected) message is
	// discarded and replaced by errSessionExpired's fixed text.
	e.run(t, "servers list with dead session", commands.RunServers, cmdutil.ExitAuth,
		deadRefresh(t, e, http.StatusUnauthorized)...)
}

func scenarioRefreshHubErrorReflectsToken(t *testing.T, e *env) {
	// A 5xx on refresh: refresh() deliberately surfaces this one
	// verbatim ("not a race, and not something re-login would
	// fix"), hub message included — so the scrub in postRefresh
	// is the only thing between the reflected token and stderr.
	e.run(t, "servers list with a failing refresh", commands.RunServers, cmdutil.ExitError,
		deadRefresh(t, e, http.StatusInternalServerError)...)
}

func scenarioRefreshRateLimitedReflectsToken(t *testing.T, e *env) {
	// Same verbatim-passthrough path, at the other status the
	// code calls out by name (429 → exit 7, never retried).
	e.run(t, "servers list against a rate-limited refresh", commands.RunServers, cmdutil.ExitRateLimited,
		deadRefresh(t, e, http.StatusTooManyRequests)...)
}

// deadRefresh puts the scenario in session mode with a hub whose
// /api/auth/refresh answers status (reflecting the submitted token), and
// asserts the command never gets far enough to call /api/servers. It returns
// the argv for `servers list`.
func deadRefresh(t *testing.T, e *env, status int) []string {
	t.Helper()
	e.seedSession(t)

	e.hub.mu.Lock()
	e.hub.refreshStatus = status
	e.hub.mu.Unlock()

	e.hub.handle("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		t.Error("servers list reached the hub despite an unrefreshable session")
		writeHubError(w, http.StatusUnauthorized, "access token is expired")
	})
	return []string{"list"}
}

// assertTokenPrefixOnly pins the `vey status` rule from the Secrets row of
// contracts/cli-commands.md: the human report names the API token by its
// 8-character prefix and nothing more, and the --json document carries no
// token material at all (commands/status.go statusPayload has no token
// field).
func assertTokenPrefixOnly(t *testing.T, e *env, token string) {
	t.Helper()
	out := e.stdout.String()

	if e.jsonMode {
		if strings.Contains(out, "adt_") {
			t.Errorf("status --json stdout mentions an API token; the JSON status document must carry none (stdout=%q)", out)
		}
		return
	}

	prefix := token[:apiTokenPrefixLen]
	if want := fmt.Sprintf("api token (%s…)", prefix); !strings.Contains(out, want) {
		t.Errorf("status human stdout = %q, want it to report %q (prefix only)", out, want)
	}
	if longer := token[:apiTokenPrefixLen+4]; strings.Contains(out, longer) {
		t.Errorf("status printed more than the %d-character token prefix (stdout=%q)", apiTokenPrefixLen, out)
	}
}

// --- the sweep ------------------------------------------------------------

// TestSecretHygieneSweep runs every command path against the stub hub in both
// human and --json mode and asserts that no password, one-time code, TOTP
// challenge/setup token, API token, access token, or refresh token ever
// reaches stdout or stderr — and that nothing but the refresh token reaches
// the credential store on disk (FR-017 / SC-006).
func TestSecretHygieneSweep(t *testing.T) {
	for _, sc := range hygieneScenarios() {
		for _, jsonMode := range []bool{false, true} {
			mode := "human"
			if jsonMode {
				mode = "json"
			}
			name := sc.name + "/" + mode

			t.Run(name, func(t *testing.T) {
				e := newEnv(t, jsonMode)
				sc.run(t, e)

				secrets := e.vault.snapshot()
				if len(secrets) == 0 {
					t.Fatal("no secrets registered for this scenario; the sweep would be vacuous")
				}
				scan(t, name, "stdout", e.stdout.String(), secrets, false)
				scan(t, name, "stderr", e.stderr.String(), secrets, false)
				scanDir(t, name, e.configDir, secrets)
			})
		}
	}
}

// TestTokenPrefixNeverRevealsWholeToken pins auth.AuthContext.TokenPrefix
// across the full range of token lengths validateAPIToken accepts (anything
// past the four-character `adt_` marker). The rendered fragment must never be
// the whole token, never exceed the 8-character display cap, and never expose
// more than half of a short token — the case a fixed 8-character rule got
// wrong, since `adt_x` is a legal token and eight characters is all of it.
func TestTokenPrefixNeverRevealsWholeToken(t *testing.T) {
	tokens := []string{
		"adt_x",                          // 5: the shortest token that validates
		"adt_ab",                         // 6
		"adt_abcd",                       // 8: exactly the display cap
		"adt_abcde",                      // 9: one past the cap
		"adt_abcdefgh12345678",           // 20: an ordinary token
		sentinelEnvAPIToken,              // 32: the sweep's sentinel
		"adt_" + strings.Repeat("k", 96), // 100: a long token
	}

	for _, token := range tokens {
		t.Run(fmt.Sprintf("len-%d", len(token)), func(t *testing.T) {
			assertTokenPrefixInvariants(t, token)
		})
	}
}

// assertTokenPrefixInvariants is TestTokenPrefixNeverRevealsWholeToken's
// per-token body, extracted to a top-level function so its run of assertions
// does not nest inside the table loop's subtest closure.
func assertTokenPrefixInvariants(t *testing.T, token string) {
	t.Helper()
	t.Setenv("VEYPORT_TOKEN", token)
	actx, err := auth.Resolve("https://hub.example.com", token, config.Config{}, nil, t.TempDir())
	if err != nil {
		t.Fatalf("auth.Resolve: %v", err)
	}
	if actx.Mode() != auth.ModeAPIToken {
		t.Fatalf("mode = %q, want %q", actx.Mode(), auth.ModeAPIToken)
	}

	got := actx.TokenPrefix()
	shown := strings.TrimSuffix(got, "…")
	if shown == got {
		t.Fatalf("TokenPrefix() = %q, want it to end in an ellipsis", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("TokenPrefix() rendered the whole %d-byte token; it must only ever show a fragment", len(token))
	}
	if len(shown) > apiTokenPrefixLen {
		t.Errorf("TokenPrefix() showed %d characters, want at most %d", len(shown), apiTokenPrefixLen)
	}
	if len(shown)*2 > len(token) {
		t.Errorf("TokenPrefix() showed %d of %d characters; at least half the token must stay hidden",
			len(shown), len(token))
	}
	if !strings.HasPrefix(token, shown) {
		t.Errorf("TokenPrefix() = %q, want a leading fragment of the token", got)
	}
}

// TestSecretHygieneDiskSweepIsNotVacuous is the positive control for the
// on-disk half of the sweep: it proves the credential file really exists,
// really is the file backend, and really contains the refresh token the sweep
// exempts — so a green disk sweep means "the forbidden kinds are absent from
// real bytes", not "there were no bytes to read".
func TestSecretHygieneDiskSweepIsNotVacuous(t *testing.T) {
	e := newEnv(t, false)
	e.seedSession(t)

	path := filepath.Join(e.configDir, auth.CredentialsFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", auth.CredentialsFileName, err)
	}

	e.hub.mu.Lock()
	seed := e.hub.refresh
	e.hub.mu.Unlock()

	if !strings.Contains(string(data), seed) {
		t.Fatalf("%s does not contain the seeded refresh token; the on-disk sweep would be vacuous", auth.CredentialsFileName)
	}
	// And the exempt kind is the only thing that gets a pass: everything
	// else must already be absent from a freshly written store.
	scan(t, "disk positive control", "the credentials file", string(data), e.vault.snapshot(), true)
}

// TestSecretHygieneSweepCoversEveryCommand guards the sweep itself: every
// entry in commands.Registry must be exercised by at least one scenario, so a
// command added later cannot silently escape the hygiene assertions.
func TestSecretHygieneSweepCoversEveryCommand(t *testing.T) {
	// Each scenario name is "<command>/<case>"; login is covered through
	// auth.Login plus RunLogin's non-TTY path.
	covered := map[string]bool{}
	for _, sc := range hygieneScenarios() {
		cmd, _, _ := strings.Cut(sc.name, "/")
		covered[cmd] = true
	}
	// The scenario prefixes use the plural command names as typed on the
	// command line, except "refresh", which is a cross-cutting auth path.
	for name := range commands.Registry {
		if !covered[name] {
			t.Errorf("command %q has no secret-hygiene scenario; add one to hygieneScenarios()", name)
		}
	}
}
