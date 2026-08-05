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
//	API token, access token, and every refresh token the stub minted.
//
// Refresh tokens are the one kind allowed to reach disk (data-model.md
// "StoredSession"); nothing is allowed to reach stdout or stderr.
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
	"encoding/base64"
	"encoding/json"
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
)

// secret is one piece of credential material in play for a scenario.
type secret struct {
	kind  secretKind
	value string
	// onDiskOK marks the only kind that legitimately reaches the credential
	// store: the refresh token (data-model.md — access tokens, passwords,
	// one-time codes and API tokens are never persisted by the CLI).
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

func hygieneScenarios() []scenario {
	return []scenario{
		// --- vey login -------------------------------------------------
		{
			name: "login/happy-path",
			run: func(t *testing.T, e *env) {
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
			},
		},
		{
			name: "login/bad-totp-code",
			run: func(t *testing.T, e *env) {
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
			},
		},
		{
			name: "login/bad-password",
			run: func(t *testing.T, e *env) {
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
			},
		},
		{
			name: "login/totp-setup-redirect",
			run: func(t *testing.T, e *env) {
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
			},
		},
		{
			name: "login/non-tty-fast-fail",
			run: func(t *testing.T, e *env) {
				f := withNonTTYStdin(t)
				// Whatever a script might pipe in must not reappear anywhere.
				if _, err := f.WriteString(sentinelPassword + "\n" + sentinelTOTPCode + "\n"); err != nil {
					t.Fatalf("seeding piped stdin: %v", err)
				}
				if _, err := f.Seek(0, io.SeekStart); err != nil {
					t.Fatalf("rewinding piped stdin: %v", err)
				}
				e.run(t, "login non-tty", commands.RunLogin, cmdutil.ExitAuth)
			},
		},
		{
			name: "login/terminal-prompter-no-echo-failure",
			run: func(t *testing.T, e *env) {
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
			},
		},

		// --- vey status ------------------------------------------------
		{
			name: "status/session-mode",
			run: func(t *testing.T, e *env) {
				e.seedSession(t)
				e.run(t, "status session", commands.RunStatus, cmdutil.ExitOK)
			},
		},
		{
			name: "status/api-token-mode-env",
			run: func(t *testing.T, e *env) {
				e.useEnvAPIToken(t)
				e.run(t, "status api-token env", commands.RunStatus, cmdutil.ExitOK)
				assertTokenPrefixOnly(t, e, sentinelEnvAPIToken)
			},
		},
		{
			name: "status/api-token-mode-config",
			run: func(t *testing.T, e *env) {
				e.useConfigAPIToken()
				e.run(t, "status api-token config", commands.RunStatus, cmdutil.ExitOK)
				assertTokenPrefixOnly(t, e, sentinelConfigAPIToken)
			},
		},
		{
			name: "status/not-signed-in",
			run: func(t *testing.T, e *env) {
				e.run(t, "status none", commands.RunStatus, cmdutil.ExitAuth)
			},
		},

		// --- vey servers -----------------------------------------------
		{
			name: "servers/list-ok",
			run: func(t *testing.T, e *env) {
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
			},
		},
		{
			name: "servers/list-forbidden",
			run: func(t *testing.T, e *env) {
				e.seedSession(t)
				e.hub.handle("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
					writeHubError(w, http.StatusForbidden, "your role may not list servers")
				})
				e.run(t, "servers list 403", commands.RunServers, cmdutil.ExitForbidden, "list")
			},
		},
		{
			name: "servers/get-ok",
			run: func(t *testing.T, e *env) {
				e.seedSession(t)
				mountServer(e, "srv-1", "web-01")
				e.run(t, "servers get", commands.RunServers, cmdutil.ExitOK, "get", "srv-1")
			},
		},
		{
			name: "servers/get-not-found",
			run: func(t *testing.T, e *env) {
				e.seedSession(t)
				mountServer(e, "srv-1", "web-01")
				e.hub.handle("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
					writeJSON(w, http.StatusOK, api.ServersPage{})
				})
				e.run(t, "servers get 404", commands.RunServers, cmdutil.ExitNotFound, "get", "ghost")
			},
		},
		{
			name: "servers/get-ambiguous",
			run: func(t *testing.T, e *env) {
				e.seedSession(t)
				mountServer(e, "srv-1", "web-01")
				e.hub.handle("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
					writeJSON(w, http.StatusOK, api.ServersPage{
						Servers: []api.Server{{ID: "srv-2", Name: "web"}, {ID: "srv-3", Name: "web"}},
						Total:   2,
					})
				})
				e.run(t, "servers get ambiguous", commands.RunServers, cmdutil.ExitUsage, "get", "web")
			},
		},

		// --- vey files -------------------------------------------------
		{
			name: "files/ls-ok",
			run: func(t *testing.T, e *env) {
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
			},
		},
		{
			name: "files/ls-forbidden",
			run: func(t *testing.T, e *env) {
				e.seedSession(t)
				mountServer(e, "srv-1", "web-01")
				e.hub.handle("GET /api/servers/{id}/files", func(w http.ResponseWriter, r *http.Request) {
					writeHubError(w, http.StatusForbidden, "path /root is outside your allowed roots")
				})
				e.run(t, "files ls 403", commands.RunFiles, cmdutil.ExitForbidden, "ls", "srv-1", "/root")
			},
		},
		{
			name: "files/cat-ok",
			run: func(t *testing.T, e *env) {
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
			},
		},
		{
			name: "files/cat-not-found",
			run: func(t *testing.T, e *env) {
				e.seedSession(t)
				mountServer(e, "srv-1", "web-01")
				e.hub.handle("GET /api/servers/{id}/files/read", func(w http.ResponseWriter, r *http.Request) {
					writeHubError(w, http.StatusNotFound, "no such file: /etc/nope.conf")
				})
				e.run(t, "files cat 404", commands.RunFiles, cmdutil.ExitNotFound, "cat", "srv-1", "/etc/nope.conf")
			},
		},

		// --- vey logs --------------------------------------------------
		{
			name: "logs/tail-brief-stream",
			run: func(t *testing.T, e *env) {
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
			},
		},

		// --- vey audit -------------------------------------------------
		{
			name: "audit/export-forbidden",
			run: func(t *testing.T, e *env) {
				e.seedSession(t)
				e.hub.handle("GET /api/audit-logs/export", func(w http.ResponseWriter, r *http.Request) {
					writeHubError(w, http.StatusForbidden, "audit export requires the admin or auditor role")
				})
				e.run(t, "audit export 403", commands.RunAudit, cmdutil.ExitForbidden, "export")
			},
		},
		{
			name: "audit/export-ok",
			run: func(t *testing.T, e *env) {
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
			},
		},

		// --- vey logout ------------------------------------------------
		{
			name: "logout/session-mode",
			run: func(t *testing.T, e *env) {
				e.seedSession(t)
				e.run(t, "logout session", commands.RunLogout, cmdutil.ExitOK)
			},
		},
		{
			name: "logout/api-token-mode",
			run: func(t *testing.T, e *env) {
				e.useEnvAPIToken(t)
				e.run(t, "logout api-token", commands.RunLogout, cmdutil.ExitAuth)
			},
		},

		// --- transparent refresh ---------------------------------------
		{
			name: "refresh/retry-after-401-then-success",
			run: func(t *testing.T, e *env) {
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
			},
		},
		{
			name: "refresh/terminal-failure",
			run: func(t *testing.T, e *env) {
				// A 401 on refresh: the hub's (reflected) message is
				// discarded and replaced by errSessionExpired's fixed text.
				e.run(t, "servers list with dead session", commands.RunServers, cmdutil.ExitAuth,
					deadRefresh(t, e, http.StatusUnauthorized)...)
			},
		},
		{
			name: "refresh/hub-error-reflects-token",
			run: func(t *testing.T, e *env) {
				// A 5xx on refresh: refresh() deliberately surfaces this one
				// verbatim ("not a race, and not something re-login would
				// fix"), hub message included — so the scrub in postRefresh
				// is the only thing between the reflected token and stderr.
				e.run(t, "servers list with a failing refresh", commands.RunServers, cmdutil.ExitError,
					deadRefresh(t, e, http.StatusInternalServerError)...)
			},
		},
		{
			name: "refresh/rate-limited-reflects-token",
			run: func(t *testing.T, e *env) {
				// Same verbatim-passthrough path, at the other status the
				// code calls out by name (429 → exit 7, never retried).
				e.run(t, "servers list against a rate-limited refresh", commands.RunServers, cmdutil.ExitRateLimited,
					deadRefresh(t, e, http.StatusTooManyRequests)...)
			},
		},
	}
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
		})
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
