package auth

// Contract tests for the interactive login flow (spec 004-cli-connector US1
// scenarios 1 and 6, FR-001/FR-012, research.md R6, contracts/rest-api.md
// "Authentication", data-model.md "Interactive session lifecycle").
//
// The hub is an httptest stub asserting the exact request/response shapes the
// contract pins; the terminal is a scripted fake prompter, so no PTY is needed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/zalando/go-keyring"
)

// Distinctive secrets so leak assertions cannot pass by accident.
const (
	loginTestPassword = "pw-MUST-NOT-LEAK-3f1a9c7b"
	loginTestCode     = "902113"
	loginTestUser     = "alice"
	loginTestRefresh  = "refresh-token-from-hub-77a1"
	loginTestAccess   = "access-token-from-hub-42b0"
)

// ---------------------------------------------------------------- hub stub

// loginHubStub serves the two auth legs with canned responses and records
// every request body it received, so tests can assert both what the CLI sent
// and what it never sent (e.g. no network call at all on a non-TTY login).
type loginHubStub struct {
	mu sync.Mutex

	loginStatus int
	loginBody   string
	totpStatus  int
	totpBody    string

	loginReqs []map[string]any
	totpReqs  []map[string]any
}

func newLoginHubStub(t *testing.T, s *loginHubStub) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		s.record(t, r, false)
		writeLoginJSON(w, s.loginStatus, s.loginBody)
	})
	mux.HandleFunc("/api/auth/login/totp", func(w http.ResponseWriter, r *http.Request) {
		s.record(t, r, true)
		writeLoginJSON(w, s.totpStatus, s.totpBody)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (s *loginHubStub) record(t *testing.T, r *http.Request, totpLeg bool) {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Errorf("%s: got method %s, want POST", r.URL.Path, r.Method)
	}
	body := map[string]any{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Errorf("%s: decoding request body: %v", r.URL.Path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if totpLeg {
		s.totpReqs = append(s.totpReqs, body)
	} else {
		s.loginReqs = append(s.loginReqs, body)
	}
}

func (s *loginHubStub) calls() (login, totp []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loginReqs, s.totpReqs
}

func writeLoginJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if body != "" {
		_, _ = w.Write([]byte(body))
	}
}

func okTOTPBody() string {
	return fmt.Sprintf(
		`{"access_token":%q,"refresh_token":%q,"user":{"username":%q,"role":"admin","extra":"ignored"}}`,
		loginTestAccess, loginTestRefresh, loginTestUser)
}

// ----------------------------------------------------------- fake prompter

type fakeLoginPrompter struct {
	username string
	password string
	code     string

	usernameErr error
	passwordErr error
	codeErr     error

	gotDefaultUser string
	calls          []string
}

func (p *fakeLoginPrompter) Username(defaultUser string) (string, error) {
	p.calls = append(p.calls, "username")
	p.gotDefaultUser = defaultUser
	return p.username, p.usernameErr
}

func (p *fakeLoginPrompter) Password() (string, error) {
	p.calls = append(p.calls, "password")
	return p.password, p.passwordErr
}

func (p *fakeLoginPrompter) TOTPCode() (string, error) {
	p.calls = append(p.calls, "totp")
	return p.code, p.codeErr
}

func scriptedPrompter() *fakeLoginPrompter {
	return &fakeLoginPrompter{
		username: loginTestUser,
		password: loginTestPassword,
		code:     loginTestCode,
	}
}

// -------------------------------------------------------------- store fakes

// newLoginTestStore returns a real keyring-backed store over a mock keyring,
// so the assertions exercise the same code path production uses.
func newLoginTestStore(t *testing.T) Store {
	t.Helper()
	keyring.MockInit()
	st, err := NewStore(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return st
}

// failingLoginStore fails every Save, to prove a persistence failure is
// reported rather than silently half-succeeding.
type failingLoginStore struct {
	err    error
	tried  int
	backed Store
}

func (s *failingLoginStore) Save(hubURL string, sess StoredSession) error {
	s.tried++
	return s.err
}
func (s *failingLoginStore) Load(hubURL string) (StoredSession, bool, error) {
	return s.backed.Load(hubURL)
}
func (s *failingLoginStore) Delete(hubURL string) error { return s.backed.Delete(hubURL) }
func (s *failingLoginStore) Backend() string            { return s.backed.Backend() }

// The SSH half of the Store interface is irrelevant to login and is simply
// delegated: login neither reads nor writes SSH material.
func (s *failingLoginStore) SaveSSH(hubURL string, m StoredSSH) error {
	return s.backed.SaveSSH(hubURL, m)
}
func (s *failingLoginStore) LoadSSH(hubURL string) (StoredSSH, bool, error) {
	return s.backed.LoadSSH(hubURL)
}

// ------------------------------------------------------------- assertions

func assertLoginExitCode(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error with exit code %d, got nil", want)
	}
	if got := cmdutil.Code(err); got != want {
		t.Fatalf("exit code = %d, want %d (err: %v)", got, want, err)
	}
}

func assertNothingStored(t *testing.T, st Store, hubURL string) {
	t.Helper()
	sess, ok, err := st.Load(hubURL)
	if err != nil {
		t.Fatalf("Load after failed login: %v", err)
	}
	if ok {
		t.Fatalf("failed login stored a session: %+v", StoredSession{Username: sess.Username, Role: sess.Role})
	}
}

func assertNoSecretsIn(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	for _, secret := range []string{loginTestPassword, loginTestCode} {
		if strings.Contains(msg, secret) {
			t.Fatalf("error message leaks a secret: %q", msg)
		}
	}
}

func nonTTYStdin(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// ------------------------------------------------------------------ tests

// Contract: 202 {totp_token} → prompt code → 200 {access,refresh,user}, then
// the refresh token is persisted for the hub (US1 scenario 1).
func TestLoginHappyPathThreeLeg(t *testing.T) {
	stub := &loginHubStub{
		loginStatus: http.StatusAccepted,
		loginBody:   `{"totp_token":"tt-abc123"}`,
		totpStatus:  http.StatusOK,
		totpBody:    okTOTPBody(),
	}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)
	prompter := scriptedPrompter()

	start := time.Now().Add(-time.Second)
	pair, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: prompter,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	assertLoginTokenPairAndUser(t, pair)
	assertLoginRequestBodiesAndPromptOrder(t, stub, prompter)
	assertLoginStoredSession(t, store, srv.URL, start)
}

// assertLoginTokenPairAndUser checks the TokenPair Login returns directly:
// both tokens came from the totp leg, and the user identity matches.
func assertLoginTokenPairAndUser(t *testing.T, pair *api.TokenPair) {
	t.Helper()
	if pair == nil {
		t.Fatal("Login returned a nil TokenPair")
	}
	if pair.AccessToken != loginTestAccess || pair.RefreshToken != loginTestRefresh {
		t.Fatalf("token pair not returned from the totp leg (access ok=%t refresh ok=%t)",
			pair.AccessToken == loginTestAccess, pair.RefreshToken == loginTestRefresh)
	}
	if pair.User.Username != loginTestUser || pair.User.Role != "admin" {
		t.Fatalf("user = %+v, want {alice admin}", pair.User)
	}
}

// assertLoginRequestBodiesAndPromptOrder checks what Login actually sent to
// the hub and the order in which it prompted for credentials.
func assertLoginRequestBodiesAndPromptOrder(t *testing.T, stub *loginHubStub, prompter *fakeLoginPrompter) {
	t.Helper()
	loginReqs, totpReqs := stub.calls()
	if len(loginReqs) != 1 || len(totpReqs) != 1 {
		t.Fatalf("calls: login=%d totp=%d, want 1 and 1", len(loginReqs), len(totpReqs))
	}
	if loginReqs[0]["username"] != loginTestUser || loginReqs[0]["password"] != loginTestPassword {
		t.Fatalf("login leg body = %v, want {username,password}", redactLoginBody(loginReqs[0]))
	}
	if totpReqs[0]["totp_token"] != "tt-abc123" || totpReqs[0]["code"] != loginTestCode {
		t.Fatalf("totp leg body = %v, want {totp_token:tt-abc123, code}", redactLoginBody(totpReqs[0]))
	}

	if want := []string{"username", "password", "totp"}; strings.Join(prompter.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("prompt order = %v, want %v", prompter.calls, want)
	}
}

// assertLoginStoredSession checks what a successful login persisted: the
// refresh token and identity, a fresh ObtainedAt, and — the point of the
// check — that the access token never reaches the credential store.
func assertLoginStoredSession(t *testing.T, store Store, hubURL string, start time.Time) {
	t.Helper()
	sess, ok, err := store.Load(hubURL)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok {
		t.Fatal("no session stored after a successful login")
	}
	if sess.RefreshToken != loginTestRefresh {
		t.Fatal("stored refresh token does not match the one the hub issued")
	}
	if sess.Username != loginTestUser || sess.Role != "admin" {
		t.Fatalf("stored identity = %s/%s, want alice/admin", sess.Username, sess.Role)
	}
	if sess.ObtainedAt.Before(start) || sess.ObtainedAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("ObtainedAt = %v, want ~now", sess.ObtainedAt)
	}
	// Only the refresh token is persisted (data-model.md): the access token
	// must not appear anywhere in the stored record.
	if blob, _ := json.Marshal(sess); strings.Contains(string(blob), loginTestAccess) {
		t.Fatal("stored session contains the access token")
	}
}

func redactLoginBody(body map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range body {
		if k == "password" || k == "code" {
			out[k] = "<redacted>"
			continue
		}
		out[k] = v
	}
	return out
}

// Contract: 200 {setup_token, requires_totp_setup:true} → enrollment guidance,
// exit 3, no TOTP prompt, no second leg, nothing stored (US1 scenario 6, R6).
func TestLoginRequiresTOTPSetupAbortsWithGuidance(t *testing.T) {
	stub := &loginHubStub{
		loginStatus: http.StatusOK,
		loginBody:   `{"setup_token":"st-xyz","requires_totp_setup":true}`,
	}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)
	prompter := scriptedPrompter()

	pair, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: prompter,
	})

	assertLoginExitCode(t, err, cmdutil.ExitAuth)
	assertNoSecretsIn(t, err)
	if pair != nil {
		t.Fatal("Login returned a token pair despite requiring TOTP setup")
	}

	msg := strings.ToLower(err.Error())
	for _, want := range []string{"enroll", "web"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("guidance %q does not mention %q", err.Error(), want)
		}
	}
	if strings.Contains(err.Error(), "st-xyz") {
		t.Fatal("guidance leaks the setup token")
	}

	if _, totpReqs := stub.calls(); len(totpReqs) != 0 {
		t.Fatalf("totp leg called %d times, want 0", len(totpReqs))
	}
	for _, c := range prompter.calls {
		if c == "totp" {
			t.Fatal("prompted for a TOTP code although enrollment is incomplete")
		}
	}
	assertNothingStored(t, store, srv.URL)
}

// Contract: 401 on the TOTP leg (bad/expired code) → exit 3, nothing stored.
func TestLoginBadTOTPCodeExitsAuth(t *testing.T) {
	stub := &loginHubStub{
		loginStatus: http.StatusAccepted,
		loginBody:   `{"totp_token":"tt-abc123"}`,
		totpStatus:  http.StatusUnauthorized,
		totpBody:    `{"error":"invalid or expired code"}`,
	}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)

	pair, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: scriptedPrompter(),
	})

	assertLoginExitCode(t, err, cmdutil.ExitAuth)
	assertNoSecretsIn(t, err)
	if pair != nil {
		t.Fatal("Login returned a token pair after a rejected TOTP code")
	}
	if !strings.Contains(err.Error(), "invalid or expired code") {
		t.Fatalf("error %q does not surface the hub's message", err)
	}
	assertNothingStored(t, store, srv.URL)
}

// Contract: 401 on the password leg → exit 3, no TOTP prompt, nothing stored.
func TestLoginBadPasswordExitsAuth(t *testing.T) {
	stub := &loginHubStub{
		loginStatus: http.StatusUnauthorized,
		loginBody:   `{"error":"invalid credentials"}`,
	}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)
	prompter := scriptedPrompter()

	_, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: prompter,
	})

	assertLoginExitCode(t, err, cmdutil.ExitAuth)
	assertNoSecretsIn(t, err)
	for _, c := range prompter.calls {
		if c == "totp" {
			t.Fatal("prompted for a TOTP code after the password was rejected")
		}
	}
	assertNothingStored(t, store, srv.URL)
}

// Contract: 429 from the login limiter → exit 7, surfaced without retry.
func TestLoginRateLimitedExitsSeven(t *testing.T) {
	t.Run("password leg", func(t *testing.T) {
		stub := &loginHubStub{
			loginStatus: http.StatusTooManyRequests,
			loginBody:   `{"error":"too many login attempts"}`,
		}
		srv := newLoginHubStub(t, stub)
		store := newLoginTestStore(t)

		_, err := Login(context.Background(), LoginOptions{
			Client:   api.NewClient(srv.URL, ""),
			HubURL:   srv.URL,
			Store:    store,
			Prompter: scriptedPrompter(),
		})

		assertLoginExitCode(t, err, cmdutil.ExitRateLimited)
		assertNoSecretsIn(t, err)
		if loginReqs, _ := stub.calls(); len(loginReqs) != 1 {
			t.Fatalf("login leg called %d times, want exactly 1 (no client-side retry)", len(loginReqs))
		}
		assertNothingStored(t, store, srv.URL)
	})

	t.Run("totp leg", func(t *testing.T) {
		stub := &loginHubStub{
			loginStatus: http.StatusAccepted,
			loginBody:   `{"totp_token":"tt-abc123"}`,
			totpStatus:  http.StatusTooManyRequests,
			totpBody:    `{"error":"too many attempts"}`,
		}
		srv := newLoginHubStub(t, stub)
		store := newLoginTestStore(t)

		_, err := Login(context.Background(), LoginOptions{
			Client:   api.NewClient(srv.URL, ""),
			HubURL:   srv.URL,
			Store:    store,
			Prompter: scriptedPrompter(),
		})

		assertLoginExitCode(t, err, cmdutil.ExitRateLimited)
		if _, totpReqs := stub.calls(); len(totpReqs) != 1 {
			t.Fatalf("totp leg called %d times, want exactly 1 (no client-side retry)", len(totpReqs))
		}
		assertNothingStored(t, store, srv.URL)
	})
}

// Contract: a non-TTY `vey login` fails fast with API-token guidance (FR-012,
// R6) — before any prompt and before any network call.
func TestLoginNonTTYFailsFastWithAPITokenGuidance(t *testing.T) {
	stub := &loginHubStub{
		loginStatus: http.StatusAccepted,
		loginBody:   `{"totp_token":"tt-abc123"}`,
		totpStatus:  http.StatusOK,
		totpBody:    okTOTPBody(),
	}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)

	pair, err := Login(context.Background(), LoginOptions{
		Client: api.NewClient(srv.URL, ""),
		HubURL: srv.URL,
		Store:  store,
		// Prompter left nil: the terminal prompter is what needs a TTY.
		Stdin: nonTTYStdin(t),
	})

	assertLoginExitCode(t, err, cmdutil.ExitAuth)
	if pair != nil {
		t.Fatal("Login returned a token pair with no TTY attached")
	}
	if !strings.Contains(err.Error(), "VEYPORT_TOKEN") {
		t.Fatalf("non-TTY error %q does not point at VEYPORT_TOKEN", err)
	}

	loginReqs, totpReqs := stub.calls()
	if len(loginReqs) != 0 || len(totpReqs) != 0 {
		t.Fatalf("non-TTY login hit the hub: login=%d totp=%d, want 0 and 0", len(loginReqs), len(totpReqs))
	}
	assertNothingStored(t, store, srv.URL)
}

// The password and the one-time code must never reach an error string.
func TestLoginErrorsNeverContainSecrets(t *testing.T) {
	cases := []struct {
		name string
		// echoesSecret marks a stub whose hub message contains the secret
		// verbatim, so the CLI must redact it before showing the message.
		echoesSecret bool
		wantCode     int
		stub         *loginHubStub
	}{
		{
			name:         "hub echoes the password back",
			echoesSecret: true,
			wantCode:     cmdutil.ExitAuth,
			stub: &loginHubStub{
				loginStatus: http.StatusUnauthorized,
				loginBody:   fmt.Sprintf(`{"error":"invalid credentials for %s"}`, loginTestPassword),
			},
		},
		{
			name:         "hub echoes the one-time code back",
			echoesSecret: true,
			wantCode:     cmdutil.ExitAuth,
			stub: &loginHubStub{
				loginStatus: http.StatusAccepted,
				loginBody:   `{"totp_token":"tt-abc123"}`,
				totpStatus:  http.StatusUnauthorized,
				totpBody:    fmt.Sprintf(`{"error":"bad code %s"}`, loginTestCode),
			},
		},
		{
			name:     "server error",
			wantCode: cmdutil.ExitError,
			stub: &loginHubStub{
				loginStatus: http.StatusInternalServerError,
				loginBody:   `{"error":"boom"}`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newLoginHubStub(t, tc.stub)
			store := newLoginTestStore(t)

			_, err := Login(context.Background(), LoginOptions{
				Client:   api.NewClient(srv.URL, ""),
				HubURL:   srv.URL,
				Store:    store,
				Prompter: scriptedPrompter(),
			})

			assertLoginExitCode(t, err, tc.wantCode)
			// The invariant is absolute: whatever the hub says, the rendered
			// error never carries the password or the one-time code.
			assertNoSecretsIn(t, err)
			if tc.echoesSecret && !strings.Contains(err.Error(), "[redacted]") {
				t.Fatalf("echoed secret was dropped without a redaction marker: %q", err)
			}
			assertNothingStored(t, store, srv.URL)
		})
	}
}

// A persistence failure must surface as an error: no silent half-success.
func TestLoginStoreSaveFailureIsAnError(t *testing.T) {
	stub := &loginHubStub{
		loginStatus: http.StatusAccepted,
		loginBody:   `{"totp_token":"tt-abc123"}`,
		totpStatus:  http.StatusOK,
		totpBody:    okTOTPBody(),
	}
	srv := newLoginHubStub(t, stub)
	saveErr := errors.New("keyring is locked")
	store := &failingLoginStore{err: saveErr, backed: newLoginTestStore(t)}

	pair, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: scriptedPrompter(),
	})
	if err == nil {
		t.Fatal("expected an error when the session cannot be persisted")
	}
	if !errors.Is(err, saveErr) {
		t.Fatalf("error %v does not wrap the store failure", err)
	}
	if pair != nil {
		t.Fatal("Login returned a token pair although nothing was persisted")
	}
	if store.tried != 1 {
		t.Fatalf("Save attempted %d times, want 1", store.tried)
	}
	assertNoSecretsIn(t, err)
}

// A 2xx that is neither the TOTP-pending nor the setup-required shape is a
// protocol error, not a silent success.
func TestLoginUnexpectedResponseIsAnError(t *testing.T) {
	stub := &loginHubStub{
		loginStatus: http.StatusOK,
		loginBody:   `{"something_else":true}`,
	}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)

	_, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: scriptedPrompter(),
	})
	if err == nil {
		t.Fatal("expected an error for an unrecognized login response")
	}
	assertNoSecretsIn(t, err)
	assertNothingStored(t, store, srv.URL)
}

// An empty username is rejected locally: no credentials are put on the wire.
func TestLoginRequiresAUsername(t *testing.T) {
	stub := &loginHubStub{loginStatus: http.StatusAccepted, loginBody: `{"totp_token":"tt"}`}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)
	prompter := scriptedPrompter()
	prompter.username = "   "

	_, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: prompter,
	})
	if err == nil {
		t.Fatal("expected an error for an empty username")
	}
	if loginReqs, _ := stub.calls(); len(loginReqs) != 0 {
		t.Fatalf("empty username was sent to the hub (%d calls)", len(loginReqs))
	}
	assertNoSecretsIn(t, err)
}

// A prompt that fails aborts the flow without contacting the hub.
func TestLoginPromptFailureAborts(t *testing.T) {
	stub := &loginHubStub{loginStatus: http.StatusAccepted, loginBody: `{"totp_token":"tt"}`}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)
	prompter := scriptedPrompter()
	prompter.passwordErr = errors.New("terminal closed")

	_, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: prompter,
	})
	if err == nil {
		t.Fatal("expected an error when the password prompt fails")
	}
	if !errors.Is(err, prompter.passwordErr) {
		t.Fatalf("error %v does not wrap the prompt failure", err)
	}
	if loginReqs, _ := stub.calls(); len(loginReqs) != 0 {
		t.Fatalf("hub was contacted despite a failed prompt (%d calls)", len(loginReqs))
	}
	assertNothingStored(t, store, srv.URL)
}

// The terminal prompter reads line-oriented answers from its input file and
// writes prompts to its output writer; the TOTP prompt states the 60-second
// validity window (R6).
func TestTerminalPrompterReadsAnswersAndStatesTOTPValidity(t *testing.T) {
	in, err := os.CreateTemp(t.TempDir(), "prompter-in")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() { _ = in.Close() })
	if _, err := in.WriteString("  bob \n" + loginTestCode + "\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if _, err := in.Seek(0, 0); err != nil {
		t.Fatalf("Seek: %v", err)
	}

	var out strings.Builder
	p := NewTerminalPrompter(in, &out)

	user, err := p.Username("carol")
	if err != nil {
		t.Fatalf("Username: %v", err)
	}
	if user != "bob" {
		t.Fatalf("Username = %q, want %q (trimmed)", user, "bob")
	}

	code, err := p.TOTPCode()
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	if code != loginTestCode {
		t.Fatalf("TOTPCode = %q, want %q", code, loginTestCode)
	}

	prompts := out.String()
	if !strings.Contains(prompts, "carol") {
		t.Fatalf("username prompt %q does not offer the default", prompts)
	}
	if !strings.Contains(prompts, "60") {
		t.Fatalf("TOTP prompt %q does not state the 60-second validity window", prompts)
	}
}

// An empty answer keeps the offered default (US1: re-running login should not
// force retyping the username).
func TestTerminalPrompterEmptyAnswerKeepsDefault(t *testing.T) {
	in, err := os.CreateTemp(t.TempDir(), "prompter-in")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() { _ = in.Close() })
	if _, err := in.WriteString("\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if _, err := in.Seek(0, 0); err != nil {
		t.Fatalf("Seek: %v", err)
	}

	var out strings.Builder
	user, err := NewTerminalPrompter(in, &out).Username("dana")
	if err != nil {
		t.Fatalf("Username: %v", err)
	}
	if user != "dana" {
		t.Fatalf("Username = %q, want the default %q", user, "dana")
	}
}

// --- coverage: guard clauses and edge cases not reached above ---------------

// TestLoginRejectsNilClient covers Login's own nil-client guard: a caller
// bug, not a hub failure, so it must never reach the network.
func TestLoginRejectsNilClient(t *testing.T) {
	_, err := Login(context.Background(), LoginOptions{
		Client:   nil,
		HubURL:   "https://hub.example.com",
		Store:    newLoginTestStore(t),
		Prompter: scriptedPrompter(),
	})
	if err == nil {
		t.Fatal("Login succeeded with a nil client, want error")
	}
	if code := cmdutil.Code(err); code != cmdutil.ExitError {
		t.Errorf("exit code = %d, want %d", code, cmdutil.ExitError)
	}
}

// TestLoginRejectsNilStore covers Login's own nil-store guard.
func TestLoginRejectsNilStore(t *testing.T) {
	_, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient("https://hub.example.com", ""),
		HubURL:   "https://hub.example.com",
		Store:    nil,
		Prompter: scriptedPrompter(),
	})
	if err == nil {
		t.Fatal("Login succeeded with a nil store, want error")
	}
	if code := cmdutil.Code(err); code != cmdutil.ExitError {
		t.Errorf("exit code = %d, want %d", code, cmdutil.ExitError)
	}
}

// TestLoginFallsBackToClientBaseURLWhenHubURLEmpty covers Login's HubURL
// fallback: every other test in this file supplies HubURL explicitly, so
// this pins the "HubURL empty → use Client.BaseURL as the credential-store
// key" branch on its own.
func TestLoginFallsBackToClientBaseURLWhenHubURLEmpty(t *testing.T) {
	stub := &loginHubStub{
		loginStatus: http.StatusAccepted,
		loginBody:   `{"totp_token":"tt-abc123"}`,
		totpStatus:  http.StatusOK,
		totpBody:    okTOTPBody(),
	}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)

	_, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   "",
		Store:    store,
		Prompter: scriptedPrompter(),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, ok, loadErr := store.Load(srv.URL); loadErr != nil || !ok {
		t.Fatalf("session not stored under Client.BaseURL = %q: (ok %v, err %v)", srv.URL, ok, loadErr)
	}
}

// TestLoginPropagatesTOTPCodePromptError covers Login's own handling of a
// failed TOTPCode() prompt, distinct from TestLoginPromptFailureAborts (which
// only exercises the earlier Password() prompt failure).
func TestLoginPropagatesTOTPCodePromptError(t *testing.T) {
	stub := &loginHubStub{loginStatus: http.StatusAccepted, loginBody: `{"totp_token":"tt-abc123"}`}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)
	prompter := scriptedPrompter()
	prompter.codeErr = errors.New("terminal closed")

	_, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: prompter,
	})
	if err == nil {
		t.Fatal("Login succeeded despite a failed TOTP-code prompt, want error")
	}
	if !errors.Is(err, prompter.codeErr) {
		t.Fatalf("error %v does not wrap the prompt failure", err)
	}
	assertNothingStored(t, store, srv.URL)
}

// TestLoginRejectsEmptyTOTPCode covers Login's local validation of the
// prompted one-time code: a whitespace-only answer must never reach the hub.
func TestLoginRejectsEmptyTOTPCode(t *testing.T) {
	stub := &loginHubStub{loginStatus: http.StatusAccepted, loginBody: `{"totp_token":"tt-abc123"}`}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)
	prompter := scriptedPrompter()
	prompter.code = "   "

	_, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: prompter,
	})
	assertLoginExitCode(t, err, cmdutil.ExitUsage)
	if _, totpReqs := stub.calls(); len(totpReqs) != 0 {
		t.Fatalf("empty one-time code was sent to the hub (%d calls)", len(totpReqs))
	}
	assertNothingStored(t, store, srv.URL)
}

// TestLoginRejectsIncompleteTokenPairFromHub covers Login's guard against a
// hub bug that accepts the one-time code but returns a half-populated pair:
// nothing may be adopted or persisted in that case.
func TestLoginRejectsIncompleteTokenPairFromHub(t *testing.T) {
	stub := &loginHubStub{
		loginStatus: http.StatusAccepted,
		loginBody:   `{"totp_token":"tt-abc123"}`,
		totpStatus:  http.StatusOK,
		totpBody:    fmt.Sprintf(`{"access_token":%q,"user":{"username":%q,"role":"admin"}}`, loginTestAccess, loginTestUser),
	}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)

	pair, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: scriptedPrompter(),
	})
	if err == nil {
		t.Fatal("Login succeeded with a token pair missing its refresh token, want error")
	}
	if pair != nil {
		t.Fatal("Login returned a token pair it should have rejected")
	}
	assertNoSecretsIn(t, err)
	assertNothingStored(t, store, srv.URL)
}

// TestLoginFallsBackToPromptedUsernameWhenHubOmitsIt covers Login's identity
// fallback: when the hub's totp-leg response carries no user object at all,
// the stored session's username must be the one the operator typed, not
// empty.
func TestLoginFallsBackToPromptedUsernameWhenHubOmitsIt(t *testing.T) {
	stub := &loginHubStub{
		loginStatus: http.StatusAccepted,
		loginBody:   `{"totp_token":"tt-abc123"}`,
		totpStatus:  http.StatusOK,
		totpBody:    fmt.Sprintf(`{"access_token":%q,"refresh_token":%q}`, loginTestAccess, loginTestRefresh),
	}
	srv := newLoginHubStub(t, stub)
	store := newLoginTestStore(t)

	pair, err := Login(context.Background(), LoginOptions{
		Client:   api.NewClient(srv.URL, ""),
		HubURL:   srv.URL,
		Store:    store,
		Prompter: scriptedPrompter(),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if pair.User.Username != loginTestUser {
		t.Errorf("returned identity = %q, want the prompted username %q", pair.User.Username, loginTestUser)
	}
	sess, ok, err := store.Load(srv.URL)
	if err != nil || !ok {
		t.Fatalf("Load = (ok %v, err %v)", ok, err)
	}
	if sess.Username != loginTestUser {
		t.Errorf("stored username = %q, want the prompted %q", sess.Username, loginTestUser)
	}
}

// TestResolvePrompterDefaultsToOSStdin covers resolvePrompter's own nil-stdin
// default (every other test that exercises the non-interactive path supplies
// an explicit Stdin file). Whichever branch it then takes depends on whether
// the test runner's own stdin happens to be a terminal; either outcome is
// acceptable here, since the point is exercising the defaulting assignment
// itself without panicking on a nil *os.File.
func TestResolvePrompterDefaultsToOSStdin(t *testing.T) {
	p, err := resolvePrompter(nil, nil)
	if err != nil {
		if code := cmdutil.Code(err); code != cmdutil.ExitAuth {
			t.Errorf("exit code = %d, want %d", code, cmdutil.ExitAuth)
		}
		return
	}
	if p == nil {
		t.Fatal("resolvePrompter returned a nil prompter with a nil error")
	}
}

// TestPromptCredentialsPropagatesUsernameError covers promptCredentials' own
// username-prompt error handling, called directly (this file is in package
// auth).
func TestPromptCredentialsPropagatesUsernameError(t *testing.T) {
	p := scriptedPrompter()
	p.usernameErr = errors.New("terminal closed")

	_, _, err := promptCredentials(p)
	if err == nil {
		t.Fatal("promptCredentials succeeded despite a failed username prompt, want error")
	}
	if !errors.Is(err, p.usernameErr) {
		t.Fatalf("error %v does not wrap the prompt failure", err)
	}
}

// TestPromptCredentialsRejectsEmptyPassword covers promptCredentials' local
// validation of the password answer.
func TestPromptCredentialsRejectsEmptyPassword(t *testing.T) {
	p := scriptedPrompter()
	p.password = ""

	_, _, err := promptCredentials(p)
	if err == nil {
		t.Fatal("promptCredentials succeeded with an empty password, want error")
	}
	if code := cmdutil.Code(err); code != cmdutil.ExitUsage {
		t.Errorf("exit code = %d, want %d", code, cmdutil.ExitUsage)
	}
}

// TestScrubSecretSkipsShortSecrets covers scrubSecret's own guard against
// substring-matching a secret too short to be worth it: below
// minRedactableSecret, a real hub message could contain the "secret" by pure
// coincidence, so scrubSecret leaves the error untouched rather than garbling
// it.
func TestScrubSecretSkipsShortSecrets(t *testing.T) {
	orig := errors.New("hub rejected code abc")
	got := scrubSecret(orig, "abc") // len 3 < minRedactableSecret (4)
	if got != orig {
		t.Errorf("scrubSecret altered an error for a secret shorter than the redaction floor: got %v, want the original error unchanged", got)
	}
}

// TestNewTerminalPrompterDefaultsInAndOut covers NewTerminalPrompter's own
// nil-in and nil-out defaulting, called directly with each left nil in turn
// (this file is in package auth, so the concrete *terminalPrompter fields
// are visible for the assertion).
func TestNewTerminalPrompterDefaultsInAndOut(t *testing.T) {
	t.Run("nil in defaults to os.Stdin", func(t *testing.T) {
		var out strings.Builder
		p, ok := NewTerminalPrompter(nil, &out).(*terminalPrompter)
		if !ok {
			t.Fatalf("NewTerminalPrompter returned %T, want *terminalPrompter", NewTerminalPrompter(nil, &out))
		}
		if p.in != os.Stdin {
			t.Error("nil in did not default to os.Stdin")
		}
	})

	t.Run("nil out defaults to os.Stderr", func(t *testing.T) {
		in, err := os.CreateTemp(t.TempDir(), "prompter-in")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		t.Cleanup(func() { _ = in.Close() })

		p, ok := NewTerminalPrompter(in, nil).(*terminalPrompter)
		if !ok {
			t.Fatalf("NewTerminalPrompter returned %T, want *terminalPrompter", NewTerminalPrompter(in, nil))
		}
		if p.out != os.Stderr {
			t.Error("nil out did not default to os.Stderr")
		}
	})
}

// TestTerminalPrompterUsernamePropagatesReadLineError covers both
// Username()'s own readLine-error return and readLine's non-EOF error-wrap
// branch: reading from an already-closed file produces a genuine read error
// (not io.EOF), which must surface as a wrapped "reading input" error rather
// than being treated as a normal end of input.
func TestTerminalPrompterUsernamePropagatesReadLineError(t *testing.T) {
	in, err := os.CreateTemp(t.TempDir(), "prompter-in")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var out strings.Builder
	p := NewTerminalPrompter(in, &out)
	if _, err := p.Username("default"); err == nil {
		t.Fatal("Username succeeded reading from a closed file, want error")
	} else if errors.Is(err, io.EOF) {
		t.Errorf("error %v was treated as a normal EOF, want a wrapped read error", err)
	}
}
