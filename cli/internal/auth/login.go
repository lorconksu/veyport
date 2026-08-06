package auth

// Interactive login (spec 004-cli-connector US1 scenarios 1 and 6, FR-001,
// FR-012; research.md R6; contracts/rest-api.md "Authentication";
// data-model.md "Interactive session lifecycle").
//
// The flow has three legs:
//
//	1. prompt username + password (no echo)
//	2. POST /api/auth/login  → 202 {totp_token} (60 s TTL) | 200 {requires_totp_setup}
//	3. prompt one-time code → POST /api/auth/login/totp → 200 {access, refresh, user}
//
// Only after leg 3 succeeds is anything persisted, and only the refresh token
// (data-model.md): the access token stays in process memory. The password and
// the one-time code are never stored, logged, or embedded in an error.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"golang.org/x/term"
)

const (
	loginPath = "/api/auth/login"
	totpPath  = "/api/auth/login/totp"

	// totpTTLSeconds is the hub's lifetime for a totp_token
	// (contracts/rest-api.md). The prompt states it so a user who walks away
	// understands why the code was rejected.
	totpTTLSeconds = 60
)

// LoginPrompter collects the interactive credentials `vey login` needs. It is
// an interface so tests (and any future non-terminal front-end) can supply
// answers without a PTY; production uses NewTerminalPrompter.
type LoginPrompter interface {
	// Username prompts for the hub username, offering defaultUser (which may
	// be empty) when the user just presses Enter.
	Username(defaultUser string) (string, error)
	// Password prompts for the password without echoing it.
	Password() (string, error)
	// TOTPCode prompts for the one-time code; the prompt text states the
	// 60-second validity window.
	TOTPCode() (string, error)
}

// LoginOptions configures Login.
type LoginOptions struct {
	// Client is an unauthenticated client for the hub; both login legs are
	// unauthenticated, so its Token is expected to be empty.
	Client *api.Client
	// HubURL is the normalized hub URL used as the credential-store key
	// (FR-005). Empty falls back to Client.BaseURL.
	HubURL string
	// Store persists the resulting session.
	Store Store
	// Prompter supplies the interactive answers. Nil means
	// NewTerminalPrompter(Stdin, os.Stderr).
	Prompter LoginPrompter
	// Stdin is the terminal to read from and to test for TTY-ness. Nil means
	// os.Stdin.
	Stdin *os.File
}

// Login runs the three-leg interactive flow and returns the signed-in
// TokenPair (access token, refresh token, and user identity). On success the
// refresh token is already persisted for the hub before the function returns.
//
// Errors carry the CLI exit-code taxonomy (cmdutil): the hub's own failures
// are passed through with the code the API client assigned them (401 → 3,
// 429 → 7) rather than re-mapped here.
func Login(ctx context.Context, opts LoginOptions) (*api.TokenPair, error) {
	prompter, err := resolvePrompter(opts.Prompter, opts.Stdin)
	if err != nil {
		return nil, err
	}

	if opts.Client == nil {
		return nil, cmdutil.NewCodedError(cmdutil.ExitError, errors.New("auth: login requires an API client"))
	}
	if opts.Store == nil {
		return nil, cmdutil.NewCodedError(cmdutil.ExitError, errors.New("auth: login requires a credential store"))
	}
	hubURL := opts.HubURL
	if strings.TrimSpace(hubURL) == "" {
		hubURL = opts.Client.BaseURL
	}

	username, password, err := promptCredentials(prompter)
	if err != nil {
		return nil, err
	}

	totpToken, err := postPassword(ctx, opts.Client, username, password)
	if err != nil {
		return nil, err
	}

	code, err := prompter.TOTPCode()
	if err != nil {
		return nil, cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("reading one-time code: %w", err))
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, cmdutil.NewUsageError(errors.New("one-time code is required"))
	}

	var pair api.TokenPair
	if err := opts.Client.Post(ctx, totpPath, map[string]string{
		"totp_token": totpToken,
		"code":       code,
	}, &pair); err != nil {
		// Already a CodedError from the api client (401 → exit 3, 429 → 7);
		// scrubbed in case the hub echoed either credential back in its
		// message. Both halves of the request are secret: the one-time code
		// the user typed, and the challenge token the hub issued in leg 2
		// (which proves the password was already verified and is a bearer
		// credential for the 60 s it lives).
		return nil, scrubSecret(scrubSecret(err, code), totpToken)
	}
	if pair.RefreshToken == "" || pair.AccessToken == "" {
		return nil, cmdutil.NewCodedError(cmdutil.ExitError,
			errors.New("hub accepted the one-time code but returned an incomplete token pair"))
	}

	// Persist before returning: a caller that sees success must be able to
	// rely on the session being on disk (data-model.md), so a store failure
	// is a login failure, not a silent half-success.
	if pair.User.Username == "" {
		pair.User.Username = username
	}
	sess := StoredSession{
		RefreshToken: pair.RefreshToken,
		Username:     pair.User.Username,
		Role:         pair.User.Role,
		ObtainedAt:   time.Now().UTC(),
	}
	if err := opts.Store.Save(hubURL, sess); err != nil {
		// The store error is scrubbed of the value it was handed: a backend
		// that quotes the secret it failed to write (an OS keyring relaying
		// a provider message, say) must not turn a save failure into a leak.
		return nil, cmdutil.NewCodedError(cmdutil.ExitError,
			fmt.Errorf("signed in, but saving the session failed: %w", scrubSecret(err, sess.RefreshToken)))
	}

	return &pair, nil
}

// resolvePrompter returns the prompter Login should use: the caller's, if it
// supplied one, otherwise a terminal prompter over stdin (os.Stdin when nil).
//
// The terminal prompter is the only thing here that requires a TTY, so the TTY
// check belongs with it: a caller that brings its own prompter has its own
// input source and stdin is irrelevant. With no terminal there is nothing to
// prompt, so this fails before any prompt and before any network call,
// pointing at the non-interactive path (FR-012, R6).
func resolvePrompter(p LoginPrompter, stdin *os.File) (LoginPrompter, error) {
	if p != nil {
		return p, nil
	}
	if stdin == nil {
		stdin = os.Stdin
	}
	if !term.IsTerminal(int(stdin.Fd())) {
		return nil, cmdutil.NewAuthError(errors.New(
			"vey login needs an interactive terminal, and stdin is not one; " +
				"for scripts and CI, use an API token instead: set VEYPORT_TOKEN=adt_... " +
				"(create one in the web UI under Settings → API Tokens)"))
	}
	return NewTerminalPrompter(stdin, os.Stderr), nil
}

// promptCredentials collects username and password, validating the username
// locally so an obviously empty attempt never reaches the login limiter.
func promptCredentials(p LoginPrompter) (username, password string, err error) {
	username, err = p.Username("")
	if err != nil {
		return "", "", cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("reading username: %w", err))
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", "", cmdutil.NewUsageError(errors.New("username is required"))
	}

	password, err = p.Password()
	if err != nil {
		// The error is wrapped, never the value: a read failure must not
		// carry whatever partial input was consumed.
		return "", "", cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("reading password: %w", err))
	}
	if password == "" {
		return "", "", cmdutil.NewUsageError(errors.New("password is required"))
	}
	return username, password, nil
}

// postPassword performs leg 2 and returns the totp_token to use for leg 3.
//
// The hub answers 202 {totp_token} or 200 {setup_token, requires_totp_setup};
// both are 2xx, so the two shapes are decoded together and told apart by
// their fields rather than by status code.
func postPassword(ctx context.Context, client *api.Client, username, password string) (string, error) {
	var resp struct {
		api.LoginTOTPPending
		api.LoginSetupRequired
	}
	if err := client.Post(ctx, loginPath, map[string]string{
		"username": username,
		"password": password,
	}, &resp); err != nil {
		// Already a CodedError from the api client (401 → exit 3, 429 → 7);
		// re-wrapping would change the exit code the contract pins, so the
		// error is only scrubbed, never re-coded.
		return "", scrubSecret(err, password)
	}

	if resp.RequiresTOTPSetup || resp.SetupToken != "" {
		// FR-001: enrollment happens in the web UI; the CLI stores nothing
		// and never echoes the setup token.
		return "", cmdutil.NewAuthError(errors.New(
			"your account has no two-factor authenticator enrolled yet; " +
				"finish enrollment in the veyport web interface (Settings → Two-Factor Authentication), " +
				"then run vey login again"))
	}
	if resp.TOTPToken == "" {
		return "", cmdutil.NewCodedError(cmdutil.ExitError,
			errors.New("hub returned an unrecognized login response: neither a one-time-code challenge nor an enrollment redirect"))
	}
	return resp.TOTPToken, nil
}

// redactionMarker replaces a secret that turned up in an error message.
const redactionMarker = "[redacted]"

// minRedactableSecret is the shortest secret worth substring-matching. Below
// it, matching would garble unrelated words in a hub message far more often
// than it would remove a real leak.
const minRedactableSecret = 4

// scrubSecret removes verbatim occurrences of secret from err's message.
//
// The CLI never puts a password or a one-time code into an error itself; this
// guards the one channel it does not control — the hub's {"error": "..."}
// text, which is surfaced to the user. The wrapped error is kept in the chain
// so errors.Is/As and the exit code assigned by the api client survive
// unchanged.
func scrubSecret(err error, secret string) error {
	if err == nil || len(secret) < minRedactableSecret {
		return err
	}
	msg := err.Error()
	scrubbed := strings.ReplaceAll(msg, secret, redactionMarker)
	if scrubbed == msg {
		return err
	}
	return &scrubbedError{msg: scrubbed, err: err}
}

// scrubbedError presents a redacted message while keeping the original error
// reachable through Unwrap (but never through Error).
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

// terminalPrompter reads answers from a terminal: plain lines for the
// username and the one-time code, and a no-echo read for the password.
type terminalPrompter struct {
	in  *os.File
	out io.Writer
	// reader is created once so a second prompt does not lose input that the
	// first prompt's buffered read pulled in.
	reader *bufio.Reader
}

// NewTerminalPrompter returns a LoginPrompter that reads from in and writes
// its prompts to out. Prompts go to out (stderr in production) so that stdout
// stays clean for machine-readable output (FR-012).
func NewTerminalPrompter(in *os.File, out io.Writer) LoginPrompter {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stderr
	}
	return &terminalPrompter{in: in, out: out, reader: bufio.NewReader(in)}
}

func (p *terminalPrompter) Username(defaultUser string) (string, error) {
	if defaultUser != "" {
		fmt.Fprintf(p.out, "Username [%s]: ", defaultUser)
	} else {
		fmt.Fprint(p.out, "Username: ")
	}
	line, err := p.readLine()
	if err != nil {
		return "", err
	}
	if line == "" {
		return defaultUser, nil
	}
	return line, nil
}

func (p *terminalPrompter) Password() (string, error) {
	fmt.Fprint(p.out, "Password: ")
	// ReadPassword bypasses the buffered reader deliberately: it must control
	// the terminal's echo mode on the file descriptor itself. On a terminal
	// this is safe because reads are line-oriented, so the buffered reader
	// never holds input past the line it returned.
	secret, err := term.ReadPassword(int(p.in.Fd()))
	fmt.Fprintln(p.out)
	if err != nil {
		// Only the failure is reported; whatever bytes were read are dropped.
		return "", fmt.Errorf("no-echo password read failed: %w", err)
	}
	return string(secret), nil
}

func (p *terminalPrompter) TOTPCode() (string, error) {
	fmt.Fprintf(p.out, "One-time code (valid for %d seconds): ", totpTTLSeconds)
	return p.readLine()
}

// readLine reads one trimmed line. A final line without a newline (EOF) is
// still returned, since that is what a piped-in answer looks like.
func (p *terminalPrompter) readLine() (string, error) {
	line, err := p.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading input: %w", err)
	}
	return strings.TrimSpace(line), nil
}
