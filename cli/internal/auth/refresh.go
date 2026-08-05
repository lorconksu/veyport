package auth

// Auth-mode resolution and transparent refresh-token rotation
// (data-model.md "AuthContext", research.md R3, contracts/rest-api.md
// POST /api/auth/refresh).
//
// Two invariants drive the shape of this file:
//
//   - Access tokens are never persisted (data-model.md "Not persisted"). They
//     live in the AuthContext for the length of one process, which is why a
//     session-mode invocation always begins with a refresh: there is no
//     stored access token to start from.
//   - The hub's refresh rotation is single-use. Read stored token → POST
//     /api/auth/refresh → persist the rotated pair must therefore be one
//     serialized, crash-safe step; a loser that persisted a hub-invalidated
//     token over a live one would lock the user out (spec edge case 1).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/config"
)

// refreshPath is the hub's rotation endpoint. The refresh token travels in
// the JSON body (the no-cookie fallback path), never in a header or a URL,
// so it cannot land in a proxy access log.
const refreshPath = "/api/auth/refresh"

// Mode is the credential mode resolved for one invocation
// (data-model.md AuthContext.mode).
type Mode string

const (
	// ModeAPIToken means an `adt_` API token from VEYPORT_TOKEN or the hub
	// profile is in use: non-interactive, non-refreshable.
	ModeAPIToken Mode = "api_token"
	// ModeSession means an interactive session's refresh token is stored
	// for this hub; access tokens are minted from it on demand.
	ModeSession Mode = "session"
	// ModeNone means no credential is available for this hub. It is a
	// normal state, not an error: commands that need auth turn it into
	// exit 3 with re-login guidance, and `vey status` just reports it.
	ModeNone Mode = "none"
)

// AuthContext is the resolved credential state for one invocation: which
// credential to send, and (in session mode) how to renew it.
//
// The zero value is not usable; build one with Resolve. An AuthContext is
// safe for concurrent use — the mutex guards the in-memory access token and
// the identity fields a refresh may re-confirm.
type AuthContext struct {
	mode      Mode
	hubURL    string
	configDir string
	store     Store

	// apiToken is the bearer for ModeAPIToken. Empty in every other mode.
	apiToken string

	mu sync.Mutex
	// access is the current access token: in memory only, never written to
	// the store.
	access   string
	username string
	role     string
}

// Resolve determines the auth mode for hubURL, per the precedence in
// data-model.md and R6: an API token (env `VEYPORT_TOKEN` first, then the
// hub's `api_token` profile entry) beats a stored session, which beats
// nothing at all.
//
// hubURL must already be normalized (config.NormalizeHubURL): it is the
// identity used for both the config lookup and the credential lookup, so a
// token configured for hub B can never be selected for hub A (FR-005).
//
// A missing credential yields ModeNone with a nil error — callers decide
// whether that is fatal. Only a malformed request (empty hub URL) or a store
// that fails to answer produces an error here.
func Resolve(hubURL string, envToken string, cfg config.Config, store Store, configDir string) (*AuthContext, error) {
	if strings.TrimSpace(hubURL) == "" {
		return nil, errors.New("auth: hub URL is empty")
	}

	a := &AuthContext{
		hubURL:    hubURL,
		configDir: configDir,
		store:     store,
	}

	// API-token sourcing and `adt_` validation live in context.go; a
	// malformed token fails here, locally, before anything reaches the hub.
	if token, src, ok := sourceAPIToken(hubURL, envToken, cfg); ok {
		if err := validateAPIToken(token, src); err != nil {
			return nil, err
		}
		a.mode, a.apiToken = ModeAPIToken, token
		return a, nil
	}

	if store != nil {
		sess, ok, err := store.Load(hubURL)
		if err != nil {
			return nil, err
		}
		if ok && strings.TrimSpace(sess.RefreshToken) != "" {
			a.mode = ModeSession
			a.username, a.role = sess.Username, sess.Role
			return a, nil
		}
	}

	a.mode = ModeNone
	return a, nil
}

// Mode reports the resolved credential mode.
func (a *AuthContext) Mode() Mode { return a.mode }

// Username returns the stored account name, which exists only in session
// mode (an API token carries no locally known identity — the hub is
// authoritative, via GET /api/auth/me).
func (a *AuthContext) Username() string {
	if a.mode != ModeSession {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.username
}

// Role returns the stored role. Display only, and session mode only; the
// server remains authoritative for authorization decisions.
func (a *AuthContext) Role() string {
	if a.mode != ModeSession {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.role
}

// Client returns an api.Client carrying the right bearer for this mode.
//
// In session mode the first call performs a refresh: access tokens are never
// persisted, so a fresh process has nothing to send until it exchanges the
// stored refresh token. In ModeNone it returns an exit-3 error telling the
// user to log in.
func (a *AuthContext) Client(ctx context.Context) (*api.Client, error) {
	switch a.mode {
	case ModeAPIToken:
		return api.NewClient(a.hubURL, a.apiToken), nil

	case ModeSession:
		token := a.accessToken()
		if token == "" {
			if err := a.refresh(ctx); err != nil {
				return nil, err
			}
			token = a.accessToken()
		}
		return api.NewClient(a.hubURL, token), nil

	default:
		return nil, a.errNotAuthenticated()
	}
}

// Do runs op with an authenticated client, retrying exactly once after a
// transparent refresh if op comes back 401 in session mode
// (contracts/rest-api.md: "exactly one transparent refresh attempt, then
// exit 3").
//
// Only 401 triggers the retry: 403/404/429 and connectivity failures are
// surfaced unchanged, so the CLI never retries into a rate limiter. In
// api_token mode nothing can be refreshed, so a 401 propagates immediately.
//
// op must be idempotent-safe to run twice; every caller in this CLI is a
// single request, so the retry replays exactly one HTTP round trip.
func (a *AuthContext) Do(ctx context.Context, op func(c *api.Client) error) error {
	if op == nil {
		return cmdutil.NewCodedError(cmdutil.ExitError, errors.New("auth: no operation supplied"))
	}

	client, err := a.Client(ctx)
	if err != nil {
		return err
	}

	err = op(client)
	if err == nil {
		return nil
	}
	if a.mode != ModeSession || cmdutil.Code(err) != cmdutil.ExitAuth {
		return err
	}

	// The access token aged out mid-invocation: renew once and replay.
	if refreshErr := a.refresh(ctx); refreshErr != nil {
		return refreshErr
	}
	client, err = a.Client(ctx)
	if err != nil {
		return err
	}
	// Whatever this returns is final — a second 401 means the credential is
	// genuinely rejected, and it carries exit 3 already.
	return op(client)
}

// refresh exchanges the stored refresh token for a rotated pair and persists
// it, holding the cross-process refresh lock for the whole critical section
// (R3).
//
// The sequence is deliberate:
//
//	lock → load (re-read *inside* the lock, so a racer's write is seen) →
//	POST → persist rotated pair → adopt the new access token → unlock
//
// Persisting before the token is used means a crash between the two leaves a
// usable session on disk rather than a token only the dead process knew.
//
// On a 401 the stored token is re-read once: if it differs from the one just
// rejected, another process rotated it while this one was blocked, and its
// newer token is retried transparently (RaceLost → Active). If nothing newer
// exists, the session is genuinely dead (RaceLost → NoSession, exit 3).
func (a *AuthContext) refresh(ctx context.Context) error {
	if a.store == nil {
		return a.errNotAuthenticated()
	}

	unlock, err := LockRefresh(a.configDir)
	if err != nil {
		return cmdutil.NewCodedError(cmdutil.ExitError, err)
	}
	defer unlock()

	sess, ok, err := a.store.Load(a.hubURL)
	if err != nil {
		return cmdutil.NewCodedError(cmdutil.ExitError, err)
	}
	if !ok || strings.TrimSpace(sess.RefreshToken) == "" {
		return a.errNotAuthenticated()
	}

	pair, err := a.postRefresh(ctx, sess.RefreshToken)
	if err != nil {
		if cmdutil.Code(err) != cmdutil.ExitAuth {
			// Connectivity, rate limiting, hub error: not a race, and not
			// something re-login would fix.
			return err
		}

		newer, ok, loadErr := a.store.Load(a.hubURL)
		if loadErr != nil {
			return cmdutil.NewCodedError(cmdutil.ExitError, loadErr)
		}
		if !ok || strings.TrimSpace(newer.RefreshToken) == "" || newer.RefreshToken == sess.RefreshToken {
			return a.errSessionExpired()
		}

		sess = newer
		pair, err = a.postRefresh(ctx, sess.RefreshToken)
		if err != nil {
			if cmdutil.Code(err) == cmdutil.ExitAuth {
				return a.errSessionExpired()
			}
			return err
		}
	}

	if strings.TrimSpace(pair.AccessToken) == "" || strings.TrimSpace(pair.RefreshToken) == "" {
		// Never adopt a half-populated pair: persisting an empty refresh
		// token would silently destroy the session.
		return cmdutil.NewCodedError(cmdutil.ExitError,
			fmt.Errorf("auth: hub %s returned an incomplete token pair on refresh", a.hubURL))
	}

	rotated := StoredSession{
		RefreshToken: pair.RefreshToken,
		// The refresh endpoint returns no user object, so identity carries
		// over from the entry that was just spent.
		Username:   sess.Username,
		Role:       sess.Role,
		ObtainedAt: time.Now().UTC(),
	}
	if pair.User.Username != "" {
		rotated.Username, rotated.Role = pair.User.Username, pair.User.Role
	}

	// Persist first: the rotated refresh token must be durable before the
	// access token it came with is used for anything.
	if err := a.store.Save(a.hubURL, rotated); err != nil {
		return cmdutil.NewCodedError(cmdutil.ExitError, err)
	}

	a.mu.Lock()
	a.access = pair.AccessToken
	a.username, a.role = rotated.Username, rotated.Role
	a.mu.Unlock()
	return nil
}

// postRefresh performs the rotation round trip. The client is built without
// a bearer on purpose: the refresh token authenticates the request through
// the JSON body, and sending an expired access token alongside it would only
// invite the hub to reject the request on the header.
func (a *AuthContext) postRefresh(ctx context.Context, refreshToken string) (api.TokenPair, error) {
	client := api.NewClient(a.hubURL, "")
	var pair api.TokenPair
	if err := client.Post(ctx, refreshPath, refreshRequest{RefreshToken: refreshToken}, &pair); err != nil {
		return api.TokenPair{}, err
	}
	return pair, nil
}

// refreshRequest is the body of POST /api/auth/refresh.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (a *AuthContext) accessToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.access
}

// errNotAuthenticated and errSessionExpired are the two exit-3 outcomes.
// Neither ever formats token material — only the hub URL, which is what the
// remediation command needs.
func (a *AuthContext) errNotAuthenticated() error {
	return cmdutil.NewAuthError(fmt.Errorf(
		"not authenticated for %s; run: vey login --hub %s", a.hubURL, a.hubURL))
}

func (a *AuthContext) errSessionExpired() error {
	return cmdutil.NewAuthError(fmt.Errorf(
		"session for %s has expired or was revoked; run: vey login --hub %s", a.hubURL, a.hubURL))
}
