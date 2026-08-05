package auth

// Tests for API-token mode (spec 004-cli-connector US2): credential sourcing
// and precedence (env `VEYPORT_TOKEN` > config `api_token` > stored session >
// none, per research.md R6 and data-model.md "AuthContext"), `adt_` prefix
// validation before any hub round trip (data-model.md "Validation rules
// summary"), and the exit-code distinction between an authentication failure
// and a permission denial (US2-4, contracts/cli-commands.md exit codes).
//
// The shared harness — stubHub, refreshFixture, listServers, assertCounts,
// assertNoTokenLeak — lives in refresh_test.go; only what api-token mode adds
// is defined here.
//
// Secret hygiene mirrors refresh_test.go: every API token minted here embeds
// apiTokenSecret, and no assertion ever prints a token value, so a failing
// test cannot dump credential material into CI logs.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/config"
)

// apiTokenSecret is embedded in every API token these tests use, so a leak
// assertion cannot pass by accident. It is distinct from refresh_test.go's
// refreshSecret to keep the two credential classes separable in a failure.
const apiTokenSecret = "SECRET-API-TOKEN-MUST-NOT-LEAK-9f3e2d"

func apiToken(label string) string { return "adt_" + label + "-" + apiTokenSecret }

// assertNoAPITokenLeak fails if err quotes API-token material. The `adt_`
// prefix itself is not material (contracts/cli-commands.md: `vey status`
// prints the prefix deliberately); the body is.
func assertNoAPITokenLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), apiTokenSecret) {
		t.Error("error message leaked API token material")
	}
}

// bearerOf resolves the client for ac and returns the bearer it carries.
// Only safe to call in api_token mode, where building a client performs no
// network I/O.
func bearerOf(t *testing.T, ac *AuthContext) string {
	t.Helper()
	c, err := ac.Client(context.Background())
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	return c.Token
}

// --- precedence (US2-3, R6) --------------------------------------------------

// TestResolveAPITokenPrecedenceMatrix walks the full env/config/session
// matrix. The rule under test is "explicit configuration beats stored state"
// (US2-3): an API token in the environment or the hub's config profile wins
// over a perfectly good stored session, and hub B's configured token never
// applies to hub A (FR-005).
func TestResolveAPITokenPrecedenceMatrix(t *testing.T) {
	envTok := apiToken("env")
	cfgTok := apiToken("config")
	otherTok := apiToken("otherhub")

	cases := []struct {
		name string
		// env is the VEYPORT_TOKEN value handed to Resolve.
		env string
		// cfgToken is the api_token configured for the fixture's own hub.
		cfgToken string
		// otherHubToken is an api_token configured for a *different* hub.
		otherHubToken string
		seedSession   bool
		wantMode      Mode
		// wantBearer is checked in api_token mode only.
		wantBearer string
	}{
		{
			name:       "env token alone",
			env:        envTok,
			wantMode:   ModeAPIToken,
			wantBearer: envTok,
		},
		{
			name:        "env token beats config token and stored session",
			env:         envTok,
			cfgToken:    cfgTok,
			seedSession: true,
			wantMode:    ModeAPIToken,
			wantBearer:  envTok,
		},
		{
			name:        "config token beats stored session when env is empty",
			cfgToken:    cfgTok,
			seedSession: true,
			wantMode:    ModeAPIToken,
			wantBearer:  cfgTok,
		},
		{
			name:        "whitespace-only env token falls through to config",
			env:         "   \t ",
			cfgToken:    cfgTok,
			seedSession: true,
			wantMode:    ModeAPIToken,
			wantBearer:  cfgTok,
		},
		{
			name:        "whitespace-only config token falls through to session",
			cfgToken:    "  ",
			seedSession: true,
			wantMode:    ModeSession,
		},
		{
			name:        "stored session alone",
			seedSession: true,
			wantMode:    ModeSession,
		},
		{
			name:          "another hub's configured token never applies",
			otherHubToken: otherTok,
			seedSession:   true,
			wantMode:      ModeSession,
		},
		{
			name:          "another hub's configured token is not a credential here",
			otherHubToken: otherTok,
			wantMode:      ModeNone,
		},
		{
			name:     "no credential anywhere",
			wantMode: ModeNone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshFixture(t)
			if tc.seedSession {
				f.seedSession(t)
			}

			hubs := map[string]config.HubProfile{}
			if tc.cfgToken != "" {
				hubs[f.hub.url()] = config.HubProfile{APIToken: tc.cfgToken}
			}
			if tc.otherHubToken != "" {
				hubs["https://other.example.com"] = config.HubProfile{APIToken: tc.otherHubToken}
			}

			ac := f.resolve(t, tc.env, config.Config{Hubs: hubs}, nil)
			if got := ac.Mode(); got != tc.wantMode {
				t.Fatalf("Mode() = %q, want %q", got, tc.wantMode)
			}

			if tc.wantMode == ModeAPIToken {
				if got := bearerOf(t, ac); got != tc.wantBearer {
					t.Error("client bearer is not the expected API token source")
				}
				// An API token carries no locally known identity; the hub is
				// authoritative (GET /api/auth/me).
				if ac.Username() != "" || ac.Role() != "" {
					t.Errorf("api_token mode exposed identity: username %q role %q", ac.Username(), ac.Role())
				}
			}

			// Resolution — and client construction in api_token mode — must
			// never touch the hub.
			assertCounts(t, f.hub, 0, 0)
		})
	}
}

// --- `adt_` prefix validation ------------------------------------------------

// TestResolveRejectsMalformedAPIToken pins data-model.md's validation rule:
// "`adt_` prefix check before sending an API token; malformed → usage error,
// not a hub round-trip". Exit 2 (usage), zero network calls.
//
// A stored session is seeded in every case on purpose: a malformed *explicit*
// credential must be reported, never silently downgraded to whatever session
// happens to be on disk — a silent fallback would run the command as a
// different identity than the operator asked for.
func TestResolveRejectsMalformedAPIToken(t *testing.T) {
	cases := []struct {
		name       string
		token      string
		fromConfig bool
	}{
		{name: "env token with no adt_ prefix", token: "ghp_" + apiTokenSecret},
		{name: "env token with wrong-case prefix", token: "ADT_" + apiTokenSecret},
		{name: "env token that is only the prefix", token: "adt_"},
		{name: "env token that is an access JWT", token: "eyJhbGciOiJIUzI1NiJ9." + apiTokenSecret},
		{name: "env token with a leading typo", token: "xadt_" + apiTokenSecret},
		{name: "config token with no adt_ prefix", token: "token-" + apiTokenSecret, fromConfig: true},
		{name: "config token that is only the prefix", token: "adt_", fromConfig: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshFixture(t)
			f.seedSession(t)

			env := tc.token
			cfg := config.Config{}
			if tc.fromConfig {
				env = ""
				cfg.Hubs = map[string]config.HubProfile{
					f.hub.url(): {APIToken: tc.token},
				}
			}

			ac, err := Resolve(f.hub.url(), env, cfg, f.store, f.dir)
			if err == nil {
				t.Fatalf("Resolve accepted a malformed API token, want a usage error (mode = %q)", ac.Mode())
			}
			assertNoAPITokenLeak(t, err)
			if code := cmdutil.Code(err); code != cmdutil.ExitUsage {
				t.Errorf("exit code = %d, want %d (usage)", code, cmdutil.ExitUsage)
			}
			if !strings.Contains(err.Error(), "adt_") {
				t.Errorf("error does not name the expected token prefix: %s", err)
			}
			// The whole point of validating locally: no hub round trip.
			assertCounts(t, f.hub, 0, 0)
		})
	}
}

// TestResolveAcceptsWellFormedAPIToken guards the other side of the
// validation: anything carrying the `adt_` prefix plus a body is accepted
// as-is. The CLI does not second-guess the hub's token format beyond the
// prefix — only the hub can decide whether a token is live.
func TestResolveAcceptsWellFormedAPIToken(t *testing.T) {
	for _, token := range []string{"adt_x", apiToken("short"), "adt_" + strings.Repeat("k", 200)} {
		f := newRefreshFixture(t)
		ac, err := Resolve(f.hub.url(), token, config.Config{}, f.store, f.dir)
		if err != nil {
			assertNoAPITokenLeak(t, err)
			t.Fatalf("Resolve rejected a well-formed API token: %v", err)
		}
		if got := ac.Mode(); got != ModeAPIToken {
			t.Errorf("Mode() = %q, want %q", got, ModeAPIToken)
		}
		if got := bearerOf(t, ac); got != token {
			t.Error("client bearer is not the supplied API token")
		}
		assertCounts(t, f.hub, 0, 0)
	}
}

// --- revoked token (US2-2) ---------------------------------------------------

// TestAPITokenModeRevokedConfigTokenExitsAuthWithoutRefresh covers US2-2 for
// the config-file sourcing path: a well-formed but revoked token gets a 401,
// and because nothing in api_token mode is refreshable
// (contracts/rest-api.md: "401 in api_token mode: no refresh possible → exit
// 3 immediately") the CLI must not attempt a refresh — not even though a
// usable stored session sits right next to it.
func TestAPITokenModeRevokedConfigTokenExitsAuthWithoutRefresh(t *testing.T) {
	f := newRefreshFixture(t)
	f.seedSession(t)
	f.hub.protectedPolicy = func(*stubHub, string, int) int { return http.StatusUnauthorized }

	cfg := config.Config{Hubs: map[string]config.HubProfile{
		f.hub.url(): {APIToken: apiToken("revoked")},
	}}
	ac := f.resolve(t, "", cfg, nil)
	if ac.Mode() != ModeAPIToken {
		t.Fatalf("Mode() = %q, want %q", ac.Mode(), ModeAPIToken)
	}

	ctx := context.Background()
	err := ac.Do(ctx, listServers(ctx))
	if err == nil {
		t.Fatal("Do succeeded with a revoked API token")
	}
	assertNoAPITokenLeak(t, err)
	assertNoTokenLeak(t, err)
	if code := cmdutil.Code(err); code != cmdutil.ExitAuth {
		t.Errorf("exit code = %d, want %d", code, cmdutil.ExitAuth)
	}
	// One protected call, zero refreshes: the rejection is final.
	assertCounts(t, f.hub, 0, 1)
	// And the stored session was neither spent nor rotated.
	if got := f.storedGen(t); got != 1 {
		t.Errorf("api_token mode touched the stored session: generation = %d, want 1", got)
	}
}

// --- 401 vs 403 (US2-4) ------------------------------------------------------

// TestAuthFailureAndPermissionDenialMapDistinctly covers US2-4: "the CLI
// surfaces the permission error distinctly from an authentication failure".
// 401 → exit 3 (re-authenticate), 403 → exit 4 (valid credential, wrong
// role), in both credential modes, and a 403 never triggers a refresh in
// either — refreshing a credential the hub already accepted cannot change the
// answer, and retrying a denial is pure noise.
func TestAuthFailureAndPermissionDenialMapDistinctly(t *testing.T) {
	run := func(t *testing.T, mode Mode, status int) (int, error) {
		t.Helper()
		f := newRefreshFixture(t)
		f.seedSession(t)
		f.hub.protectedPolicy = func(*stubHub, string, int) int { return status }

		env := ""
		if mode == ModeAPIToken {
			env = apiToken("live")
		}
		ac := f.resolve(t, env, config.Config{}, nil)
		if got := ac.Mode(); got != mode {
			t.Fatalf("Mode() = %q, want %q", got, mode)
		}

		ctx := context.Background()
		err := ac.Do(ctx, listServers(ctx))
		if err == nil {
			t.Fatalf("Do succeeded against a %d route", status)
		}
		assertNoAPITokenLeak(t, err)
		assertNoTokenLeak(t, err)

		refresh, protected := f.hub.counts()
		switch {
		case mode == ModeAPIToken:
			// Nothing is refreshable, so neither status may produce one.
			assertCounts(t, f.hub, 0, 1)
		case status == http.StatusForbidden:
			// One refresh to mint the initial access token (access tokens are
			// never persisted), then a single protected call: no retry.
			assertCounts(t, f.hub, 1, 1)
		default:
			// 401 in session mode is the one case that earns a retry.
			if refresh != 2 || protected != 2 {
				t.Errorf("401 in session mode: refresh=%d protected=%d, want 2 and 2", refresh, protected)
			}
		}
		return cmdutil.Code(err), err
	}

	var apiAuthCode, apiForbiddenCode int

	t.Run("api token 401 is an authentication failure", func(t *testing.T) {
		code, _ := run(t, ModeAPIToken, http.StatusUnauthorized)
		apiAuthCode = code
		if code != cmdutil.ExitAuth {
			t.Errorf("exit code = %d, want %d", code, cmdutil.ExitAuth)
		}
	})

	t.Run("api token 403 is a permission denial", func(t *testing.T) {
		code, _ := run(t, ModeAPIToken, http.StatusForbidden)
		apiForbiddenCode = code
		if code != cmdutil.ExitForbidden {
			t.Errorf("exit code = %d, want %d", code, cmdutil.ExitForbidden)
		}
	})

	t.Run("the two are not conflated", func(t *testing.T) {
		if apiAuthCode == apiForbiddenCode {
			t.Errorf("401 and 403 both mapped to exit %d; they must be distinguishable by scripts", apiAuthCode)
		}
	})

	t.Run("session 403 is a permission denial with no refresh retry", func(t *testing.T) {
		code, _ := run(t, ModeSession, http.StatusForbidden)
		if code != cmdutil.ExitForbidden {
			t.Errorf("exit code = %d, want %d", code, cmdutil.ExitForbidden)
		}
	})

	t.Run("session 401 remains an authentication failure", func(t *testing.T) {
		code, _ := run(t, ModeSession, http.StatusUnauthorized)
		if code != cmdutil.ExitAuth {
			t.Errorf("exit code = %d, want %d", code, cmdutil.ExitAuth)
		}
	})
}
