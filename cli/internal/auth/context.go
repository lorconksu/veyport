package auth

// API-token mode: where a token comes from, and what makes one usable
// (spec 004-cli-connector US2, research.md R6, data-model.md HubProfile
// "api_token" + "Validation rules summary").
//
// This file holds the sourcing/validation half of AuthContext resolution;
// refresh.go holds the session half (rotation, locking) and the Resolve entry
// point that composes the two. The split is deliberate: API-token mode is
// pure, local, and offline — deciding whether a token is *well formed* must
// never involve the network, while deciding whether a session is *live*
// always does.

import (
	"fmt"
	"strings"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/config"
)

// apiTokenPrefix marks a veyport API token. It is the one structural fact the
// CLI knows about token format: whether a token is live, revoked, or scoped
// for another hub is the hub's call, not ours.
const apiTokenPrefix = "adt_"

// tokenSource names where a sourced API token came from, phrased for an error
// message so a mistyped credential points at the file or variable to fix.
type tokenSource string

const (
	tokenSourceEnv    tokenSource = "the VEYPORT_TOKEN environment variable"
	tokenSourceConfig tokenSource = "the hub's api_token entry in the config file"
)

// sourceAPIToken applies the API-token half of the R6 precedence chain:
// env `VEYPORT_TOKEN` first, then the `api_token` recorded for this exact hub
// in the config file. It reports whether a token was found at all; a session,
// if any, is only consulted when this returns false.
//
// hubURL must be normalized (config.NormalizeHubURL) — it is the map key, so
// a token configured for hub B can never be selected for hub A (FR-005).
//
// Values are trimmed and empty-after-trim is treated as absent: an exported-
// but-empty `VEYPORT_TOKEN` (the common `export VEYPORT_TOKEN=` or a shell
// variable that failed to expand) means "no token here", not "an unusable
// token", and must fall through to the next source rather than fail the
// invocation.
func sourceAPIToken(hubURL, envToken string, cfg config.Config) (string, tokenSource, bool) {
	if token := strings.TrimSpace(envToken); token != "" {
		return token, tokenSourceEnv, true
	}
	// Indexing a nil map is defined and yields the zero HubProfile, so an
	// empty config needs no special case.
	if token := strings.TrimSpace(cfg.Hubs[hubURL].APIToken); token != "" {
		return token, tokenSourceConfig, true
	}
	return "", "", false
}

// validateAPIToken enforces data-model.md's rule that the `adt_` prefix is
// checked "before sending an API token; malformed → usage error, not a hub
// round-trip".
//
// Exit 2 rather than exit 3 is the point: a token that cannot possibly be a
// veyport token is an operator mistake in the environment or config file, not
// a rejected credential, and a script that sees exit 3 would go off and try to
// re-authenticate over something no amount of re-authentication can fix.
// Failing locally also keeps a foreign secret — a GitHub PAT pasted into the
// wrong variable, say — off the wire entirely.
//
// The message names the source and the expected prefix but never any part of
// the value: the token may be a valid credential for some *other* system, and
// stderr is exactly where it must not be echoed.
func validateAPIToken(token string, src tokenSource) error {
	if strings.HasPrefix(token, apiTokenPrefix) && len(token) > len(apiTokenPrefix) {
		return nil
	}
	return cmdutil.NewUsageError(fmt.Errorf(
		"malformed API token in %s: a veyport API token starts with %q followed by the token body; "+
			"correct the value, or clear it to use a stored session (vey login)",
		src, apiTokenPrefix))
}

// tokenPrefixMaxLen is the most of an API token `vey status` may ever show
// (contracts/cli-commands.md, Secrets row: "token *prefix* only").
const tokenPrefixMaxLen = 8

// TokenPrefix reports the display-safe form of the API token this
// AuthContext resolved to: a leading fragment plus an ellipsis, never the
// whole value. It answers "" in every mode but ModeAPIToken.
//
// The fragment is bounded twice — at tokenPrefixMaxLen characters, and at
// half the token's length. The second bound is what keeps the guarantee
// honest for a short token: validateAPIToken accepts anything past `adt_`,
// so a five-character token under a fixed 8-character rule would have been
// rendered in full, turning the "prefix only" contract into a disclosure of
// the entire credential (FR-017).
//
// This exists so `vey status` never re-derives the env>config precedence
// sourceAPIToken already applied when Resolve built this AuthContext —
// duplicating that chain risks it drifting from the one Resolve actually
// uses. AuthContext otherwise never exposes the raw token (R17: credentials
// must never be printed in full); this is the one sanctioned exception, and
// it only ever hands back a prefix.
func (a *AuthContext) TokenPrefix() string {
	if a.mode != ModeAPIToken {
		return ""
	}
	n := tokenPrefixMaxLen
	if half := len(a.apiToken) / 2; half < n {
		n = half
	}
	return a.apiToken[:n] + "…"
}
