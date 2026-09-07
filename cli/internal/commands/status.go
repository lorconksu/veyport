package commands

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// newAuthContext builds the credential store for ctx.ConfigDir and resolves
// the AuthContext for hubURL (api_token > session > none, per
// data-model.md "AuthContext"). Shared by status, logout, servers, files,
// logs, and audit so precedence and storage-backend selection live in
// exactly one place.
//
// The keyring-fallback warning is suppressed here (nil warnW — auth.NewStore
// documents nil as "suppress without consuming the one-time budget"): the
// moment that warning matters is `vey login`, when credentials are first
// written and the storage choice is decided (RunLogin passes ctx.Printer.Err
// directly to its own auth.NewStore call for that reason). Every other
// command is a read of an already-decided storage backend, and `vey status`
// already reports it via the "storage" field, so repeating the warning on
// every invocation on a headless machine would just be noise.
func newAuthContext(ctx *Context, hubURL string) (auth.Store, *auth.AuthContext, error) {
	store, err := auth.NewStore(ctx.ConfigDir, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("opening credential store: %w", err)
	}
	actx, err := auth.Resolve(hubURL, os.Getenv("VEYPORT_TOKEN"), ctx.Config, store, ctx.ConfigDir)
	if err != nil {
		return store, nil, err
	}
	return store, actx, nil
}

// statusPayload is the --json shape for `vey status`
// (contracts/cli-commands.md `vey status`:
// "{hub, hub_source, mode, username, role, reachable, storage}"), extended
// by 009 with the calling session's expiry fields (contracts/ui-cli.md:
// "vey status | ... prints Session expires: <RFC3339> and Idle deadline:
// <RFC3339> (or "none"); JSON adds session_expires_at,
// session_idle_deadline_at").
type statusPayload struct {
	Hub       string `json:"hub"`
	HubSource string `json:"hub_source"`
	Mode      string `json:"mode"`
	Username  string `json:"username,omitempty"`
	Role      string `json:"role,omitempty"`
	Reachable bool   `json:"reachable"`
	Storage   string `json:"storage"`

	SessionExpiresAt      *string `json:"session_expires_at,omitempty"`
	SessionIdleDeadlineAt *string `json:"session_idle_deadline_at,omitempty"`

	// sessionInfoKnown is set only when GET /api/auth/sessions succeeded
	// and the calling session was found, so the human report can tell
	// "no limit configured" (print "none") apart from "the sessions call
	// failed" (omit the two lines entirely). Unexported: never part of
	// the --json payload.
	sessionInfoKnown bool
}

// modeString renders m using vey's own stable JSON vocabulary (api_token /
// session / none), independent of auth.Mode's internal representation.
func modeString(m auth.Mode) string {
	switch m {
	case auth.ModeAPIToken:
		return "api_token"
	case auth.ModeSession:
		return "session"
	default:
		return "none"
	}
}

// humanMode renders the auth-mode line per contracts/cli-commands.md `vey
// status`: "api token (adt_xxxx…)" / "interactive session as <user>
// (<role>)" / "not signed in".
func humanMode(p statusPayload, tokenPrefix string) string {
	switch p.Mode {
	case "api_token":
		return fmt.Sprintf("api token (%s)", tokenPrefix)
	case "session":
		return fmt.Sprintf("interactive session as %s (%s)", p.Username, p.Role)
	default:
		return "not signed in"
	}
}

// timeOrNone renders p (an RFC3339 timestamp, or nil when the corresponding
// limit is disabled) as itself, or "none" when nil.
func timeOrNone(p *string) string {
	if p == nil {
		return "none"
	}
	return *p
}

// printStatus renders p to the printer: one JSON document in --json mode,
// or a field/value human report otherwise. The session-expiry lines
// (009) are appended only when sessionInfoKnown — i.e. GET
// /api/auth/sessions succeeded and located the calling session; a failed
// sessions call omits them entirely rather than printing misleading data
// (contracts/ui-cli.md: "when the sessions call fails, status still prints
// the rest and omits the two lines").
func printStatus(ctx *Context, p statusPayload, tokenPrefix string) {
	_ = ctx.Printer.Payload(p, func(w io.Writer, v any) error {
		sp := v.(statusPayload)
		fmt.Fprintf(w, "Hub: %s (%s)\n", sp.Hub, sp.HubSource)
		fmt.Fprintf(w, "Auth: %s\n", humanMode(sp, tokenPrefix))
		fmt.Fprintf(w, "Reachable: %t\n", sp.Reachable)
		fmt.Fprintf(w, "Storage: %s\n", sp.Storage)
		if sp.sessionInfoKnown {
			fmt.Fprintf(w, "Session expires: %s\n", timeOrNone(sp.SessionExpiresAt))
			fmt.Fprintf(w, "Idle deadline: %s\n", timeOrNone(sp.SessionIdleDeadlineAt))
		}
		return nil
	})
}

// fillSessionInfo fetches GET /api/auth/sessions and, when the calling
// session is found among the results, populates payload's session-expiry
// fields and marks sessionInfoKnown (contracts/rest-api.md: "GET
// /api/auth/sessions ... current: true on the calling session"). Any
// failure — network, decode, the session simply not being in the list —
// is swallowed: session info is a nice-to-have addition to `vey status`,
// never a reason to fail or otherwise alter the command's exit code.
func fillSessionInfo(ctx context.Context, actx *auth.AuthContext, payload *statusPayload) {
	var sessions api.SessionsResponse
	err := actx.Do(ctx, func(c *api.Client) error {
		return c.Get(ctx, "/api/auth/sessions", nil, &sessions)
	})
	if err != nil {
		return
	}
	for _, s := range sessions.Sessions {
		if !s.Current {
			continue
		}
		payload.SessionExpiresAt = s.ExpiresAt
		payload.SessionIdleDeadlineAt = s.IdleDeadlineAt
		payload.sessionInfoKnown = true
		return
	}
}

// RunStatus implements `vey status` (contracts/cli-commands.md `vey
// status`): effective hub, auth mode, reachability (GET /api/auth/me
// through the resolved AuthContext), and credential-storage backend.
func RunStatus(ctx *Context) int {
	if err := requireNoArgs("status", ctx.Args); err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	hubURL, err := ctx.RequireHub()
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	store, actx, err := newAuthContext(ctx, hubURL)
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	mode := actx.Mode()
	payload := statusPayload{
		Hub:       hubURL,
		HubSource: ctx.HubSource,
		Mode:      modeString(mode),
		Username:  actx.Username(),
		Role:      actx.Role(),
		Storage:   store.Backend(),
	}

	if mode == auth.ModeNone {
		payload.Reachable = false
		printStatus(ctx, payload, "")
		return cmdutil.ExitAuth
	}

	tokenPrefix := actx.TokenPrefix()

	bg := context.Background()
	var me api.Me
	doErr := actx.Do(bg, func(c *api.Client) error {
		return c.Get(bg, "/api/auth/me", nil, &me)
	})

	if doErr == nil {
		payload.Reachable = true
		if payload.Username == "" {
			payload.Username = me.Username
		}
		if payload.Role == "" {
			payload.Role = me.Role
		}
		if mode == auth.ModeSession {
			fillSessionInfo(bg, actx, &payload)
		}
		printStatus(ctx, payload, tokenPrefix)
		return cmdutil.ExitOK
	}

	payload.Reachable = false
	printStatus(ctx, payload, tokenPrefix)
	if cmdutil.Code(doErr) == cmdutil.ExitConn {
		return cmdutil.ExitConn
	}
	return cmdutil.ExitAuth
}
