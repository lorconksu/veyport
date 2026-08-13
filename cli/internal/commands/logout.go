package commands

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// logoutPayload is the --json shape for a successful `vey logout`.
type logoutPayload struct {
	Hub    string `json:"hub"`
	Status string `json:"status"`
}

// RunLogout implements `vey logout` (contracts/cli-commands.md `vey
// logout`): best-effort server-side invalidation via POST /api/auth/logout
// (session mode only), then unconditional local credential removal.
// FR-006: invalidates the session at the hub and removes all locally
// stored credentials for that hub.
func RunLogout(ctx *Context) int {
	if err := requireNoArgs("logout", ctx.Args); err != nil {
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

	switch actx.Mode() {
	case auth.ModeAPIToken:
		nothing := cmdutil.NewAuthError(errors.New(
			"nothing to log out: the active credential is an API token from VEYPORT_TOKEN or the config file, not a stored session — unset it there to sign out"))
		ctx.Printer.Error(nothing)
		return cmdutil.Code(nothing)

	case auth.ModeSession:
		bg := context.Background()
		if callErr := actx.Do(bg, func(c *api.Client) error {
			return c.Post(bg, "/api/auth/logout", nil, nil)
		}); callErr != nil {
			ctx.Printer.Errorf("warning: could not invalidate session at %s: %v\n", hubURL, callErr)
		}

		if delErr := store.Delete(hubURL); delErr != nil {
			ctx.Printer.Error(delErr)
			return cmdutil.Code(delErr)
		}

		_ = ctx.Printer.Payload(logoutPayload{Hub: hubURL, Status: "signed_out"}, func(w io.Writer, v any) error {
			p := v.(logoutPayload)
			_, err := fmt.Fprintf(w, "Signed out of %s\n", p.Hub)
			return err
		})
		return cmdutil.ExitOK

	default: // auth.ModeNone
		nothing := cmdutil.NewAuthError(fmt.Errorf("nothing to log out: no stored session for %s", hubURL))
		ctx.Printer.Error(nothing)
		return cmdutil.Code(nothing)
	}
}
