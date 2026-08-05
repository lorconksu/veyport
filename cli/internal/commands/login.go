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

// loginPayload is the --json shape for a successful `vey login`.
type loginPayload struct {
	Hub      string `json:"hub"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// RunLogin implements `vey login` (contracts/cli-commands.md `vey login`):
// the interactive three-leg sign-in flow, delegating credential collection,
// TOTP handling, and persistence to auth.Login. Non-TTY fast-fail (exit 3
// with API-token guidance) is handled inside auth.Login itself.
func RunLogin(ctx *Context) int {
	hubURL, err := ctx.RequireHub()
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	// auth.Login's very first check — before it ever touches Client or Store
	// — is whether stdin is a TTY (no Prompter is supplied here, so it uses
	// its own terminal check). When stdin is not a TTY that check alone
	// decides the outcome, so opening the credential store first is pure
	// overhead the non-interactive path shouldn't pay: it can do disk I/O,
	// probe for a keyring, and print a one-time fallback warning to stderr
	// ahead of (and unrelated to) the exit-3 guidance the command is about
	// to emit (contracts/cli-commands.md "no command ever prompts when
	// stdin is not a TTY"; SC-004). Deferring store/client construction
	// until stdin is confirmed interactive keeps that non-interactive exit
	// side-effect-free and its stderr output limited to the one JSON error.
	var store auth.Store
	var client *api.Client
	if cmdutil.IsTTY(os.Stdin) {
		store, err = auth.NewStore(ctx.ConfigDir, ctx.Printer.Err)
		if err != nil {
			wrapped := fmt.Errorf("opening credential store: %w", err)
			ctx.Printer.Error(wrapped)
			return cmdutil.Code(wrapped)
		}
		client = api.NewClient(hubURL, "")
	}

	pair, err := auth.Login(context.Background(), auth.LoginOptions{
		Client: client,
		HubURL: hubURL,
		Store:  store,
		Stdin:  os.Stdin,
	})
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	payload := loginPayload{Hub: hubURL, Username: pair.User.Username, Role: pair.User.Role}
	_ = ctx.Printer.Payload(payload, func(w io.Writer, v any) error {
		p := v.(loginPayload)
		_, err := fmt.Fprintf(w, "Signed in to %s as %s (%s)\n", p.Hub, p.Username, p.Role)
		return err
	})
	return cmdutil.ExitOK
}
