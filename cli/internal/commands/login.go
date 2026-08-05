package commands

import (
	"errors"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// RunLogin implements `vey login` (contracts/cli-commands.md `vey login`):
// the interactive three-leg sign-in flow. Stub — replaced by T012–T014.
func RunLogin(ctx *Context) int {
	err := errors.New("vey login: not implemented")
	ctx.Printer.Error(err)
	return cmdutil.Code(err)
}
