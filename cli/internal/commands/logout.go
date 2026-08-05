package commands

import (
	"errors"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// RunLogout implements `vey logout` (contracts/cli-commands.md `vey
// logout`): best-effort server-side invalidation plus local credential
// removal. Stub — replaced by T014.
func RunLogout(ctx *Context) int {
	err := errors.New("vey logout: not implemented")
	ctx.Printer.Error(err)
	return cmdutil.Code(err)
}
