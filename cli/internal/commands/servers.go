package commands

import (
	"errors"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// RunServers implements `vey servers list` and `vey servers get <server>`
// (contracts/cli-commands.md `vey servers list`, `vey servers get`). Stub —
// replaced by T015.
func RunServers(ctx *Context) int {
	err := errors.New("vey servers: not implemented")
	ctx.Printer.Error(err)
	return cmdutil.Code(err)
}
