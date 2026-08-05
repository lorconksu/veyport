package commands

import (
	"errors"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// RunStatus implements `vey status` (contracts/cli-commands.md `vey
// status`): effective hub, auth mode, reachability, and credential-storage
// backend. Stub — replaced by T014.
func RunStatus(ctx *Context) int {
	err := errors.New("vey status: not implemented")
	ctx.Printer.Error(err)
	return cmdutil.Code(err)
}
