package commands

import (
	"errors"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// RunAudit implements `vey audit export` (contracts/cli-commands.md `vey
// audit export`): a role-gated streaming passthrough of the hub's audit
// export. Stub — replaced by T027.
func RunAudit(ctx *Context) int {
	err := errors.New("vey audit: not implemented")
	ctx.Printer.Error(err)
	return cmdutil.Code(err)
}
