package commands

import (
	"errors"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// RunFiles implements `vey files ls <server> <path>` and `vey files cat
// <server> <path>` (contracts/cli-commands.md `vey files ls`, `vey files
// cat`). Stub — replaced by T021.
func RunFiles(ctx *Context) int {
	err := errors.New("vey files: not implemented")
	ctx.Printer.Error(err)
	return cmdutil.Code(err)
}
