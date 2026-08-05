package commands

import (
	"errors"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// RunLogs implements `vey logs tail <server> <path> [--grep <pattern>]`
// (contracts/cli-commands.md `vey logs tail`): a live SSE follow. Stub —
// replaced by T025.
func RunLogs(ctx *Context) int {
	err := errors.New("vey logs: not implemented")
	ctx.Printer.Error(err)
	return cmdutil.Code(err)
}
