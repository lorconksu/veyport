package commands

import (
	"fmt"
	"strings"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// requireNoArgs enforces a "no arguments, no flags" command surface (login,
// logout, status), so a mistyped invocation fails as a usage error instead
// of being silently ignored. The flag-shaped case gets its own message
// because the mistake it catches in practice is a *global* flag placed after
// the subcommand (`vey login --hub <url>`), where the fix is ordering, not
// removal.
func requireNoArgs(cmd string, args []string) error {
	if len(args) == 0 {
		return nil
	}
	if strings.HasPrefix(args[0], "-") {
		return cmdutil.NewUsageError(fmt.Errorf(
			"vey %s takes no flags; global flags go before the subcommand: vey %s %s",
			cmd, strings.Join(args, " "), cmd))
	}
	return cmdutil.NewUsageError(fmt.Errorf("usage: vey %s (takes no arguments)", cmd))
}
