// Command vey is the veyport CLI connector.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/commands"
	"github.com/wyiu/veyport/cli/internal/config"
)

// version is stamped at build time via:
//
//	-ldflags "-X main.version=$(VERSION)"
var version = "dev"

// usage documents the command surface from
// specs/004-cli-connector/contracts/cli-commands.md. Global flags precede
// the subcommand name; each subcommand's own flags follow it (e.g.
// `vey servers list --status x`) — vey does not accept global flags after
// the subcommand.
const usage = `usage: vey [global flags] <command> [command flags]

vey is the veyport CLI connector.

Global flags:
  --hub string   hub base URL (overrides VEYPORT_HUB and the config file)
  --json         emit machine-readable JSON output
  --help         print this usage and exit
  --version, -v  print the vey version and exit

Commands:
  login          sign in to a hub interactively
  logout         sign out and remove stored credentials for the hub
  status         show the effective hub, auth mode, and reachability
  servers list   list servers on the hub
  servers get    show one server's details
  files ls       list a path on a remote server
  files cat      print a remote file to stdout
  logs tail      stream a remote log file
  audit export   stream the audit log export
`

func main() {
	os.Exit(run(os.Args[1:]))
}

// run parses global flags, resolves config, dispatches to the subcommand
// registry (cli/internal/commands), and returns the process exit code.
//
// Global flags are parsed with a flag.FlagSet, which stops at the first
// non-flag argument (the subcommand name) per the stdlib's usual behavior —
// this is what enforces "global flags before the subcommand, subcommand
// flags after" without any custom lookahead. Output is hand-rolled (R1,
// hub/cmd/veyport/admin.go's dispatch style) rather than delegated to the
// flag package's default usage/error printing, so vey controls exit codes
// and message shape precisely.
func run(args []string) int {
	fs := flag.NewFlagSet("vey", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // usage and errors are printed by hand below

	hubFlag := fs.String("hub", "", "hub base URL (overrides VEYPORT_HUB and the config file)")
	jsonFlag := fs.Bool("json", false, "emit machine-readable JSON output")
	helpFlag := fs.Bool("help", false, "print usage and exit")
	versionFlag := fs.Bool("version", false, "print the vey version and exit")
	fs.BoolVar(versionFlag, "v", false, "print the vey version and exit")

	if err := fs.Parse(args); err != nil {
		fmt.Fprint(os.Stderr, usage)
		return cmdutil.ExitUsage
	}

	if *versionFlag {
		fmt.Printf("vey %s\n", version)
		return cmdutil.ExitOK
	}

	if *helpFlag {
		fmt.Fprint(os.Stdout, usage)
		return cmdutil.ExitOK
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return cmdutil.ExitUsage
	}

	name, cmdArgs := rest[0], rest[1:]
	fn, ok := commands.Registry[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n", name)
		fmt.Fprint(os.Stderr, usage)
		return cmdutil.ExitUsage
	}

	printer := cmdutil.NewPrinter(os.Stdout, os.Stderr, *jsonFlag)

	configPath, err := config.DefaultPath()
	if err != nil {
		printer.Error(err)
		return cmdutil.Code(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		printer.Error(err)
		return cmdutil.Code(err)
	}

	ctx := commands.NewContext(*hubFlag, os.Getenv("VEYPORT_HUB"), cfg, filepath.Dir(configPath), printer, cmdArgs)
	return fn(ctx)
}
