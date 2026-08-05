// Command vey is the veyport CLI connector.
package main

import (
	"fmt"
	"os"
)

// version is stamped at build time via:
//
//	-ldflags "-X main.version=$(VERSION)"
var version = "dev"

const usage = `usage: vey <command> [flags]

vey is the veyport CLI connector.

Global flags:
  --version, -v   print the vey version and exit

Commands:
  (none yet)
`

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches the top-level command and returns the process exit code.
// It currently only understands --version/-v; command dispatch (login,
// servers, files, logs, audit, ...) is added here in a later task.
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	switch args[0] {
	case "--version", "-v":
		fmt.Printf("vey %s\n", version)
		return 0
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
}
