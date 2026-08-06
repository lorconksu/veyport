package commands

import (
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/config"
)

// Context is the shared invocation context every subcommand receives: the
// resolved global flags (--json), output discipline (Printer), the parsed
// config file, and the subcommand's own argv. Hub resolution is
// deliberately NOT done here — see RequireHub — because not every command
// needs a hub (e.g. bare `vey --help`), and ErrNoHub shouldn't surface for
// commands that never touch it.
type Context struct {
	// HubURL is the effective, normalized hub base URL. Empty until
	// RequireHub has resolved it successfully.
	HubURL string
	// HubSource records which input supplied HubURL: "flag", "env", or
	// "config" (config.EffectiveHub). Empty until RequireHub has resolved
	// it successfully.
	HubSource string

	// JSON reports whether --json was passed on the command line. Mirrors
	// Printer.JSON; kept as its own field because commands consult it
	// directly (e.g. to pick a response envelope) without reaching into
	// Printer.
	JSON bool
	// Printer centralizes stdout/stderr output discipline (see
	// cmdutil.Printer): stdout carries payload only, stderr carries
	// diagnostics and errors.
	Printer *cmdutil.Printer

	// ConfigDir is the directory containing vey's config file
	// (filepath.Dir of config.DefaultPath()), for commands that need to
	// locate sibling files (credential store, lock file).
	ConfigDir string
	// Config is the parsed contents of the config file (zero value if the
	// file doesn't exist yet — see config.Load).
	Config config.Config

	// Args is the subcommand's own argv: os.Args with the program name,
	// global flags, and the subcommand name already stripped. Each command
	// parses its own flags from this slice (contracts/cli-commands.md
	// "Global behavior": global flags precede the subcommand, subcommand
	// flags follow it — e.g. `vey servers list --status x`).
	Args []string

	// hubFlag and hubEnv are the raw, not-yet-normalized --hub flag and
	// VEYPORT_HUB env values, captured at construction and consumed lazily
	// by RequireHub.
	hubFlag string
	hubEnv  string
}

// NewContext builds the Context for one invocation. hubFlag and hubEnv are
// the raw --hub flag and VEYPORT_HUB env values; hub resolution happens
// lazily via RequireHub, not here, so commands that don't need a hub never
// pay for (or fail on) that resolution.
func NewContext(hubFlag, hubEnv string, cfg config.Config, configDir string, printer *cmdutil.Printer, args []string) *Context {
	return &Context{
		JSON:      printer.JSON,
		Printer:   printer,
		ConfigDir: configDir,
		Config:    cfg,
		Args:      args,
		hubFlag:   hubFlag,
		hubEnv:    hubEnv,
	}
}

// RequireHub lazily resolves and caches the effective hub URL — flag > env >
// config file, per contracts/cli-commands.md "Global behavior" — for the
// commands that need one (servers, files, logs, audit). login and status
// have their own hub-handling needs, wired up in later tasks. A resolution
// failure (config.ErrNoHub) is mapped to exit code 2, carrying ErrNoHub's
// built-in remediation guidance ("pass --hub, set VEYPORT_HUB, or set
// default_hub in the config file").
func (c *Context) RequireHub() (string, error) {
	if c.HubURL != "" {
		return c.HubURL, nil
	}
	hubURL, source, err := config.EffectiveHub(c.hubFlag, c.hubEnv, c.Config)
	if err != nil {
		return "", cmdutil.NewUsageError(err)
	}
	c.HubURL, c.HubSource = hubURL, source
	return c.HubURL, nil
}

// Registry maps each subcommand name to its entry point. cmd/vey/main.go
// dispatches by looking up args[0] here once global flags have been
// stripped; the map's keys are the exhaustive command list
// (contracts/cli-commands.md "Commands"). Each entry is a stub today, living
// in the file named for the task that will replace it with the real
// implementation.
var Registry = map[string]func(ctx *Context) int{
	"login":    RunLogin,
	"logout":   RunLogout,
	"status":   RunStatus,
	"servers":  RunServers,
	"files":    RunFiles,
	"logs":     RunLogs,
	"audit":    RunAudit,
	"ssh-cert": RunSSHCert,
}
