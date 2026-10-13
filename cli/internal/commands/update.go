package commands

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/update"
)

const updateUsage = `usage: vey [--hub https://hub] [--json] update [--check]

Check the configured Hub distribution and install a newer verified CLI at
/usr/local/bin/vey. --check reads metadata without changing files or downloading
the binary. Updates require verified HTTPS and refuse redirects or downgrades.
No credentials or login are required. Configuration and credentials are preserved.

Run the installed /usr/local/bin/vey. Permission errors print an exact sudo
command with --hub because sudo may not retain your Hub configuration.
`

func RunUpdate(ctx *Context) int {
	return runUpdate(ctx, update.Check, func(c context.Context, hub, version string) (update.Result, error) {
		return update.Apply(c, hub, version, ctx.Revision)
	})
}

func runUpdate(ctx *Context, checkUpdate, applyUpdate func(context.Context, string, string) (update.Result, error)) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	check := fs.Bool("check", false, "check without downloading or changing files")
	help := fs.Bool("help", false, "print usage")
	if err := fs.Parse(ctx.Args); err != nil || len(fs.Args()) != 0 {
		ctx.Printer.Error(cmdutil.NewUsageError(fmt.Errorf("%s", updateUsage)))
		return cmdutil.ExitUsage
	}
	if *help {
		fmt.Fprint(ctx.Printer.Out, updateUsage)
		return cmdutil.ExitOK
	}
	hub, err := ctx.RequireHub()
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
	var result update.Result
	if *check {
		result, err = checkUpdate(context.Background(), hub, ctx.Version)
	} else {
		result, err = applyUpdate(context.Background(), hub, ctx.Version)
	}
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
	err = ctx.Printer.Payload(result, func(w io.Writer, v any) error {
		r := v.(update.Result)
		if r.Installed {
			_, err := fmt.Fprintf(w, "Updated vey to %s.\nPrevious executable retained at %s\n", r.AvailableVersion, r.Backup)
			return err
		}
		if r.UpdateAvailable {
			_, err := fmt.Fprintf(w, "Update available: vey %s -> %s (%s/%s).\n", r.CurrentVersion, r.AvailableVersion, r.Artifact.OS, r.Artifact.Arch)
			return err
		}
		_, err := fmt.Fprintf(w, "No newer CLI update: installed %s, Hub %s.\n", r.CurrentVersion, r.AvailableVersion)
		return err
	})
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
	return cmdutil.ExitOK
}
