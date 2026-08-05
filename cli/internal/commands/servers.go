package commands

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// RunServers implements `vey servers list` and `vey servers get <server>`
// (contracts/cli-commands.md `vey servers list`, `vey servers get`),
// dispatching on ctx.Args[0].
func RunServers(ctx *Context) int {
	if len(ctx.Args) == 0 {
		err := cmdutil.NewUsageError(errors.New("usage: vey servers <list|get> [args]"))
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	sub, rest := ctx.Args[0], ctx.Args[1:]
	switch sub {
	case "list":
		return runServersList(ctx, rest)
	case "get":
		return runServersGet(ctx, rest)
	default:
		err := cmdutil.NewUsageError(fmt.Errorf("unknown servers subcommand %q (want list or get)", sub))
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
}

// runServersList implements `vey servers list [--status s] [--search q]
// [--limit N] [--offset N]`: flags are parsed from args (which follow the
// "servers list" subcommand, per the global-flags-before-subcommand
// contract) and passed through to the hub unchanged. Human output is an
// aligned NAME/STATUS/ID table; the total is reported to stderr. --json
// passes the hub's response envelope through verbatim. Zero rows still
// exits 0.
func runServersList(ctx *Context, args []string) int {
	fs := flag.NewFlagSet("servers list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	status := fs.String("status", "", "filter by server status")
	search := fs.String("search", "", "filter by name/hostname search")
	limit := fs.Int("limit", 0, "maximum number of servers to return")
	offset := fs.Int("offset", 0, "pagination offset")
	if err := fs.Parse(args); err != nil {
		wrapped := cmdutil.NewUsageError(err)
		ctx.Printer.Error(wrapped)
		return cmdutil.Code(wrapped)
	}

	query := url.Values{}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "status":
			query.Set("status", *status)
		case "search":
			query.Set("search", *search)
		case "limit":
			query.Set("limit", fmt.Sprintf("%d", *limit))
		case "offset":
			query.Set("offset", fmt.Sprintf("%d", *offset))
		}
	})

	hubURL, err := ctx.RequireHub()
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
	_, actx, err := newAuthContext(ctx, hubURL)
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	bg := context.Background()
	var page api.ServersPage
	if err := actx.Do(bg, func(c *api.Client) error {
		return c.Get(bg, "/api/servers", query, &page)
	}); err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	_ = ctx.Printer.Payload(page, func(w io.Writer, v any) error {
		p := v.(api.ServersPage)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSTATUS\tID")
		for _, s := range p.Servers {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Name, s.Status, s.ID)
		}
		return tw.Flush()
	})
	ctx.Printer.Errorf("total %d\n", page.Total)
	return cmdutil.ExitOK
}

// runServersGet implements `vey servers get <server>`: <server> is an ID or
// unique name, resolved via a direct GET by ID first; on 404, exactly one
// fallback GET /api/servers?search=<server> resolves it by exact name
// match. Ambiguous matches exit 2 listing candidates; no match exits 5.
func runServersGet(ctx *Context, args []string) int {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		err := cmdutil.NewUsageError(errors.New("usage: vey servers get <server>"))
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
	ref := args[0]

	hubURL, err := ctx.RequireHub()
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
	_, actx, err := newAuthContext(ctx, hubURL)
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	bg := context.Background()
	var server api.Server
	getErr := actx.Do(bg, func(c *api.Client) error {
		return c.Get(bg, "/api/servers/"+url.PathEscape(ref), nil, &server)
	})
	if getErr == nil {
		printServer(ctx, server)
		return cmdutil.ExitOK
	}
	if cmdutil.Code(getErr) != cmdutil.ExitNotFound {
		ctx.Printer.Error(getErr)
		return cmdutil.Code(getErr)
	}

	// Direct lookup 404'd: ref may be a name. One fallback search call
	// resolves it (contracts/cli-commands.md: "resolved via one search
	// call").
	var page api.ServersPage
	query := url.Values{"search": []string{ref}}
	if err := actx.Do(bg, func(c *api.Client) error {
		return c.Get(bg, "/api/servers", query, &page)
	}); err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	var matches []api.Server
	for _, s := range page.Servers {
		if s.Name == ref {
			matches = append(matches, s)
		}
	}

	switch len(matches) {
	case 1:
		printServer(ctx, matches[0])
		return cmdutil.ExitOK
	case 0:
		notFound := cmdutil.NewNotFoundError(fmt.Errorf("no server found matching %q", ref))
		ctx.Printer.Error(notFound)
		return cmdutil.Code(notFound)
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, fmt.Sprintf("%s (%s)", m.Name, m.ID))
		}
		sort.Strings(names)
		ambiguous := cmdutil.NewUsageError(fmt.Errorf("%q matches multiple servers: %s", ref, strings.Join(names, ", ")))
		ctx.Printer.Error(ambiguous)
		return cmdutil.Code(ambiguous)
	}
}

// printServer renders one server: field/value lines in human mode, the raw
// server object in --json mode.
func printServer(ctx *Context, s api.Server) {
	_ = ctx.Printer.Payload(s, func(w io.Writer, v any) error {
		srv := v.(api.Server)
		fmt.Fprintf(w, "ID: %s\n", srv.ID)
		fmt.Fprintf(w, "Name: %s\n", srv.Name)
		fmt.Fprintf(w, "Status: %s\n", srv.Status)
		if srv.Hostname != nil {
			fmt.Fprintf(w, "Hostname: %s\n", *srv.Hostname)
		}
		if srv.IPAddress != nil {
			fmt.Fprintf(w, "IP Address: %s\n", *srv.IPAddress)
		}
		if srv.OS != nil {
			fmt.Fprintf(w, "OS: %s\n", *srv.OS)
		}
		if srv.AgentVersion != nil {
			fmt.Fprintf(w, "Agent Version: %s\n", *srv.AgentVersion)
		}
		if srv.Labels != "" {
			fmt.Fprintf(w, "Labels: %s\n", srv.Labels)
		}
		if srv.LastSeenAt != nil {
			fmt.Fprintf(w, "Last Seen: %s\n", *srv.LastSeenAt)
		}
		return nil
	})
}
