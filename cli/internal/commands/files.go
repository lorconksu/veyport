package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// apiServersPathPrefix is the shared "/api/servers/{id}/..." URL prefix
// (contracts/cli-commands.md `vey files ls`, `vey files cat`), used here to
// avoid repeating the "/api/servers/" literal across this file's requests.
const apiServersPathPrefix = "/api/servers/"

// RunFiles implements `vey files ls <server> <path>` and `vey files cat
// <server> <path>` (contracts/cli-commands.md `vey files ls`, `vey files
// cat`), dispatching on ctx.Args[0].
func RunFiles(ctx *Context) int {
	if len(ctx.Args) == 0 {
		err := cmdutil.NewUsageError(errors.New("usage: vey files <ls|cat> <server> <path>"))
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	sub, rest := ctx.Args[0], ctx.Args[1:]
	switch sub {
	case "ls":
		return runFilesLs(ctx, rest)
	case "cat":
		return runFilesCat(ctx, rest)
	default:
		err := cmdutil.NewUsageError(fmt.Errorf("unknown files subcommand %q (want ls or cat)", sub))
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
}

// runFilesLs implements `vey files ls <server> <path>`
// (contracts/cli-commands.md `vey files ls`): GET
// /api/servers/{id}/files?path=. Human output is an `ls -l`-ish tabwriter
// listing (type marker, size, name — unreadable entries annotated);
// --json passes the hub's {files: [...]} envelope through verbatim.
func runFilesLs(ctx *Context, args []string) int {
	ref, path, err := parseServerPathArgs(args, "ls")
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	actx, err := resolveHubAuth(ctx)
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	bg := context.Background()
	id, err := resolveServerID(actx, ref)
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	var listing api.FileListing
	query := url.Values{"path": []string{path}}
	if err := actx.Do(bg, func(c *api.Client) error {
		return c.Get(bg, apiServersPathPrefix+url.PathEscape(id)+"/files", query, &listing)
	}); err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	_ = ctx.Printer.Payload(listing, func(w io.Writer, v any) error {
		l := v.(api.FileListing)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, f := range l.Files {
			typeMarker := "-"
			if f.IsDir {
				typeMarker = "d"
			}
			name := f.Name
			if !f.Readable {
				name += " (unreadable)"
			}
			fmt.Fprintf(tw, "%s\t%d\t%s\n", typeMarker, f.Size, name)
		}
		return tw.Flush()
	})
	return cmdutil.ExitOK
}

// runFilesCat implements `vey files cat <server> <path>`
// (contracts/cli-commands.md `vey files cat`): GET
// /api/servers/{id}/files/read?path=, streamed to stdout unmodified via
// Client.GetStream + Printer.PayloadRaw. Binary-safe: no JSON wrapping of
// content, no trailing newline added, and --json behaves identically since
// there is no JSON variant beyond the shared error shape on stderr.
func runFilesCat(ctx *Context, args []string) int {
	ref, path, err := parseServerPathArgs(args, "cat")
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	actx, err := resolveHubAuth(ctx)
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	bg := context.Background()
	id, err := resolveServerID(actx, ref)
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	query := url.Values{"path": []string{path}}
	var body io.ReadCloser
	if err := actx.Do(bg, func(c *api.Client) error {
		rc, err := c.GetStream(bg, apiServersPathPrefix+url.PathEscape(id)+"/files/read", query)
		if err != nil {
			return err
		}
		body = rc
		return nil
	}); err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
	defer body.Close()

	if _, err := ctx.Printer.PayloadRaw(body); err != nil {
		wrapped := cmdutil.NewConnError(fmt.Errorf("streaming file content: %w", err))
		ctx.Printer.Error(wrapped)
		return cmdutil.Code(wrapped)
	}
	return cmdutil.ExitOK
}

// parseServerPathArgs validates the shared `<server> <path>` argv shape for
// both files subcommands: both are required, and blank (whitespace-only)
// values are rejected the same as missing ones.
func parseServerPathArgs(args []string, sub string) (ref, path string, err error) {
	if len(args) < 2 || strings.TrimSpace(args[0]) == "" || strings.TrimSpace(args[1]) == "" {
		return "", "", cmdutil.NewUsageError(fmt.Errorf("usage: vey files %s <server> <path>", sub))
	}
	return args[0], args[1], nil
}

// resolveHubAuth resolves the effective hub and its AuthContext, the shared
// preamble every hub-touching files subcommand needs.
func resolveHubAuth(ctx *Context) (*auth.AuthContext, error) {
	hubURL, err := ctx.RequireHub()
	if err != nil {
		return nil, err
	}
	_, actx, err := newAuthContext(ctx, hubURL)
	if err != nil {
		return nil, err
	}
	return actx, nil
}

// resolveServerID resolves ref (a server ID or unique name) to its ID: a
// direct GET /api/servers/{id} first, falling back to exactly one
// GET /api/servers?search= call on a 404 (contracts/cli-commands.md `vey
// servers get`: "<server> is an ID or unique name, resolved via one search
// call; ambiguity → exit 2 listing candidates"). vey files ls/cat need the
// server's ID to build /api/servers/{id}/files*, so they resolve the same
// way runServersGet does (servers.go), duplicated here rather than shared
// since it is not exported as its own helper there.
func resolveServerID(actx *auth.AuthContext, ref string) (string, error) {
	bg := context.Background()

	var server api.Server
	getErr := actx.Do(bg, func(c *api.Client) error {
		return c.Get(bg, apiServersPathPrefix+url.PathEscape(ref), nil, &server)
	})
	if getErr == nil {
		return server.ID, nil
	}
	if cmdutil.Code(getErr) != cmdutil.ExitNotFound {
		return "", getErr
	}

	// Direct lookup 404'd: ref may be a name. One fallback search call
	// resolves it.
	var page api.ServersPage
	query := url.Values{"search": []string{ref}}
	if err := actx.Do(bg, func(c *api.Client) error {
		return c.Get(bg, "/api/servers", query, &page)
	}); err != nil {
		return "", err
	}

	var matches []api.Server
	for _, s := range page.Servers {
		if s.Name == ref {
			matches = append(matches, s)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0].ID, nil
	case 0:
		return "", cmdutil.NewNotFoundError(fmt.Errorf("no server found matching %q", ref))
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, fmt.Sprintf("%s (%s)", m.Name, m.ID))
		}
		sort.Strings(names)
		return "", cmdutil.NewUsageError(fmt.Errorf("%q matches multiple servers: %s", ref, strings.Join(names, ", ")))
	}
}
