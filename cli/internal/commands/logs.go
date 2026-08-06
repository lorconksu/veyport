package commands

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// RunLogs implements `vey logs tail <server> <path> [--grep <pattern>]`
// (contracts/cli-commands.md `vey logs tail`): a live SSE follow.
//
// The interrupt handler is installed here, around the whole command, so
// Ctrl-C is a clean stop (exit 0) at every stage — while resolving the
// server reference, while the stream is being established, and once lines
// are flowing (spec US4-3). runLogs takes the resulting context explicitly
// so tests can drive the same clean-stop path without touching process
// signals.
func RunLogs(ctx *Context) int {
	base, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runLogs(ctx, base)
}

// runLogs dispatches the logs subcommand. `tail` is the only one in 004;
// anything else (including nothing at all) is a usage error, checked before
// any hub resolution or network access happens.
func runLogs(cmd *Context, base context.Context) int {
	const usage = "usage: vey logs tail <server> <path> [--grep <pattern>]"

	if len(cmd.Args) == 0 {
		return failLogs(cmd, cmdutil.NewUsageError(errors.New(usage)))
	}
	sub, rest := cmd.Args[0], cmd.Args[1:]
	if sub != "tail" {
		return failLogs(cmd, cmdutil.NewUsageError(fmt.Errorf("unknown logs subcommand %q (want tail); %s", sub, usage)))
	}
	return runLogsTail(cmd, base, rest, usage)
}

// runLogsTail streams one log file. --grep is forwarded to the hub as the
// `grep` query parameter and never applied locally: the filtering happens
// server-side (contracts/rest-api.md), which is what keeps a noisy log from
// being shipped across the network only to be discarded here.
func runLogsTail(cmd *Context, base context.Context, args []string, usage string) int {
	fs := flag.NewFlagSet("logs tail", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	grep := fs.String("grep", "", "server-side filter pattern")

	// flag.Parse stops at the first non-flag argument, so parse-consume-repeat
	// to accept the flag on either side of the positionals (`logs tail srv
	// /path --grep x` and `logs tail --grep x srv /path` both work).
	var positional []string
	remaining := args
	for {
		if err := fs.Parse(remaining); err != nil {
			return failLogs(cmd, cmdutil.NewUsageError(fmt.Errorf("%w; %s", err, usage)))
		}
		remaining = fs.Args()
		if len(remaining) == 0 {
			break
		}
		positional = append(positional, remaining[0])
		remaining = remaining[1:]
	}

	if len(positional) != 2 {
		return failLogs(cmd, cmdutil.NewUsageError(errors.New(usage)))
	}
	serverRef, path := positional[0], positional[1]
	if strings.TrimSpace(serverRef) == "" || strings.TrimSpace(path) == "" {
		return failLogs(cmd, cmdutil.NewUsageError(errors.New(usage)))
	}

	hubURL, err := cmd.RequireHub()
	if err != nil {
		return failLogs(cmd, err)
	}
	_, actx, err := newAuthContext(cmd, hubURL)
	if err != nil {
		return failLogs(cmd, err)
	}

	serverID, err := resolveLogServerID(base, actx, serverRef)
	if err != nil {
		return classifyLogsExit(cmd, err)
	}

	query := url.Values{"path": []string{path}}
	if *grep != "" {
		query.Set("grep", *grep)
	}

	out := &logLineWriter{printer: cmd.Printer}
	streamPath := "/api/servers/" + url.PathEscape(serverID) + "/logs/tail"

	// AuthContext.Do replays the operation once on a 401. That is safe here
	// even though the operation streams: StreamSSE only ever reports 401
	// from the response status, before a single event is dispatched, so a
	// replay can never duplicate output.
	err = actx.Do(base, func(c *api.Client) error {
		return c.StreamSSE(base, streamPath, query, out.handle)
	})
	// Whatever ended the stream, a partial trailing line already received is
	// the operator's data — emit it before reporting.
	out.flush()

	return classifyLogsExit(cmd, err)
}

// classifyLogsExit turns the stream's terminal error into the documented
// exit code (research.md R8).
func classifyLogsExit(cmd *Context, err error) int {
	switch {
	case err == nil:
		return cmdutil.ExitOK

	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Ctrl-C (or SIGTERM): the user ended the tail, which is success.
		// Nothing is printed — the shell is about to get its prompt back.
		return cmdutil.ExitOK

	case errors.Is(err, api.ErrStreamEnded):
		// The hub's handleTailLog only returns when the client disconnects
		// or the agent session dies, so a clean server-side EOF means the
		// tail stopped for a reason the operator did not choose (US4-4:
		// report the disconnection rather than sitting silent).
		return failLogs(cmd, cmdutil.NewConnError(errors.New(
			"log stream closed by the hub before you stopped it (the agent may have disconnected)")))

	default:
		return failLogs(cmd, err)
	}
}

// failLogs reports err on stderr and returns its exit code.
func failLogs(cmd *Context, err error) int {
	cmd.Printer.Error(err)
	return cmdutil.Code(err)
}

// resolveLogServerID turns a server ID or unique name into an ID, using the
// same two-step resolution as `vey servers get`: a direct lookup by ID
// first, then exactly one search call to resolve a name. Resolving up front
// (rather than passing the reference straight into the tail URL) keeps a
// 404 from being ambiguous between "no such server" and "no such log path".
func resolveLogServerID(ctx context.Context, actx *auth.AuthContext, ref string) (string, error) {
	var server api.Server
	err := actx.Do(ctx, func(c *api.Client) error {
		return c.Get(ctx, "/api/servers/"+url.PathEscape(ref), nil, &server)
	})
	if err == nil {
		if server.ID != "" {
			return server.ID, nil
		}
		return ref, nil
	}
	if cmdutil.Code(err) != cmdutil.ExitNotFound {
		return "", err
	}

	var page api.ServersPage
	if err := actx.Do(ctx, func(c *api.Client) error {
		return c.Get(ctx, "/api/servers", url.Values{"search": []string{ref}}, &page)
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

// logLine is the --json stream shape: one JSON document per log line
// (contracts/cli-commands.md `vey logs tail`: JSON-lines `{"line": "..."}`).
type logLine struct {
	Line string `json:"line"`
}

// logLineWriter turns the hub's SSE frames into log lines on stdout.
//
// Two properties of the hub's framing drive this type. First, every default
// frame's payload is base64 (hub/internal/server/handlers_logs.go writes
// `data: <base64(chunk)>`), so it must be decoded before anything is
// printed. Second, a frame is whatever a single agent-side file read
// returned (agent/internal/logtailer/tailer.go), so frames are NOT
// line-aligned: one log line can straddle two frames and one frame can hold
// many lines. Lines are therefore reassembled here, and only complete lines
// are emitted — which is also exactly the "no client-side buffering beyond
// one line" bound the contract requires (Constitution IV).
type logLineWriter struct {
	printer *cmdutil.Printer

	// buf holds the bytes received since the last newline: at most one
	// partial line, hard-capped by maxPartialLineBytes.
	buf bytes.Buffer

	// warnedMalformed keeps a corrupt stream from flooding stderr with the
	// same notice once per frame.
	warnedMalformed bool
}

// maxPartialLineBytes caps the line-reassembly buffer. A log file with no
// newline in sight must not grow the CLI's memory without bound; past the
// cap the partial line is emitted as-is rather than retained.
const maxPartialLineBytes = api.MaxSSEEventBytes

// handle dispatches one SSE event.
func (w *logLineWriter) handle(ev api.SSEEvent) error {
	switch ev.Event {
	case "", "message":
		w.data(ev.Data)
	case "overflow":
		w.overflow(ev.Data)
	default:
		// Unknown event type from a newer hub: ignored, per the
		// forward-compatibility rule in contracts/rest-api.md.
	}
	return nil
}

// data decodes one base64 log frame and emits whatever complete lines it
// completes.
func (w *logLineWriter) data(encoded string) {
	if encoded == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// A frame that is not base64 is not something this CLI can render.
		// Skipping it (with one notice) keeps a long-running tail alive
		// through a single bad frame instead of aborting the operator's
		// session; the notice goes to stderr so piped stdout stays clean.
		if !w.warnedMalformed {
			w.warnedMalformed = true
			w.printer.Errorf("warning: skipping malformed log frame(s) from the hub\n")
		}
		return
	}

	w.buf.Write(raw)
	for {
		pending := w.buf.Bytes()
		i := bytes.IndexByte(pending, '\n')
		if i < 0 {
			break
		}
		w.writeLine(pending[:i])
		w.buf.Next(i + 1)
	}

	if w.buf.Len() > maxPartialLineBytes {
		w.printer.Errorf("warning: log line exceeded %d bytes with no newline; emitting it in fragments\n", maxPartialLineBytes)
		w.writeLine(w.buf.Bytes())
		w.buf.Reset()
	}
}

// overflow renders the hub's `event: overflow` notice. It is a diagnostic
// about the hub's own buffering, not log content, so it goes to stderr and
// never contaminates piped stdout.
func (w *logLineWriter) overflow(data string) {
	var payload struct {
		Dropped int `json:"dropped"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err == nil && payload.Dropped > 0 {
		w.printer.Errorf("warning: hub dropped %d log line(s); the tail is falling behind\n", payload.Dropped)
		return
	}
	w.printer.Errorf("warning: hub dropped log output; the tail is falling behind\n")
}

// flush emits any trailing partial line, so a stream that drops mid-line
// still delivers what was received.
func (w *logLineWriter) flush() {
	if w.buf.Len() == 0 {
		return
	}
	w.writeLine(w.buf.Bytes())
	w.buf.Reset()
}

// writeLine emits exactly one line, immediately: a plain line in human mode,
// a `{"line": "..."}` document in --json mode. Nothing is buffered past this
// call, so a tail stays live under a pipe.
func (w *logLineWriter) writeLine(line []byte) {
	line = bytes.TrimSuffix(line, []byte("\r"))
	_ = w.printer.Payload(logLine{Line: string(line)}, func(out io.Writer, v any) error {
		_, err := fmt.Fprintf(out, "%s\n", v.(logLine).Line)
		return err
	})
}
