package commands

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/config"
)

// --- scaffolding --------------------------------------------------------
//
// The hub base64-encodes every log frame it forwards
// (hub/internal/server/handlers_logs.go: `fmt.Fprintf(w, "data: %s\n\n",
// base64.StdEncoding.EncodeToString(data))`), and the frames are raw agent
// read-buffer chunks, NOT line-aligned (agent/internal/logtailer/tailer.go
// forwards whatever a single file Read returned). These helpers reproduce
// that framing exactly so the command tests exercise the real wire shape.

// logFrame renders payload the way the hub does: base64 inside a default
// (unnamed) SSE data frame.
func logFrame(payload string) string {
	return "data: " + base64.StdEncoding.EncodeToString([]byte(payload)) + "\n\n"
}

// overflowFrame renders the hub's overflow notice frame.
func overflowFrame(dropped int) string {
	return fmt.Sprintf("event: overflow\ndata: {\"dropped\":%d}\n\n", dropped)
}

// tailHandler builds an SSE handler for GET
// /api/servers/{id}/logs/tail, invoking body once headers are written.
func tailHandler(body func(w http.ResponseWriter, r *http.Request, flush func())) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		body(w, r, flusher.Flush)
	}
}

// newLogsHub stands up a hub stub with the refresh stub, server-by-ID
// resolution (any id resolves to itself), and the given tail handler.
func newLogsHub(t *testing.T, tail http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "name": "web-01", "status": "online"})
	})
	mux.HandleFunc("GET /api/servers/{id}/logs/tail", func(w http.ResponseWriter, r *http.Request) {
		if !requireBearer(r, "access-1") {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		tail(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newLogsContext wires a *Context at srv with a seeded session, mirroring
// the other command tests' setup.
func newLogsContext(t *testing.T, srv *httptest.Server, jsonMode bool, args []string) (*Context, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	t.Setenv("VEYPORT_TOKEN", "")
	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now(),
	})
	return newCmdContext(srv.URL, configDir, jsonMode, args)
}

// syncBuffer is a mutex-guarded buffer, needed where the test reads output
// while the command under test is still writing it (the signal tests).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// --- usage --------------------------------------------------------------

// TestLogs_UsageErrors covers the required `tail` subcommand and its two
// positional arguments (contracts/cli-commands.md: `vey logs tail <server>
// <path>`); every malformed invocation is exit 2.
func TestLogs_UsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no subcommand", nil},
		{"unknown subcommand", []string{"follow", "srv-1", "/var/log/syslog"}},
		{"tail with no args", []string{"tail"}},
		{"tail with only a server", []string{"tail", "srv-1"}},
		{"tail with too many args", []string{"tail", "srv-1", "/var/log/syslog", "extra"}},
		{"tail with unknown flag", []string{"tail", "srv-1", "/var/log/syslog", "--nope"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, stdout, stderr := newCmdContext("https://hub.example.com", t.TempDir(), false, tc.args)
			if code := RunLogs(ctx); code != cmdutil.ExitUsage {
				t.Fatalf("exit code = %d, want %d (ExitUsage)", code, cmdutil.ExitUsage)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty (usage errors go to stderr)", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Error("stderr is empty, want a usage message")
			}
		})
	}
}

// --- streaming output ---------------------------------------------------

// TestLogsTail_StreamsLinesToStdout covers US4-1: lines reach stdout as they
// arrive. The stub deliberately splits a log line across two SSE frames —
// exactly what the agent's chunked reads produce — so the command must
// reassemble lines rather than print frames.
func TestLogsTail_StreamsLinesToStdout(t *testing.T) {
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, logFrame("line one\nline t"))
		flush()
		fmt.Fprint(w, logFrame("wo\nline three\n"))
		flush()
	}))

	ctx, stdout, stderr := newLogsContext(t, srv, false, []string{"tail", "srv-1", "/var/log/syslog"})
	code := RunLogs(ctx)

	want := "line one\nline two\nline three\n"
	if stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
	// The hub's tail never ends voluntarily, so a clean close is still an
	// unexpected close at the command level.
	if code != cmdutil.ExitConn {
		t.Errorf("exit code = %d, want %d (ExitConn) on server-side close; stderr=%q", code, cmdutil.ExitConn, stderr.String())
	}
}

// TestLogsTail_PathAndGrepAreQueryParams covers US4-2 and the "server-side
// grep" contract: --grep travels as the `grep` query parameter and the CLI
// never filters locally (every line the hub sends is printed, matching or
// not).
func TestLogsTail_PathAndGrepAreQueryParams(t *testing.T) {
	var (
		mu               sync.Mutex
		gotPath, gotGrep string
		gotAccept        string
	)
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		mu.Lock()
		gotPath = r.URL.Query().Get("path")
		gotGrep = r.URL.Query().Get("grep")
		gotAccept = r.Header.Get("Accept")
		mu.Unlock()
		// The hub already applied the filter; whatever arrives is printed.
		fmt.Fprint(w, logFrame("kept-by-server\n"))
		flush()
	}))

	ctx, stdout, _ := newLogsContext(t, srv, false, []string{"tail", "srv-1", "/var/log/syslog", "--grep", "panic"})
	RunLogs(ctx)

	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/var/log/syslog" {
		t.Errorf("path query param = %q, want %q", gotPath, "/var/log/syslog")
	}
	if gotGrep != "panic" {
		t.Errorf("grep query param = %q, want %q", gotGrep, "panic")
	}
	if gotAccept != "text/event-stream" {
		t.Errorf("Accept = %q, want text/event-stream", gotAccept)
	}
	if stdout.String() != "kept-by-server\n" {
		t.Errorf("stdout = %q, want the server's line passed through verbatim", stdout.String())
	}
}

// TestLogsTail_GrepFlagBeforePositionals accepts the flag in either
// position, so `vey logs tail --grep x srv path` works too.
func TestLogsTail_GrepFlagBeforePositionals(t *testing.T) {
	var (
		mu      sync.Mutex
		gotGrep string
	)
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		mu.Lock()
		gotGrep = r.URL.Query().Get("grep")
		mu.Unlock()
		flush()
	}))

	ctx, _, _ := newLogsContext(t, srv, false, []string{"tail", "--grep", "boom", "srv-1", "/var/log/syslog"})
	RunLogs(ctx)

	mu.Lock()
	defer mu.Unlock()
	if gotGrep != "boom" {
		t.Errorf("grep query param = %q, want %q", gotGrep, "boom")
	}
}

// TestLogsTail_NoGrepOmitsParam keeps the request clean when no filter is
// requested.
func TestLogsTail_NoGrepOmitsParam(t *testing.T) {
	var (
		mu      sync.Mutex
		hasGrep bool
	)
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		mu.Lock()
		_, hasGrep = r.URL.Query()["grep"]
		mu.Unlock()
		flush()
	}))

	ctx, _, _ := newLogsContext(t, srv, false, []string{"tail", "srv-1", "/var/log/syslog"})
	RunLogs(ctx)

	mu.Lock()
	defer mu.Unlock()
	if hasGrep {
		t.Error("grep query param present, want it omitted when --grep is not passed")
	}
}

// TestLogsTail_JSONLines covers the --json contract: one JSON document per
// line on stdout, shaped {"line": "..."}.
func TestLogsTail_JSONLines(t *testing.T) {
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, logFrame("alpha\nbra"))
		flush()
		fmt.Fprint(w, logFrame("vo\n"))
		flush()
	}))

	ctx, stdout, _ := newLogsContext(t, srv, true, []string{"tail", "srv-1", "/var/log/syslog"})
	RunLogs(ctx)

	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout had %d JSON lines, want 2: %q", len(lines), stdout.String())
	}
	want := []string{"alpha", "bravo"}
	for i, raw := range lines {
		var doc struct {
			Line string `json:"line"`
		}
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatalf("stdout line %d is not valid JSON (%v): %q", i, err, raw)
		}
		if doc.Line != want[i] {
			t.Errorf("stdout line %d = %q, want %q", i, doc.Line, want[i])
		}
	}
}

// TestLogsTail_JSONErrorsGoToStderr keeps stdout payload-only in JSON mode:
// the unexpected-close failure is a {"error","code"} document on stderr.
func TestLogsTail_JSONErrorsGoToStderr(t *testing.T) {
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		flush() // immediate clean close, no events
	}))

	ctx, stdout, stderr := newLogsContext(t, srv, true, []string{"tail", "srv-1", "/var/log/syslog"})
	if code := RunLogs(ctx); code != cmdutil.ExitConn {
		t.Fatalf("exit code = %d, want %d (ExitConn)", code, cmdutil.ExitConn)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	var doc struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
	}
	// The credential store may emit a one-time keyring-fallback warning
	// ahead of the error; the command failure is always the last line.
	errLines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
	last := errLines[len(errLines)-1]
	if err := json.Unmarshal([]byte(last), &doc); err != nil {
		t.Fatalf("last stderr line is not a JSON error document (%v): %q", err, stderr.String())
	}
	if doc.Code != cmdutil.ExitConn {
		t.Errorf("stderr error code = %d, want %d", doc.Code, cmdutil.ExitConn)
	}
	if doc.Error == "" {
		t.Error("stderr error message is empty")
	}
}

// --- termination --------------------------------------------------------

// TestLogsTail_UnexpectedCloseExit6 covers US4-4: the CLI reports the
// disconnection on stderr rather than sitting silent, and exits 6.
func TestLogsTail_UnexpectedCloseExit6(t *testing.T) {
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, logFrame("some line\n"))
		flush()
	}))

	ctx, stdout, stderr := newLogsContext(t, srv, false, []string{"tail", "srv-1", "/var/log/syslog"})
	code := RunLogs(ctx)

	if code != cmdutil.ExitConn {
		t.Fatalf("exit code = %d, want %d (ExitConn)", code, cmdutil.ExitConn)
	}
	if stdout.String() != "some line\n" {
		t.Errorf("stdout = %q, want the line delivered before the close", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr is empty, want a notice that the stream closed")
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "stream") {
		t.Errorf("stderr = %q, want a notice mentioning the stream closing", stderr.String())
	}
}

// TestLogsTail_MidStreamDropExit6 covers an abrupt connection loss (no
// chunked terminator): also a stderr notice and exit 6, never a silent hang.
func TestLogsTail_MidStreamDropExit6(t *testing.T) {
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, logFrame("before the drop\n"))
		flush()
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("test server does not support hijacking")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	}))

	ctx, stdout, stderr := newLogsContext(t, srv, false, []string{"tail", "srv-1", "/var/log/syslog"})
	code := RunLogs(ctx)

	if code != cmdutil.ExitConn {
		t.Fatalf("exit code = %d, want %d (ExitConn); stderr=%q", code, cmdutil.ExitConn, stderr.String())
	}
	if stdout.String() != "before the drop\n" {
		t.Errorf("stdout = %q, want the line delivered before the drop", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want a disconnection notice")
	}
}

// TestLogsTail_SIGINTExitsZero covers US4-3: Ctrl-C terminates the stream
// cleanly and exits 0 with no error output. The signal is delivered to this
// test process for real, so it also proves RunLogs installs the handler.
func TestLogsTail_SIGINTExitsZero(t *testing.T) {
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, logFrame("live line\n"))
		flush()
		<-r.Context().Done() // a real tail never ends on its own
	}))

	t.Setenv("VEYPORT_TOKEN", "")
	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now(),
	})

	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	printer := cmdutil.NewPrinter(stdout, stderr, false)
	ctx := NewContext(srv.URL, "", config.Config{}, configDir, printer, []string{"tail", "srv-1", "/var/log/syslog"})

	codeCh := make(chan int, 1)
	go func() { codeCh <- RunLogs(ctx) }()

	// Output proves the signal handler is already installed (RunLogs
	// registers it before the first byte is written).
	waitFor(t, "the first streamed line", func() bool { return stdout.String() == "live line\n" })

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("raising SIGINT: %v", err)
	}

	select {
	case code := <-codeCh:
		if code != cmdutil.ExitOK {
			t.Errorf("exit code = %d, want %d (ExitOK) on Ctrl-C; stderr=%q", code, cmdutil.ExitOK, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("vey logs tail did not exit within 15s of SIGINT")
	}

	if strings.Contains(stderr.String(), "Error:") {
		t.Errorf("stderr = %q, want no error output on a clean Ctrl-C exit", stderr.String())
	}
	if stdout.String() != "live line\n" {
		t.Errorf("stdout = %q, want only the streamed line", stdout.String())
	}
}

// TestLogsTail_ContextCancelExitsZero exercises the same clean-stop path
// through the injectable seam, without touching process signals.
func TestLogsTail_ContextCancelExitsZero(t *testing.T) {
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, logFrame("live line\n"))
		flush()
		<-r.Context().Done()
	}))

	t.Setenv("VEYPORT_TOKEN", "")
	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now(),
	})

	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	printer := cmdutil.NewPrinter(stdout, stderr, false)
	cmdCtx := NewContext(srv.URL, "", config.Config{}, configDir, printer, []string{"tail", "srv-1", "/var/log/syslog"})

	base, cancel := context.WithCancel(context.Background())
	defer cancel()

	codeCh := make(chan int, 1)
	go func() { codeCh <- runLogs(cmdCtx, base) }()

	waitFor(t, "the first streamed line", func() bool { return stdout.String() == "live line\n" })
	cancel()

	select {
	case code := <-codeCh:
		if code != cmdutil.ExitOK {
			t.Errorf("exit code = %d, want %d (ExitOK) on cancellation; stderr=%q", code, cmdutil.ExitOK, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runLogs did not return within 15s of cancellation")
	}
}

// --- hub-specific framing -----------------------------------------------

// TestLogsTail_OverflowEventGoesToStderr covers the hub's `event: overflow`
// frame (handlers_logs.go): it is a diagnostic, so it belongs on stderr and
// must never be mistaken for a log line on stdout.
func TestLogsTail_OverflowEventGoesToStderr(t *testing.T) {
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, logFrame("kept\n"))
		fmt.Fprint(w, overflowFrame(12))
		flush()
	}))

	ctx, stdout, stderr := newLogsContext(t, srv, false, []string{"tail", "srv-1", "/var/log/syslog"})
	RunLogs(ctx)

	if stdout.String() != "kept\n" {
		t.Errorf("stdout = %q, want only the log line (overflow notices are diagnostics)", stdout.String())
	}
	if !strings.Contains(stderr.String(), "12") {
		t.Errorf("stderr = %q, want a notice naming the 12 dropped lines", stderr.String())
	}
}

// TestLogsTail_TrailingPartialLineIsFlushed makes sure a final line with no
// newline (the stream dropped mid-line) still reaches stdout.
func TestLogsTail_TrailingPartialLineIsFlushed(t *testing.T) {
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, logFrame("complete\npartial-no-newline"))
		flush()
	}))

	ctx, stdout, _ := newLogsContext(t, srv, false, []string{"tail", "srv-1", "/var/log/syslog"})
	RunLogs(ctx)

	want := "complete\npartial-no-newline\n"
	if stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
}

// TestLogsTail_CRLFLogLines strips the carriage return so Windows-authored
// logs render (and JSON-encode) as clean lines.
func TestLogsTail_CRLFLogLines(t *testing.T) {
	srv := newLogsHub(t, tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, logFrame("dos-line\r\n"))
		flush()
	}))

	ctx, stdout, _ := newLogsContext(t, srv, false, []string{"tail", "srv-1", "/var/log/syslog"})
	RunLogs(ctx)

	if stdout.String() != "dos-line\n" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "dos-line\n")
	}
}

// --- server reference resolution ---------------------------------------

// TestLogsTail_ResolvesServerName accepts a server name, resolving it the
// same way `vey servers get` does: direct lookup first, then one search.
func TestLogsTail_ResolvesServerName(t *testing.T) {
	var (
		mu       sync.Mutex
		tailedID string
	)
	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("search") != "web-01" {
			t.Errorf("search param = %q, want %q", r.URL.Query().Get("search"), "web-01")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"servers": []map[string]string{{"id": "srv-uuid-1", "name": "web-01", "status": "online"}},
			"total":   1,
		})
	})
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "server not found"})
	})
	mux.HandleFunc("GET /api/servers/{id}/logs/tail", tailHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		mu.Lock()
		tailedID = r.PathValue("id")
		mu.Unlock()
		fmt.Fprint(w, logFrame("resolved\n"))
		flush()
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, stdout, _ := newLogsContext(t, srv, false, []string{"tail", "web-01", "/var/log/syslog"})
	RunLogs(ctx)

	mu.Lock()
	defer mu.Unlock()
	if tailedID != "srv-uuid-1" {
		t.Errorf("tail was issued against %q, want the resolved id %q", tailedID, "srv-uuid-1")
	}
	if stdout.String() != "resolved\n" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "resolved\n")
	}
}

// TestLogsTail_UnknownServerExit5 pins the not-found mapping for a server
// reference that resolves to nothing.
func TestLogsTail_UnknownServerExit5(t *testing.T) {
	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"servers": []map[string]string{}, "total": 0})
	})
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "server not found"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, stdout, _ := newLogsContext(t, srv, false, []string{"tail", "ghost", "/var/log/syslog"})
	if code := RunLogs(ctx); code != cmdutil.ExitNotFound {
		t.Fatalf("exit code = %d, want %d (ExitNotFound)", code, cmdutil.ExitNotFound)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

// --- error mapping ------------------------------------------------------

// TestLogsTail_ErrorStatusMapping pins the hub's refusals to the documented
// exit codes (R8), with nothing on stdout.
func TestLogsTail_ErrorStatusMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   int
	}{
		{"forbidden path", http.StatusForbidden, cmdutil.ExitForbidden},
		{"unknown path", http.StatusNotFound, cmdutil.ExitNotFound},
		{"agent offline", http.StatusBadGateway, cmdutil.ExitError},
		{"too many streams", http.StatusTooManyRequests, cmdutil.ExitRateLimited},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newLogsHub(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "refused"})
			})

			ctx, stdout, stderr := newLogsContext(t, srv, false, []string{"tail", "srv-1", "/var/log/syslog"})
			if code := RunLogs(ctx); code != tc.want {
				t.Fatalf("exit code = %d, want %d; stderr=%q", code, tc.want, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), "refused") {
				t.Errorf("stderr = %q, want the hub's message surfaced", stderr.String())
			}
		})
	}
}

// TestLogsTail_NoHubExit2 keeps the "no hub configured" failure a usage
// error, consistent with the other hub-bound commands.
func TestLogsTail_NoHubExit2(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")
	ctx, _, stderr := newCmdContext("", t.TempDir(), false, []string{"tail", "srv-1", "/var/log/syslog"})
	if code := RunLogs(ctx); code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stderr=%q", code, cmdutil.ExitUsage, stderr.String())
	}
}
