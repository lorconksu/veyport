package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// --- scaffolding --------------------------------------------------------

// sseHandler builds an SSE handler that runs body with a flusher already
// wired up and the SSE response headers written.
func sseHandler(body func(w http.ResponseWriter, r *http.Request, flush func())) http.HandlerFunc {
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

// collectSSE runs StreamSSE against srv, appending every dispatched event to
// the returned slice, and returns the terminal error.
func collectSSE(t *testing.T, srv *httptest.Server, query url.Values) ([]SSEEvent, error) {
	t.Helper()
	c := newTestClient(srv, "tok")
	var got []SSEEvent
	err := c.StreamSSE(context.Background(), "/api/stream", query, func(ev SSEEvent) error {
		got = append(got, ev)
		return nil
	})
	return got, err
}

// --- parsing ------------------------------------------------------------

// TestStreamSSE_ParsesDataAndEventLines pins the SSE framing rules the hub
// actually uses (hub/internal/server/handlers_logs.go: plain `data:` frames
// plus `event: overflow` frames) along with the spec-mandated handling of
// multi-line data, comments, and unknown fields.
func TestStreamSSE_ParsesDataAndEventLines(t *testing.T) {
	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		// A plain default-event frame, exactly as handleTailLog writes it.
		fmt.Fprint(w, "data: aGVsbG8K\n\n")
		// Multi-line data joins with \n (SSE spec).
		fmt.Fprint(w, "data: one\ndata: two\ndata: three\n\n")
		// A named event, as the hub's overflow notice does.
		fmt.Fprint(w, "event: overflow\ndata: {\"dropped\":7}\n\n")
		// Comment lines and unknown/ignored fields must not dispatch or
		// leak into the next event.
		fmt.Fprint(w, ": keep-alive comment\nid: 42\nretry: 3000\nbogus: whatever\ndata: after-noise\n\n")
		// A field with no space after the colon: only ONE leading space is
		// stripped, per spec.
		fmt.Fprint(w, "data:no-space\n\n")
		// event name resets after dispatch: this must come back as "".
		fmt.Fprint(w, "data: unnamed-again\n\n")
		flush()
	}))
	defer srv.Close()

	got, err := collectSSE(t, srv, nil)
	if !errors.Is(err, ErrStreamEnded) {
		t.Fatalf("terminal error = %v, want ErrStreamEnded", err)
	}

	want := []SSEEvent{
		{Event: "", Data: "aGVsbG8K"},
		{Event: "", Data: "one\ntwo\nthree"},
		{Event: "overflow", Data: `{"dropped":7}`},
		{Event: "", Data: "after-noise"},
		{Event: "", Data: "no-space"},
		{Event: "", Data: "unnamed-again"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

// TestStreamSSE_CRLFAndTrailingPartialEvent covers \r\n line endings and the
// spec rule that an event never terminated by a blank line is discarded at
// end of stream (no half-event is ever dispatched).
func TestStreamSSE_CRLFAndTrailingPartialEvent(t *testing.T) {
	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, "data: crlf-line\r\n\r\n")
		fmt.Fprint(w, "data: never-terminated\n")
		flush()
	}))
	defer srv.Close()

	got, err := collectSSE(t, srv, nil)
	if !errors.Is(err, ErrStreamEnded) {
		t.Fatalf("terminal error = %v, want ErrStreamEnded", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1 (the unterminated event must be discarded): %#v", len(got), got)
	}
	if got[0] != (SSEEvent{Data: "crlf-line"}) {
		t.Errorf("event = %#v, want Data=%q with no trailing \\r", got[0], "crlf-line")
	}
}

// --- request shape (R4) -------------------------------------------------

// TestStreamSSE_RequestHeadersAndQuery pins R4's wire contract: the stream
// GET carries Authorization: Bearer (the hub's readAccessToken honors the
// header, unlike browser EventSource) and Accept: text/event-stream, and
// query parameters are passed through unchanged.
func TestStreamSSE_RequestHeadersAndQuery(t *testing.T) {
	var (
		mu                                              sync.Mutex
		gotAuth, gotAccept, gotPath, gotGrep, gotMethod string
	)
	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotMethod = r.Method
		gotPath = r.URL.Query().Get("path")
		gotGrep = r.URL.Query().Get("grep")
		mu.Unlock()
		fmt.Fprint(w, "data: x\n\n")
		flush()
	}))
	defer srv.Close()

	query := url.Values{"path": []string{"/var/log/syslog"}, "grep": []string{"panic"}}
	if _, err := collectSSE(t, srv, query); !errors.Is(err, ErrStreamEnded) {
		t.Fatalf("terminal error = %v, want ErrStreamEnded", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok")
	}
	if gotAccept != "text/event-stream" {
		t.Errorf("Accept = %q, want %q", gotAccept, "text/event-stream")
	}
	if gotPath != "/var/log/syslog" {
		t.Errorf("path param = %q, want %q", gotPath, "/var/log/syslog")
	}
	if gotGrep != "panic" {
		t.Errorf("grep param = %q, want %q", gotGrep, "panic")
	}
}

// TestStreamSSE_NoTokenOmitsAuthorization guards the same
// "empty token → no header" rule the rest of the client follows.
func TestStreamSSE_NoTokenOmitsAuthorization(t *testing.T) {
	var (
		mu      sync.Mutex
		gotAuth string
	)
	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		flush()
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	_ = c.StreamSSE(context.Background(), "/api/stream", nil, func(SSEEvent) error { return nil })

	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty when no token is configured", gotAuth)
	}
}

// --- bounded buffer (Constitution IV) -----------------------------------

// TestStreamSSE_OversizedLineBounded verifies a single absurdly long
// `data:` line is rejected with a distinct, identifiable error rather than
// being buffered into an OOM or silently truncated.
func TestStreamSSE_OversizedLineBounded(t *testing.T) {
	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, "data: fine\n\n")
		flush()
		fmt.Fprint(w, "data: ")
		fmt.Fprint(w, strings.Repeat("A", 2*MaxSSEEventBytes))
		fmt.Fprint(w, "\n\n")
		flush()
	}))
	defer srv.Close()

	got, err := collectSSE(t, srv, nil)
	if !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("error = %v, want ErrEventTooLarge", err)
	}
	if errors.Is(err, ErrStreamEnded) {
		t.Error("an over-long line must not be reported as a clean stream end")
	}
	// The events delivered before the oversized line still count.
	if len(got) != 1 || got[0].Data != "fine" {
		t.Errorf("events before the oversized line = %#v, want exactly [{Data:fine}]", got)
	}
	if code := cmdutil.Code(err); code == cmdutil.ExitOK {
		t.Errorf("Code(err) = %d, want a non-zero exit code", code)
	}
}

// TestStreamSSE_OversizedAccumulatedEventBounded covers the other unbounded
// path: many individually-small `data:` lines inside one never-terminated
// event. The accumulated buffer must be capped too.
func TestStreamSSE_OversizedAccumulatedEventBounded(t *testing.T) {
	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		chunk := "data: " + strings.Repeat("B", 64*1024) + "\n"
		for i := 0; i < 64; i++ { // 4 MiB of data lines, none over the per-line cap
			if _, err := fmt.Fprint(w, chunk); err != nil {
				return
			}
		}
		flush()
	}))
	defer srv.Close()

	_, err := collectSSE(t, srv, nil)
	if !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("error = %v, want ErrEventTooLarge", err)
	}
}

// TestStreamSSE_MaxEventBytesIsOneMiB pins R4's documented 1 MiB cap.
func TestStreamSSE_MaxEventBytesIsOneMiB(t *testing.T) {
	if MaxSSEEventBytes != 1<<20 {
		t.Errorf("MaxSSEEventBytes = %d, want %d (1 MiB, per research.md R4)", MaxSSEEventBytes, 1<<20)
	}
}

// --- termination modes --------------------------------------------------

// TestStreamSSE_CleanServerCloseIsDistinct covers a hub that ends the
// response normally: the caller must be able to tell this apart from a
// transport failure (the log tail never ends voluntarily, so the command
// layer turns this into its "unexpected close" notice).
func TestStreamSSE_CleanServerCloseIsDistinct(t *testing.T) {
	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, "data: only\n\n")
		flush()
	}))
	defer srv.Close()

	got, err := collectSSE(t, srv, nil)
	if !errors.Is(err, ErrStreamEnded) {
		t.Fatalf("error = %v, want ErrStreamEnded", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if cmdutil.Code(err) == cmdutil.ExitConn {
		t.Error("a clean server close must not be pre-classified as a connectivity error; the command layer decides")
	}
}

// TestStreamSSE_MidStreamNetworkErrorIsDistinct covers a connection torn
// down mid-body (no chunked terminator). This must NOT look like a clean
// end, and must carry the connectivity exit code (R8: exit 6).
func TestStreamSSE_MidStreamNetworkErrorIsDistinct(t *testing.T) {
	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, "data: before-the-drop\n\n")
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
		_ = conn.Close() // abrupt drop: no terminating chunk
	}))
	defer srv.Close()

	got, err := collectSSE(t, srv, nil)
	if err == nil {
		t.Fatal("expected an error after an abrupt connection drop")
	}
	if errors.Is(err, ErrStreamEnded) {
		t.Fatalf("a mid-stream drop must be distinguishable from a clean end; got %v", err)
	}
	if code := cmdutil.Code(err); code != cmdutil.ExitConn {
		t.Errorf("Code(err) = %d, want %d (ExitConn); err = %v", code, cmdutil.ExitConn, err)
	}
	if len(got) != 1 || got[0].Data != "before-the-drop" {
		t.Errorf("events before the drop = %#v, want exactly [{Data:before-the-drop}]", got)
	}
}

// TestStreamSSE_ContextCancellationStopsCleanly covers Ctrl-C: cancelling
// mid-stream returns a context error (not a clean end, not a transport
// error) promptly, and leaves no goroutine behind.
func TestStreamSSE_ContextCancellationStopsCleanly(t *testing.T) {
	before := goroutineBaseline()

	blocked := make(chan struct{})
	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, "data: first\n\n")
		flush()
		<-r.Context().Done() // hold the stream open like a real tail
		close(blocked)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := newTestClient(srv, "tok")
	seen := 0
	done := make(chan error, 1)
	go func() {
		done <- c.StreamSSE(ctx, "/api/stream", nil, func(ev SSEEvent) error {
			seen++
			cancel() // Ctrl-C arrives while the stream is live
			return nil
		})
	}()

	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("StreamSSE did not return within 10s of context cancellation")
	}

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want one wrapping context.Canceled", err)
	}
	if errors.Is(err, ErrStreamEnded) {
		t.Error("cancellation must not be reported as a clean server-side end")
	}
	if seen != 1 {
		t.Errorf("callback invocations = %d, want 1", seen)
	}

	<-blocked
	srv.Close()
	assertNoGoroutineLeak(t, before)
}

// TestStreamSSE_CallbackErrorStopsStream verifies a caller-side error
// terminates the stream immediately and is surfaced verbatim.
func TestStreamSSE_CallbackErrorStopsStream(t *testing.T) {
	before := goroutineBaseline()

	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		for i := 0; i < 100; i++ {
			if _, err := fmt.Fprintf(w, "data: line-%d\n\n", i); err != nil {
				return
			}
			flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	sentinel := errors.New("caller said stop")
	c := newTestClient(srv, "tok")
	seen := 0
	err := c.StreamSSE(context.Background(), "/api/stream", nil, func(ev SSEEvent) error {
		seen++
		if seen == 2 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the caller's sentinel", err)
	}
	if seen != 2 {
		t.Errorf("callback invocations = %d, want 2 (stream must stop on the first callback error)", seen)
	}

	srv.Close()
	assertNoGoroutineLeak(t, before)
}

// TestStreamSSE_NonOKStatusMapsToExitCode verifies the stream GET reuses the
// client's shared status→exit-code mapping instead of inventing its own.
func TestStreamSSE_NonOKStatusMapsToExitCode(t *testing.T) {
	cases := []struct {
		status int
		want   int
	}{
		{http.StatusUnauthorized, cmdutil.ExitAuth},
		{http.StatusForbidden, cmdutil.ExitForbidden},
		{http.StatusNotFound, cmdutil.ExitNotFound},
		{http.StatusTooManyRequests, cmdutil.ExitRateLimited},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, `{"error":"nope"}`)
			}))
			defer srv.Close()

			called := false
			c := newTestClient(srv, "tok")
			err := c.StreamSSE(context.Background(), "/api/stream", nil, func(SSEEvent) error {
				called = true
				return nil
			})
			if err == nil {
				t.Fatal("expected an error for a non-2xx stream response")
			}
			if called {
				t.Error("callback must never fire for a non-2xx response")
			}
			if got := cmdutil.Code(err); got != tc.want {
				t.Errorf("Code(err) = %d, want %d", got, tc.want)
			}
			if !strings.Contains(err.Error(), "nope") {
				t.Errorf("error = %q, want the hub's message preserved", err.Error())
			}
		})
	}
}

// TestStreamSSE_NilCallback guards against a nil callback panicking.
func TestStreamSSE_NilCallback(t *testing.T) {
	srv := httptest.NewServer(sseHandler(func(w http.ResponseWriter, r *http.Request, flush func()) {
		fmt.Fprint(w, "data: x\n\n")
		flush()
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.StreamSSE(context.Background(), "/api/stream", nil, nil)
	if err == nil {
		t.Fatal("expected an error for a nil callback, got nil")
	}
	if errors.Is(err, ErrStreamEnded) {
		t.Errorf("nil callback must be an argument error, not a clean end; got %v", err)
	}
}

// TestStreamSSE_UnreachableHubIsConnectivityError pins the transport-error
// mapping for a stream that never connects.
func TestStreamSSE_UnreachableHubIsConnectivityError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close() // nothing is listening anymore

	c := NewClient(base, "tok")
	err := c.StreamSSE(context.Background(), "/api/stream", nil, func(SSEEvent) error { return nil })
	if got := cmdutil.Code(err); got != cmdutil.ExitConn {
		t.Errorf("Code(err) = %d, want %d (ExitConn); err = %v", got, cmdutil.ExitConn, err)
	}
}

// --- goroutine-leak helpers ---------------------------------------------

func goroutineBaseline() int {
	runtime.GC()
	return runtime.NumGoroutine()
}

// assertNoGoroutineLeak fails if the goroutine count stays above the
// baseline (plus slack for the test server's own teardown) after a grace
// period. StreamSSE must not spawn anything the caller can't join.
func assertNoGoroutineLeak(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var after int
	for time.Now().Before(deadline) {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= before+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("goroutine count = %d after streaming, want <= %d (baseline %d): possible leak", after, before+2, before)
}
