package api

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// MaxSSEEventBytes bounds both a single SSE line and the total `data:`
// payload accumulated for one event (research.md R4: "capped buffer
// (1 MiB)"). Nothing in this reader grows without a limit — a hub (or
// anything impersonating one) that never emits a newline or never
// terminates an event costs the CLI 1 MiB, not the machine's memory
// (Constitution IV).
const MaxSSEEventBytes = 1 << 20

// sseInitialBufBytes is the scanner's starting buffer. It grows on demand
// up to MaxSSEEventBytes, so the common case (log lines of a few hundred
// bytes) never allocates the full cap.
const sseInitialBufBytes = 64 * 1024

var (
	// ErrStreamEnded reports that the server closed the stream cleanly:
	// the response body reached EOF with the HTTP framing intact. This is
	// deliberately *not* pre-classified as a connectivity failure, because
	// whether a clean end is expected depends on the endpoint. For the log
	// tail it never is — the hub's handleTailLog only returns when the
	// client disconnects or the agent session dies — so `vey logs tail`
	// turns this into its "unexpected close" notice (exit 6). A finite
	// stream would instead treat it as success.
	ErrStreamEnded = errors.New("sse: server closed the stream")

	// ErrEventTooLarge reports that a single line, or the accumulated
	// `data:` payload of one event, exceeded MaxSSEEventBytes. Surfaced as
	// an error rather than silently truncating (which would corrupt log
	// output) or buffering without limit (which would be the OOM this cap
	// exists to prevent).
	ErrEventTooLarge = errors.New("sse: event exceeds the maximum buffered size")
)

// SSEEvent is one dispatched server-sent event.
//
// Event is the `event:` field ("" for the default, unnamed event type) and
// Data is the concatenated `data:` fields with a single "\n" between
// consecutive lines, per the SSE spec. No decoding is applied here: the
// framing layer is deliberately payload-agnostic, and the hub's own
// encoding (base64 for log frames, JSON for `event: overflow`) is decoded by
// the command that knows which endpoint it asked for.
type SSEEvent struct {
	Event string
	Data  string
}

// StreamSSE issues a GET to path and consumes the response as a
// server-sent-event stream, invoking fn once per dispatched event
// (research.md R4: stdlib net/http plus a bounded bufio scanner, no
// dependency).
//
// The request carries `Accept: text/event-stream` and the client's
// `Authorization: Bearer` credential — the hub's readAccessToken honors the
// header, so the CLI is not subject to the browser EventSource limitation
// that forces the web app onto cookies.
//
// StreamSSE always returns a non-nil error, and the four ways a stream can
// end are each distinguishable:
//
//   - ErrStreamEnded — the server closed the stream cleanly.
//   - ctx.Err() (errors.Is → context.Canceled / DeadlineExceeded) — the
//     caller cancelled, e.g. Ctrl-C. This is the clean-stop path.
//   - ErrEventTooLarge — the 1 MiB cap was hit.
//   - a connectivity error (cmdutil.ExitConn) — the connection dropped
//     mid-body, or was never established.
//
// plus whatever fn itself returns, propagated verbatim so a caller can stop
// the stream on its own terms. Non-2xx responses go through the client's
// shared status→exit-code mapping before any event is dispatched.
//
// StreamSSE runs entirely on the calling goroutine and starts none of its
// own: when it returns, nothing of its making is still running, and the
// response body is closed.
func (c *Client) StreamSSE(ctx context.Context, path string, query url.Values, fn func(SSEEvent) error) error {
	if fn == nil {
		return cmdutil.NewCodedError(cmdutil.ExitError, errors.New("sse: no event handler supplied"))
	}

	req, err := c.newRequest(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return err
	}
	// Override the JSON Accept newRequest sets for the REST surface.
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return mapTransportErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mapStatusErr(resp)
	}

	return scanSSE(ctx, resp.Body, fn)
}

// scanSSE runs the SSE parse loop over r. Split out from StreamSSE so the
// framing rules are testable independently of the transport.
func scanSSE(ctx context.Context, r io.Reader, fn func(SSEEvent) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, sseInitialBufBytes), MaxSSEEventBytes)

	var buf sseEventBuf

	for scanner.Scan() {
		// bufio.ScanLines already strips a trailing "\r", so CRLF and LF
		// framing are handled identically.
		line := scanner.Text()

		if line == "" {
			// Blank line: dispatch, if there is anything to dispatch.
			ev, dispatch := buf.take()
			if !dispatch {
				continue
			}
			if err := fn(ev); err != nil {
				return err
			}
			continue
		}

		if strings.HasPrefix(line, ":") {
			continue // comment / keep-alive
		}

		if err := buf.apply(parseSSEField(line)); err != nil {
			return err
		}
	}

	return scanEndErr(ctx, scanner)
}

// sseEventBuf accumulates the fields of the event currently being parsed.
// The zero value is the "between events" state.
type sseEventBuf struct {
	eventName string
	data      strings.Builder
	hasData   bool
}

// take reports the event a blank line just terminated, resetting the buffer
// for the next one. Per the SSE spec an event with no `data:` field at all is
// not dispatched (ok is false), and the event-type buffer resets either way.
func (b *sseEventBuf) take() (ev SSEEvent, ok bool) {
	if !b.hasData {
		b.eventName = ""
		return SSEEvent{}, false
	}
	ev = SSEEvent{Event: b.eventName, Data: b.data.String()}
	b.eventName = ""
	b.data.Reset()
	b.hasData = false
	return ev, true
}

// apply folds one parsed field into the buffer.
func (b *sseEventBuf) apply(field, value string) error {
	switch field {
	case "data":
		return b.appendData(value)
	case "event":
		b.eventName = value
	default:
		// "id", "retry", and any unknown field are ignored — the CLI
		// never reconnects, so there is no last-event-id to track, and
		// forward compatibility requires ignoring what it doesn't know.
	}
	return nil
}

// appendData accumulates one `data:` field, joining consecutive ones with the
// single "\n" the spec mandates. The join byte is charged against the cap
// before the decision is made, so MaxSSEEventBytes bounds what is actually
// retained rather than trailing it by a byte per line.
func (b *sseEventBuf) appendData(value string) error {
	want := len(value)
	if b.hasData {
		want++
	}
	if b.data.Len()+want > MaxSSEEventBytes {
		return cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf(
			"%w: accumulated data exceeds %d bytes", ErrEventTooLarge, MaxSSEEventBytes))
	}
	if b.hasData {
		b.data.WriteByte('\n')
	}
	b.data.WriteString(value)
	b.hasData = true
	return nil
}

// parseSSEField splits one non-blank, non-comment line into its field name
// and value.
func parseSSEField(line string) (field, value string) {
	name, rest, found := strings.Cut(line, ":")
	if !found {
		// A bare field name with no colon: an empty value.
		return line, ""
	}
	// Exactly one leading space is stripped, per the spec.
	return name, strings.TrimPrefix(rest, " ")
}

// scanEndErr classifies why the scan loop stopped, keeping the four
// termination modes StreamSSE documents distinguishable.
func scanEndErr(ctx context.Context, scanner *bufio.Scanner) error {
	// Cancellation wins over whatever error the aborted read produced: a
	// cancelled transport surfaces as "context canceled", "use of closed
	// network connection", or a bare EOF depending on timing, and the
	// caller must see the same clean-stop signal in every case.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf(
				"%w: a single line exceeds %d bytes", ErrEventTooLarge, MaxSSEEventBytes))
		}
		// Anything else is the connection failing under us — including the
		// truncated-body case (io.ErrUnexpectedEOF), which is precisely
		// what distinguishes a dropped connection from the clean EOF below.
		return cmdutil.NewConnError(fmt.Errorf("stream interrupted: %w", err))
	}

	// Clean EOF. Any partially-accumulated event is discarded, per spec.
	return ErrStreamEnded
}
