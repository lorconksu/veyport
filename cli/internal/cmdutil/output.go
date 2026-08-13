package cmdutil

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// Printer centralizes vey's output discipline: stdout carries payload data
// only; stderr carries diagnostics, warnings, progress, and errors. With
// JSON mode enabled, stdout is exactly one JSON document (or JSON-lines for
// streams) and errors are {"error","code"} on stderr (contracts/cli-commands.md
// "Global behavior" / research.md R8).
type Printer struct {
	Out  io.Writer
	Err  io.Writer
	JSON bool
}

// NewPrinter builds a Printer bound to the given stdout/stderr writers.
func NewPrinter(out, err io.Writer, jsonMode bool) *Printer {
	return &Printer{Out: out, Err: err, JSON: jsonMode}
}

// HumanFunc renders v as human-readable text to w. Implementations must not
// write anything to stderr; that stream is reserved for diagnostics.
type HumanFunc func(w io.Writer, v any) error

// jsonErrorPayload is the exact JSON error shape emitted on stderr in JSON
// mode: {"error": "...", "code": <n>}.
type jsonErrorPayload struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

// Payload writes v to stdout: as a single JSON document when the Printer is
// in JSON mode, otherwise via human, the caller-supplied human-readable
// renderer. If human is nil in non-JSON mode, v is rendered with fmt's
// default formatting followed by a newline.
func (p *Printer) Payload(v any, human HumanFunc) error {
	if p.JSON {
		enc := json.NewEncoder(p.Out)
		return enc.Encode(v)
	}
	if human != nil {
		return human(p.Out, v)
	}
	_, err := fmt.Fprintf(p.Out, "%v\n", v)
	return err
}

// PayloadRaw copies r to stdout verbatim, for binary-safe passthrough
// streams (e.g. `vey files cat`, `vey audit export`) that have no JSON
// variant beyond the shared error shape. JSON mode does not alter this
// output — the contract treats it as a no-op passthrough.
func (p *Printer) PayloadRaw(r io.Reader) (int64, error) {
	return io.Copy(p.Out, r)
}

// Errorf writes a plain diagnostic (warning, progress note, informational
// message) to stderr. It is never JSON-wrapped, in either mode: these are
// not command failures and carry no exit code. Callers must never pass
// request/response bodies or credentials to Errorf.
func (p *Printer) Errorf(format string, args ...any) {
	fmt.Fprintf(p.Err, format, args...)
}

// Error reports a command failure to stderr, using err's mapped exit code
// (see Code). In JSON mode it emits the exact shape {"error","code"} as a
// single JSON document; otherwise it writes a plain "Error: <message>" line.
// Callers must never pass request/response bodies or credentials in err.
func (p *Printer) Error(err error) {
	if err == nil {
		return
	}
	if p.JSON {
		payload := jsonErrorPayload{Error: err.Error(), Code: Code(err)}
		enc := json.NewEncoder(p.Err)
		_ = enc.Encode(payload)
		return
	}
	fmt.Fprintf(p.Err, "Error: %s\n", err.Error())
}

// IsTTY reports whether f is attached to an interactive terminal. Used to
// decide whether interactive-only steps (e.g. login prompts) may run, per
// the "no command ever prompts when stdin is not a TTY" contract.
func IsTTY(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
