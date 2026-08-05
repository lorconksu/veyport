package cmdutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

type samplePayload struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
}

// TestPayload_JSONMode verifies JSON-mode Payload writes exactly one
// parseable JSON document to stdout and nothing to stderr.
func TestPayload_JSONMode(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := NewPrinter(&out, &errBuf, true)

	v := samplePayload{Name: "web-1", ID: 42}
	if err := p.Payload(v, nil); err != nil {
		t.Fatalf("Payload returned error: %v", err)
	}

	if errBuf.Len() != 0 {
		t.Errorf("stderr not empty: %q", errBuf.String())
	}

	// Must be a single parseable JSON document.
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	var got samplePayload
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (raw: %q)", err, out.String())
	}
	if got != v {
		t.Errorf("decoded payload = %+v, want %+v", got, v)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Errorf("stdout contained more than one JSON document (raw: %q)", out.String())
	}
}

// TestPayload_HumanMode_CustomRenderer verifies non-JSON mode uses the
// supplied HumanFunc instead of JSON encoding.
func TestPayload_HumanMode_CustomRenderer(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := NewPrinter(&out, &errBuf, false)

	v := samplePayload{Name: "web-1", ID: 42}
	human := func(w io.Writer, v any) error {
		sp := v.(samplePayload)
		_, err := io.WriteString(w, "NAME  ID\n"+sp.Name+"  "+"42\n")
		return err
	}

	if err := p.Payload(v, human); err != nil {
		t.Fatalf("Payload returned error: %v", err)
	}
	if !strings.Contains(out.String(), "NAME  ID") {
		t.Errorf("stdout = %q, want human-rendered table header", out.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr not empty: %q", errBuf.String())
	}
	// Must NOT be JSON in human mode.
	var probe samplePayload
	if err := json.Unmarshal(out.Bytes(), &probe); err == nil {
		t.Errorf("human-mode output unexpectedly parsed as JSON: %q", out.String())
	}
}

// TestPayload_HumanMode_NilRenderer verifies the fmt fallback is used when
// no HumanFunc is supplied outside JSON mode.
func TestPayload_HumanMode_NilRenderer(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := NewPrinter(&out, &errBuf, false)

	if err := p.Payload("plain text", nil); err != nil {
		t.Fatalf("Payload returned error: %v", err)
	}
	if out.String() != "plain text\n" {
		t.Errorf("stdout = %q, want %q", out.String(), "plain text\n")
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr not empty: %q", errBuf.String())
	}
}

// TestPayloadRaw verifies binary-safe passthrough copies bytes verbatim to
// stdout regardless of JSON mode, and never touches stderr.
func TestPayloadRaw(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		var out, errBuf bytes.Buffer
		p := NewPrinter(&out, &errBuf, jsonMode)

		data := []byte{0x00, 0x01, 0xFF, 'h', 'i', 0x00}
		n, err := p.PayloadRaw(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("PayloadRaw returned error: %v", err)
		}
		if n != int64(len(data)) {
			t.Errorf("PayloadRaw copied %d bytes, want %d", n, len(data))
		}
		if !bytes.Equal(out.Bytes(), data) {
			t.Errorf("stdout = %v, want %v", out.Bytes(), data)
		}
		if errBuf.Len() != 0 {
			t.Errorf("stderr not empty: %q", errBuf.String())
		}
	}
}

// TestError_JSONMode_ExactShape locks the JSON error shape on stderr to
// exactly {"error": "...", "code": <n>} (contracts/cli-commands.md, R8).
func TestError_JSONMode_ExactShape(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
	}{
		{"generic", errors.New("boom"), ExitError},
		{"usage", NewUsageError(errors.New("missing argument")), ExitUsage},
		{"auth", NewAuthError(errors.New("session expired")), ExitAuth},
		{"forbidden", NewForbiddenError(errors.New("access denied")), ExitForbidden},
		{"not_found", NewNotFoundError(errors.New("no such server")), ExitNotFound},
		{"conn", NewConnError(errors.New("dial tcp: connection refused")), ExitConn},
		{"rate_limited", NewRateLimitedError(errors.New("try again later")), ExitRateLimited},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			p := NewPrinter(&out, &errBuf, true)

			p.Error(c.err)

			if out.Len() != 0 {
				t.Errorf("stdout not empty on error path: %q", out.String())
			}

			// Exact-match the field set and values by decoding into a map,
			// so unexpected extra fields (e.g. leaked stack traces) fail.
			var raw map[string]any
			if err := json.Unmarshal(errBuf.Bytes(), &raw); err != nil {
				t.Fatalf("stderr is not valid JSON: %v (raw: %q)", err, errBuf.String())
			}
			if len(raw) != 2 {
				t.Errorf("json error object has %d fields, want exactly 2 (error, code): %v", len(raw), raw)
			}
			gotMsg, ok := raw["error"].(string)
			if !ok || gotMsg != c.err.Error() {
				t.Errorf("error field = %v, want %q", raw["error"], c.err.Error())
			}
			gotCode, ok := raw["code"].(float64)
			if !ok || int(gotCode) != c.code {
				t.Errorf("code field = %v, want %d", raw["code"], c.code)
			}

			// Exact string shape too (field order is stable from the
			// struct definition), single line, newline-terminated.
			want := `{"error":"` + c.err.Error() + `","code":` + strconv.Itoa(c.code) + "}\n"
			if errBuf.String() != want {
				t.Errorf("stderr = %q, want %q", errBuf.String(), want)
			}
		})
	}
}

// TestError_HumanMode verifies non-JSON mode writes a plain human-readable
// line to stderr, with nothing on stdout.
func TestError_HumanMode(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := NewPrinter(&out, &errBuf, false)

	p.Error(NewNotFoundError(errors.New("no such server: web-9")))

	if out.Len() != 0 {
		t.Errorf("stdout not empty: %q", out.String())
	}
	want := "Error: no such server: web-9\n"
	if errBuf.String() != want {
		t.Errorf("stderr = %q, want %q", errBuf.String(), want)
	}
	// Human mode must not leak JSON.
	if strings.Contains(errBuf.String(), `"code"`) {
		t.Errorf("human-mode error output looks JSON-shaped: %q", errBuf.String())
	}
}

// TestError_Nil verifies Error is a no-op for a nil error in both modes.
func TestError_Nil(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		var out, errBuf bytes.Buffer
		p := NewPrinter(&out, &errBuf, jsonMode)
		p.Error(nil)
		if out.Len() != 0 || errBuf.Len() != 0 {
			t.Errorf("jsonMode=%v: Error(nil) wrote output: stdout=%q stderr=%q", jsonMode, out.String(), errBuf.String())
		}
	}
}

// TestErrorf_PlainDiagnostic verifies Errorf writes plain (non-JSON)
// diagnostics to stderr in both modes, and never touches stdout.
func TestErrorf_PlainDiagnostic(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		var out, errBuf bytes.Buffer
		p := NewPrinter(&out, &errBuf, jsonMode)

		p.Errorf("warning: %s is deprecated\n", "--foo")

		if out.Len() != 0 {
			t.Errorf("jsonMode=%v: stdout not empty: %q", jsonMode, out.String())
		}
		want := "warning: --foo is deprecated\n"
		if errBuf.String() != want {
			t.Errorf("jsonMode=%v: stderr = %q, want %q", jsonMode, errBuf.String(), want)
		}
	}
}

// TestStdoutStderrSeparation is a combined discipline check: a payload
// write followed by a diagnostic must land exclusively on their respective
// streams, never mixed.
func TestStdoutStderrSeparation(t *testing.T) {
	var out, errBuf bytes.Buffer
	p := NewPrinter(&out, &errBuf, true)

	if err := p.Payload(samplePayload{Name: "x", ID: 1}, nil); err != nil {
		t.Fatalf("Payload error: %v", err)
	}
	p.Errorf("progress: fetching page 2\n")

	if strings.Contains(out.String(), "progress") {
		t.Errorf("diagnostic leaked into stdout: %q", out.String())
	}
	if strings.Contains(errBuf.String(), `"name"`) {
		t.Errorf("payload leaked into stderr: %q", errBuf.String())
	}
}

// TestIsTTY_NonTerminal verifies IsTTY returns false for a plain pipe,
// matching the "no command ever prompts when stdin is not a TTY" contract
// (files/pipes are the common non-interactive case in CI and scripting).
func TestIsTTY_NonTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if IsTTY(r) {
		t.Error("IsTTY(pipe read end) = true, want false")
	}
	if IsTTY(w) {
		t.Error("IsTTY(pipe write end) = true, want false")
	}
}

// TestIsTTY_DevNull verifies IsTTY returns false for /dev/null, a common
// stand-in for redirected/non-interactive stdin.
func TestIsTTY_DevNull(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer f.Close()

	if IsTTY(f) {
		t.Error("IsTTY(/dev/null) = true, want false")
	}
}
