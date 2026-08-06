package cmdutil

import (
	"errors"
	"fmt"
	"testing"
)

// TestExitConstants pins the exact taxonomy values from research.md R8.
// These are part of the CLI's documented scripting contract — a value
// changing here is a breaking change.
func TestExitConstants(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"ExitOK", ExitOK, 0},
		{"ExitError", ExitError, 1},
		{"ExitUsage", ExitUsage, 2},
		{"ExitAuth", ExitAuth, 3},
		{"ExitForbidden", ExitForbidden, 4},
		{"ExitNotFound", ExitNotFound, 5},
		{"ExitConn", ExitConn, 6},
		{"ExitRateLimited", ExitRateLimited, 7},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
			}
		})
	}
}

// TestCode_Constructors verifies every New*Error helper maps through Code()
// to its documented exit code, and that the underlying error message and
// errors.Is/As chain survive wrapping.
func TestCode_Constructors(t *testing.T) {
	base := errors.New("boom")

	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, ExitOK},
		{"plain unknown error", base, ExitError},
		{"fmt-wrapped unknown error", fmt.Errorf("context: %w", base), ExitError},
		{"NewCodedError arbitrary", NewCodedError(ExitUsage, base), ExitUsage},
		{"NewUsageError", NewUsageError(base), ExitUsage},
		{"NewAuthError", NewAuthError(base), ExitAuth},
		{"NewForbiddenError", NewForbiddenError(base), ExitForbidden},
		{"NewNotFoundError", NewNotFoundError(base), ExitNotFound},
		{"NewConnError", NewConnError(base), ExitConn},
		{"NewRateLimitedError", NewRateLimitedError(base), ExitRateLimited},
		{"wrapped CodedError still resolves via errors.As", fmt.Errorf("outer: %w", NewAuthError(base)), ExitAuth},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Code(c.err); got != c.want {
				t.Errorf("Code(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}

// TestCodedError_ErrorAndUnwrap verifies CodedError delegates its message
// and unwraps to the underlying error for errors.Is/errors.As chains.
func TestCodedError_ErrorAndUnwrap(t *testing.T) {
	base := errors.New("bad credentials")
	ce := NewAuthError(base)

	if got := ce.Error(); got != "bad credentials" {
		t.Errorf("Error() = %q, want %q", got, "bad credentials")
	}
	if !errors.Is(ce, base) {
		t.Error("errors.Is(ce, base) = false, want true (Unwrap should expose base)")
	}

	var target *CodedError
	if !errors.As(fmt.Errorf("wrapped: %w", ce), &target) {
		t.Fatal("errors.As failed to find *CodedError in wrapped chain")
	}
	if target.Code != ExitAuth {
		t.Errorf("recovered CodedError.Code = %d, want %d", target.Code, ExitAuth)
	}
}

// TestCodedError_NilErr guards against a nil-Err CodedError panicking.
func TestCodedError_NilErr(t *testing.T) {
	ce := &CodedError{Code: ExitError}
	if got := ce.Error(); got != "" {
		t.Errorf("Error() on nil-Err CodedError = %q, want empty string", got)
	}
}
