package cmdutil

import "errors"

// Exit code taxonomy (spec 004-cli-connector, research.md R8). Stable and
// documented for scripting (US2): distinguishes "re-auth" from "no access"
// from "retry later". Centralized here and pinned by contract tests.
const (
	// ExitOK indicates success.
	ExitOK = 0
	// ExitError indicates a generic/unexpected error.
	ExitError = 1
	// ExitUsage indicates a usage error (bad flags/args).
	ExitUsage = 2
	// ExitAuth indicates an authentication failure: invalid/expired
	// credentials, including exhausted refresh.
	ExitAuth = 3
	// ExitForbidden indicates permission denied (403 with valid auth).
	ExitForbidden = 4
	// ExitNotFound indicates an unknown server/path.
	ExitNotFound = 5
	// ExitConn indicates a connectivity failure: dial/TLS/timeout/stream-drop.
	ExitConn = 6
	// ExitRateLimited indicates the request was rate-limited (429),
	// surfaced without client retry.
	ExitRateLimited = 7
)

// CodedError pairs an exit code with an underlying error. Use the New*Error
// constructors to build one, and Code to recover the intended exit code from
// any error value (including ones that are not a CodedError).
type CodedError struct {
	Code int
	Err  error
}

// Error implements the error interface, delegating to the wrapped error.
func (e *CodedError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// Unwrap allows errors.Is/errors.As to see through to the wrapped error.
func (e *CodedError) Unwrap() error {
	return e.Err
}

// NewCodedError builds a CodedError with an arbitrary exit code.
func NewCodedError(code int, err error) *CodedError {
	return &CodedError{Code: code, Err: err}
}

// NewUsageError builds a CodedError mapped to ExitUsage.
func NewUsageError(err error) *CodedError {
	return &CodedError{Code: ExitUsage, Err: err}
}

// NewAuthError builds a CodedError mapped to ExitAuth.
func NewAuthError(err error) *CodedError {
	return &CodedError{Code: ExitAuth, Err: err}
}

// NewForbiddenError builds a CodedError mapped to ExitForbidden.
func NewForbiddenError(err error) *CodedError {
	return &CodedError{Code: ExitForbidden, Err: err}
}

// NewNotFoundError builds a CodedError mapped to ExitNotFound.
func NewNotFoundError(err error) *CodedError {
	return &CodedError{Code: ExitNotFound, Err: err}
}

// NewConnError builds a CodedError mapped to ExitConn.
func NewConnError(err error) *CodedError {
	return &CodedError{Code: ExitConn, Err: err}
}

// NewRateLimitedError builds a CodedError mapped to ExitRateLimited.
func NewRateLimitedError(err error) *CodedError {
	return &CodedError{Code: ExitRateLimited, Err: err}
}

// Code returns the exit code intended for err. nil maps to ExitOK; a
// *CodedError (anywhere in the chain, via errors.As) yields its Code; any
// other non-nil error maps to ExitError.
func Code(err error) int {
	if err == nil {
		return ExitOK
	}
	var coded *CodedError
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ExitError
}
