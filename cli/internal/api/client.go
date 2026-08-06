// Package api implements the REST client used to talk to the veyport hub:
// Bearer-token injection, error mapping, SSE streaming, and response types.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// maxErrorBodyBytes bounds how much of a non-2xx response body is read when
// hunting for a {"error": "..."} envelope, guarding against a misbehaving or
// malicious server sending an unbounded body.
const maxErrorBodyBytes = 64 * 1024

// Client is a minimal REST client for the hub's /api surface. It injects
// Authorization: Bearer on every request when a token is set, uses the
// default (OS-trust-store) TLS verification with no skip-verify or custom-CA
// hook anywhere (R9), and never installs a cookie jar — the hub's Bearer
// path bypasses cookies/CSRF by design, and Set-Cookie headers on responses
// (e.g. from POST /api/auth/login/totp) are ignored.
type Client struct {
	// BaseURL is the hub's base URL, e.g. "https://hub.example.com". It is
	// stored without a trailing slash; callers pass API paths starting
	// with "/api/...".
	BaseURL string

	// Token is the bearer credential (access JWT or adt_ API token)
	// attached as "Authorization: Bearer <Token>". When empty, no
	// Authorization header is sent.
	Token string

	// HTTP is the underlying client. It has no cookie jar and uses the
	// default transport (nil), which means default Go TLS verification
	// against the OS trust store — never overridden here.
	HTTP *http.Client
}

// NewClient builds a Client for baseURL with the given bearer token (may be
// empty). The returned client has no cookie jar and does not customize TLS
// verification in any way.
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{
			// Jar intentionally left nil: no cookie jar (R9/contract:
			// "no cookies, no CSRF token" on the Bearer path).
			// Transport intentionally left nil: http.DefaultTransport,
			// i.e. default TLS verification against the OS trust store.
			// Do not add a Transport/TLSClientConfig here — that is
			// exactly the seam an --insecure/--ca-cert flag would use,
			// and R9 forbids both.
		},
	}
}

// Get issues a GET to path with the given query parameters and decodes the
// JSON response body into out (which may be nil to discard the body).
func (c *Client) Get(ctx context.Context, path string, query url.Values, out any) error {
	return c.do(ctx, http.MethodGet, path, query, nil, out)
}

// Post issues a POST to path with body marshaled as the JSON request body
// (body may be nil for an empty request) and decodes the JSON response into
// out (which may be nil to discard the body).
func (c *Client) Post(ctx context.Context, path string, body any, out any) error {
	return c.do(ctx, http.MethodPost, path, nil, body, out)
}

// GetStream issues a GET to path with the given query parameters and
// returns the raw response body for passthrough streaming (files cat, audit
// export, SSE log tail). The caller must Close the returned ReadCloser. On
// a non-2xx response, GetStream reads and closes the body itself and
// returns the mapped error.
func (c *Client) GetStream(ctx context.Context, path string, query url.Values) (io.ReadCloser, error) {
	req, err := c.newRequest(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, mapTransportErr(err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, mapStatusErr(resp)
	}

	return resp.Body, nil
}

// do performs a single request/response round trip and decodes a JSON body
// into out on success.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	req, err := c.newRequest(ctx, method, path, query, body)
	if err != nil {
		return err
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return mapTransportErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mapStatusErr(resp)
	}

	if out == nil {
		return nil
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
		return cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("decoding hub response: %w", err))
	}
	return nil
}

// newRequest builds an *http.Request against BaseURL+path, attaching the
// query string, JSON-encoding body when present, and injecting the Bearer
// Authorization header when Token is set. Cache-Control on the response is
// never consulted by this client (contract: "Cache-Control ignored").
func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, body any) (*http.Request, error) {
	full := c.BaseURL + path
	if len(query) > 0 {
		full += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("encoding request body: %w", err))
		}
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, full, bodyReader)
	if err != nil {
		return nil, cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("building request: %w", err))
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	return req, nil
}

// mapStatusErr maps a non-2xx HTTP response to the CLI's exit-code
// taxonomy (R8), preferring the hub's {"error": "..."} message when the
// body parses as one.
func mapStatusErr(resp *http.Response) error {
	limited := io.LimitReader(resp.Body, maxErrorBodyBytes)
	raw, _ := io.ReadAll(limited)

	msg := strings.TrimSpace(string(raw))
	var envelope errorResponse
	if len(raw) > 0 && json.Unmarshal(raw, &envelope) == nil && envelope.Error != "" {
		msg = envelope.Error
	}
	if msg == "" {
		msg = resp.Status
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return cmdutil.NewAuthError(errors.New(msg))
	case http.StatusForbidden:
		return cmdutil.NewForbiddenError(errors.New(msg))
	case http.StatusNotFound:
		return cmdutil.NewNotFoundError(errors.New(msg))
	case http.StatusTooManyRequests:
		return cmdutil.NewRateLimitedError(errors.New(msg))
	default:
		return cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("%s: %s", resp.Status, msg))
	}
}

// mapTransportErr maps a transport-level failure (dial/timeout/TLS) to the
// CLI's exit-code taxonomy. Every case here is exit-6 connectivity (R8);
// certificate-verification failures get a distinct message naming the
// problem and pointing at OS trust-store installation (R9 — the CLI offers
// no skip-verify/custom-CA flag, so the fix is always "install the hub's CA
// into the OS trust store").
func mapTransportErr(err error) error {
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return cmdutil.NewConnError(fmt.Errorf(
			"certificate verification failed: %w — the hub's certificate is not trusted by this system; if the hub uses a private/internal CA, install that CA into your operating system's trust store (vey does not support skipping certificate verification)",
			unknownAuthority,
		))
	}

	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		return cmdutil.NewConnError(fmt.Errorf(
			"certificate verification failed: %w — the hub's certificate is invalid or expired; install a valid certificate, or install the issuing CA into your operating system's trust store",
			certInvalid,
		))
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return cmdutil.NewConnError(fmt.Errorf(
			"certificate verification failed: %w — the hub's certificate does not match the hostname you connected to; check --hub/VEYPORT_HUB, or install the correct CA into your operating system's trust store",
			hostnameErr,
		))
	}

	var certVerification *tls.CertificateVerificationError
	if errors.As(err, &certVerification) {
		return cmdutil.NewConnError(fmt.Errorf(
			"certificate verification failed: %w — the hub's certificate could not be verified against your operating system's trust store; install the hub's CA certificate there (vey does not support skipping certificate verification)",
			certVerification,
		))
	}

	return cmdutil.NewConnError(fmt.Errorf("connecting to hub: %w", err))
}
