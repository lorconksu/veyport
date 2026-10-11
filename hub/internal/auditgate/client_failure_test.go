package auditgate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type observedBody struct {
	io.Reader
	closes int
}

func (b *observedBody) Close() error { b.closes++; return nil }

type faultReader struct {
	data []byte
	err  error
}

func (r *faultReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

func TestPreserveAttachmentFailureContracts(t *testing.T) {
	now := time.Now().UTC()
	want := []byte("sealed script")
	for _, tc := range []struct {
		name string
		data []byte
		err  error
	}{
		{"truncated", want[:3], io.EOF},
		{"overlong", append(append([]byte(nil), want...), 'x'), io.EOF},
		{"wrong_hash_at_eof", bytes.Repeat([]byte("x"), len(want)), io.EOF},
		{"read_error_after_prefix", want[:3], io.ErrUnexpectedEOF},
		{"read_error_at_exact_length", want, errors.New("source unavailable")},
		{"valid_final_read_with_eof", want, io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &observedBody{Reader: &faultReader{data: append([]byte(nil), tc.data...), err: tc.err}}
			requests := 0
			c := &Client{endpoint: "https://archive.invalid", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				_, err := io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
				if err != nil {
					return nil, err
				}
				return jsonResponse(fakeReceipt(now)), nil
			})}}
			receipt, err := c.Preserve(context.Background(), clientEnvelope(now, int64(len(want)), auditrecord.Hash(want)), []AttachmentInput{{ID: "script", Reader: source}})
			if tc.name == "valid_final_read_with_eof" {
				if err != nil || receipt.Token == "" {
					t.Fatalf("valid finite input rejected: %v", err)
				}
			} else if !errors.Is(err, ErrReceipt) || receipt.Token != "" {
				t.Fatalf("fault issued receipt: %+v, %v", receipt, err)
			}
			if requests != 1 || source.closes != 1 {
				t.Fatalf("request retried or source cleanup changed: requests=%d closes=%d", requests, source.closes)
			}
		})
	}
}

func TestPreserveRejectsMalformedReceiptAndClosesBody(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name string
		body io.Reader
	}{
		{"read_failure", &faultReader{err: io.ErrUnexpectedEOF}},
		{"oversized", strings.NewReader(strings.Repeat("x", auditrecord.MaxReceiptBytes+4097))},
		{"duplicate_token", strings.NewReader(`{"token":"one","token":"two"}`)},
		{"empty_token", strings.NewReader(`{"token":""}`)},
		{"invalid_manifest", strings.NewReader(`{"token":"signed","manifest":{}}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &observedBody{Reader: tc.body}
			c := &Client{endpoint: "https://archive.invalid", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				_, _ = io.Copy(io.Discard, r.Body)
				return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
			})}}
			if _, err := c.Preserve(context.Background(), clientEnvelope(now, 0, ""), nil); !errors.Is(err, ErrReceipt) || body.closes != 1 {
				t.Fatalf("malformed response accepted or leaked: %v, closes=%d", err, body.closes)
			}
		})
	}
}

func TestReadOriginalRejectsHTTPSizeAndStatusBeforeDelivery(t *testing.T) {
	ref := fakeReceipt(time.Now()).Manifest
	ref.Bytes = 4
	for _, tc := range []struct {
		name   string
		status int
		length int64
	}{
		{"unknown_length", 200, -1}, {"short_length", 200, 3},
		{"long_length", 200, 5}, {"empty_length", 200, 0}, {"denied", 403, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &observedBody{Reader: strings.NewReader("data")}
			c := &Client{endpoint: "https://archive.invalid", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, ContentLength: tc.length, Body: body, Header: make(http.Header)}, nil
			})}}
			reader, err := c.ReadOriginal(context.Background(), ref, "intent")
			if reader != nil || !errors.Is(err, ErrReceipt) || body.closes != 1 {
				t.Fatalf("unsafe body returned: %v, closes=%d", err, body.closes)
			}
		})
	}
	for _, endpoint := range []string{"https://archive.invalid", "://invalid"} {
		c := &Client{endpoint: endpoint, http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport unavailable")
		})}}
		if body, err := c.ReadOriginal(context.Background(), ref, "intent"); body != nil || !errors.Is(err, ErrReceipt) {
			t.Fatal("request failure returned original")
		}
	}
	for _, bad := range []auditrecord.ObjectRef{{}, func() auditrecord.ObjectRef { r := ref; r.Bytes = auditrecord.MaxAttachmentBytes + 1; return r }()} {
		if _, err := (&Client{}).ReadOriginal(context.Background(), bad, "intent"); !errors.Is(err, ErrReceipt) {
			t.Fatal("invalid original bounds accepted")
		}
	}
	if _, err := (&Client{}).ReadOriginal(context.Background(), ref, strings.Repeat("x", auditrecord.MaxReceiptBytes+1)); !errors.Is(err, ErrReceipt) {
		t.Fatal("oversized intent accepted")
	}
}

func TestLookupFailureContracts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   io.Reader
	}{
		{"read_failure", 200, &faultReader{err: io.ErrUnexpectedEOF}},
		{"too_large", 200, strings.NewReader(strings.Repeat("x", auditrecord.MaxReceiptBytes+4097))},
		{"ambiguous_json", 200, strings.NewReader(`{"token":"one","token":"two"}`)},
		{"unavailable", 503, strings.NewReader("private error")},
		{"untyped_absence", 404, strings.NewReader(`{"code":"anchor_not_found"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &observedBody{Reader: tc.body}
			c := &Client{endpoint: "https://archive.invalid", bearer: strings.Repeat("b", 32), http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 32) {
					t.Fatal("lookup omitted scoped credential")
				}
				return &http.Response{StatusCode: tc.status, Body: body, Header: make(http.Header)}, nil
			})}}
			if _, err := c.Lookup(context.Background(), "event", auditrecord.Hash(nil)); !errors.Is(err, ErrReceipt) || body.closes != 1 {
				t.Fatalf("untrusted lookup accepted/leaked: %v, closes=%d", err, body.closes)
			}
		})
	}
	for _, endpoint := range []string{"https://archive.invalid", "://invalid"} {
		c := &Client{endpoint: endpoint, http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })}}
		if _, err := c.Lookup(context.Background(), "event", auditrecord.Hash(nil)); !errors.Is(err, ErrReceipt) {
			t.Fatal("lookup transport failure accepted")
		}
	}
	if _, err := (&Client{}).Lookup(context.Background(), "../event", auditrecord.Hash(nil)); !errors.Is(err, ErrReceipt) {
		t.Fatal("invalid event lookup accepted")
	}
}
