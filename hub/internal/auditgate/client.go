package auditgate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type AttachmentInput = auditrecord.AttachmentInput
type Preserver interface {
	Preserve(context.Context, []byte, []AttachmentInput) (auditrecord.Receipt, error)
}

type ClientConfig struct {
	Endpoint         string
	AllowedHosts     []string
	AllowedAddresses []string
	TLS              *tls.Config
	Bearer           string
	Verifier         *Verifier
}
type Client struct {
	endpoint string
	http     *http.Client
	bearer   string
	verifier *Verifier
}

func NewClient(c ClientConfig) (*Client, error) {
	if c.TLS == nil || len(c.TLS.Certificates) == 0 && len(c.Bearer) < 32 {
		return nil, ErrReceipt
	}
	client, err := NewTLSClient(TransportConfig{Endpoint: c.Endpoint, AllowedHosts: c.AllowedHosts, AllowedAddresses: c.AllowedAddresses, TLS: c.TLS, Timeout: 10 * time.Second, Connections: 8})
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: strings.TrimSuffix(c.Endpoint, "/"), http: client, bearer: c.Bearer, verifier: c.Verifier}, nil
}

func (c *Client) Preserve(ctx context.Context, raw []byte, inputs []AttachmentInput) (auditrecord.Receipt, error) {
	_, e, err := auditrecord.ExpectedFor(raw)
	if err != nil || len(inputs) != len(e.Attachments) {
		return auditrecord.Receipt{}, auditrecord.ErrSchema
	}
	var headers bytes.Buffer
	writer := multipart.NewWriter(&headers)
	var readers []io.Reader
	var closers []io.Closer
	length := int64(len(raw))
	takeHeader := func() {
		b := append([]byte(nil), headers.Bytes()...)
		readers = append(readers, bytes.NewReader(b))
		length += int64(len(b))
		headers.Reset()
	}
	header := textproto.MIMEHeader{}
	header.Set("Content-Type", "application/json")
	header.Set("Content-ID", "envelope")
	_, err = writer.CreatePart(header)
	if err != nil {
		return auditrecord.Receipt{}, ErrReceipt
	}
	takeHeader()
	readers = append(readers, bytes.NewReader(raw))
	for i, a := range e.Attachments {
		if inputs[i].ID != a.ID || inputs[i].Reader == nil {
			return auditrecord.Receipt{}, auditrecord.ErrSchema
		}
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-ID", a.ID)
		_, err = writer.CreatePart(h)
		if err != nil {
			return auditrecord.Receipt{}, ErrReceipt
		}
		takeHeader()
		readers = append(readers, &attachmentReader{ctx: ctx, reader: inputs[i].Reader, expected: a, hash: sha256.New()})
		length += a.Bytes
		if closer, ok := inputs[i].Reader.(io.Closer); ok {
			closers = append(closers, closer)
		}
	}
	if writer.Close() != nil {
		return auditrecord.Receipt{}, ErrReceipt
	}
	takeHeader()
	body := &submissionBody{reader: io.MultiReader(readers...), closers: closers}
	defer body.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/records", body)
	if err != nil {
		return auditrecord.Receipt{}, ErrReceipt
	}
	req.ContentLength = length
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return auditrecord.Receipt{}, ErrReceipt
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return auditrecord.Receipt{}, ErrReceipt
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, auditrecord.MaxReceiptBytes+4097))
	if err != nil {
		return auditrecord.Receipt{}, ErrReceipt
	}
	var receipt auditrecord.Receipt
	if auditrecord.Decode(b, &receipt, auditrecord.MaxReceiptBytes+4096) != nil || receipt.Token == "" || !receipt.Manifest.Valid() {
		return receipt, ErrReceipt
	}
	return receipt, nil
}

type attachmentReader struct {
	ctx      context.Context
	reader   io.Reader
	expected auditrecord.Attachment
	n        int64
	hash     hash.Hash
	done     bool
}

func (r *attachmentReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.done {
		return 0, io.EOF
	}
	if r.n == r.expected.Bytes {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n != 0 || err != io.EOF || hex.EncodeToString(r.hash.Sum(nil)) != r.expected.SHA256 {
			return 0, auditrecord.ErrSchema
		}
		r.done = true
		return 0, io.EOF
	}
	if int64(len(p)) > r.expected.Bytes-r.n {
		p = p[:r.expected.Bytes-r.n]
	}
	if len(p) > 32<<10 {
		p = p[:32<<10]
	}
	n, err := r.reader.Read(p)
	if n > 0 {
		r.n += int64(n)
		_, _ = r.hash.Write(p[:n])
	}
	if err == io.EOF {
		if r.n != r.expected.Bytes {
			return n, auditrecord.ErrSchema
		}
		if hex.EncodeToString(r.hash.Sum(nil)) != r.expected.SHA256 {
			return n, auditrecord.ErrSchema
		}
		r.done = true
	}
	return n, err
}

type submissionBody struct {
	reader  io.Reader
	closers []io.Closer
	once    sync.Once
}

func (b *submissionBody) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *submissionBody) Close() error {
	b.once.Do(func() {
		for _, c := range b.closers {
			_ = c.Close()
		}
	})
	return nil
}

// ReadOriginal uses a separate read credential and an already preserved access
// intent. The caller must enforce its live authorization and one-use handle.
func (c *Client) ReadOriginal(ctx context.Context, ref auditrecord.ObjectRef, intentToken string) (io.ReadCloser, error) {
	if !ref.Valid() || ref.Bytes > auditrecord.MaxAttachmentBytes || len(intentToken) > auditrecord.MaxReceiptBytes {
		return nil, ErrReceipt
	}
	b, _ := json.Marshal(struct {
		Object      auditrecord.ObjectRef `json:"object"`
		IntentToken string                `json:"intent_token"`
	}{ref, intentToken})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/originals", bytes.NewReader(b))
	if err != nil {
		return nil, ErrReceipt
	}
	req.Header.Set("Content-Type", "application/json")
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, ErrReceipt
	}
	if resp.StatusCode != http.StatusOK || resp.ContentLength != ref.Bytes {
		resp.Body.Close()
		return nil, ErrReceipt
	}
	return resp.Body, nil
}

func (c *Client) Lookup(ctx context.Context, eventID, recordHash string) (auditrecord.Receipt, error) {
	if !auditrecord.ValidID(eventID) || !auditrecord.ValidHash(recordHash) {
		return auditrecord.Receipt{}, ErrReceipt
	}
	b, err := c.get(ctx, "/v1/records/"+url.PathEscape(eventID)+"?sha256="+recordHash, auditrecord.MaxReceiptBytes+4096)
	if err != nil {
		return auditrecord.Receipt{}, err
	}
	var receipt auditrecord.Receipt
	if auditrecord.Decode(b, &receipt, auditrecord.MaxReceiptBytes+4096) != nil {
		return receipt, ErrReceipt
	}
	return receipt, nil
}

// Anchor verifies a fresh nonce bound to the independently signed latest policy
// anchor. A verifier is mandatory; TLS authentication alone is not policy proof.
func (c *Client) Anchor(ctx context.Context, installationID string) (auditrecord.AnchorResponse, error) {
	if !auditrecord.ValidID(installationID) || c.verifier == nil {
		return auditrecord.AnchorResponse{}, ErrReceipt
	}
	var nonceBytes [32]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return auditrecord.AnchorResponse{}, ErrReceipt
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	b, err := c.get(ctx, "/v1/anchors/"+url.PathEscape(installationID)+"?nonce="+nonce, auditrecord.MaxEnvelopeBytes+auditrecord.MaxReceiptBytes+4096)
	if err != nil {
		return auditrecord.AnchorResponse{}, err
	}
	var response auditrecord.AnchorResponse
	if auditrecord.Decode(b, &response, auditrecord.MaxEnvelopeBytes+auditrecord.MaxReceiptBytes+4096) != nil || response.Nonce != nonce {
		return response, ErrReceipt
	}
	expected, e, err := auditrecord.ExpectedFor(response.Record)
	if err != nil || e.EventType != auditrecord.PolicyAnchor || e.Details == nil || e.Details.InstallationID != installationID {
		return response, ErrReceipt
	}
	expected.Nonce = nonce
	claims, err := c.verifier.Verify(response.Receipt.Token, expected, time.Now())
	if err != nil || auditrecord.Digest(claims.Manifest) != auditrecord.Digest(response.Receipt.Manifest) {
		return response, ErrReceipt
	}
	return response, nil
}

func (c *Client) get(ctx context.Context, path string, max int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path, nil)
	if err != nil {
		return nil, ErrReceipt
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, ErrReceipt
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, 1025))
		var missing auditrecord.AnchorNotFoundResponse
		if strings.HasPrefix(req.URL.Path, "/v1/anchors/") && readErr == nil && auditrecord.Decode(b, &missing, 1024) == nil && missing.Code == "anchor_not_found" && missing.InstallationID == strings.TrimPrefix(req.URL.Path, "/v1/anchors/") && missing.Nonce == req.URL.Query().Get("nonce") {
			return nil, ErrAnchorNotFound
		}
		return nil, ErrReceipt
	}
	if resp.StatusCode != http.StatusOK {
		return nil, ErrReceipt
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if err != nil || len(b) > max {
		return nil, ErrReceipt
	}
	return b, nil
}

// Gate couples exact submitted bytes, a live preparation, external archival and a
// durable one-use dispatch claim. Callers still recheck live authorization at dispatch.
type Gate struct {
	Preserver Preserver
	Verifier  *Verifier
	Consumer  Consumer
	Now       func() time.Time
}

func (g Gate) Admit(ctx context.Context, raw []byte, attachments []AttachmentInput, live auditrecord.ExecutionBinding, minRetain time.Time) (auditrecord.Receipt, error) {
	e, envelope, err := auditrecord.ExpectedFor(raw)
	if err != nil || envelope.EventType != auditrecord.ExecutionAdmission || auditrecord.Digest(envelope.Execution) != auditrecord.Digest(&live) || g.Preserver == nil || g.Verifier == nil || g.Consumer == nil {
		return auditrecord.Receipt{}, ErrReceipt
	}
	e.MinRetainUntil = minRetain
	receipt, err := g.Preserver.Preserve(ctx, raw, attachments)
	if err != nil {
		return receipt, err
	}
	now := time.Now()
	if g.Now != nil {
		now = g.Now()
	}
	c, err := g.Verifier.Verify(receipt.Token, e, now)
	if err != nil {
		return auditrecord.Receipt{}, err
	}
	if auditrecord.Digest(c.Manifest) != auditrecord.Digest(receipt.Manifest) {
		return auditrecord.Receipt{}, ErrReceipt
	}
	if _, err = g.Verifier.Consume(ctx, receipt.Token, e, now, g.Consumer); err != nil {
		return auditrecord.Receipt{}, err
	}
	return receipt, nil
}
