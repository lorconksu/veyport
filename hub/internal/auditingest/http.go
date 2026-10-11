package auditingest

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type Scope string

const (
	ScopeIngest Scope = "ingest"
	ScopeRead   Scope = "original-read"
	ScopeAdmin  Scope = "admin"
	ScopeExport Scope = "export-index"
)

// Credential contains only hashes. A single principal cannot combine write,
// original-read and administration scopes.
type Credential struct {
	ID                string `json:"id"`
	TokenSHA256       string `json:"token_sha256,omitempty"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
	Scope             Scope  `json:"scope"`
}
type Authenticator struct{ credentials []Credential }

func NewAuthenticator(credentials []Credential) (*Authenticator, error) {
	if len(credentials) == 0 || len(credentials) > 64 {
		return nil, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, c := range credentials {
		if !auditrecord.ValidID(c.ID) || seen[c.ID] || c.Scope != ScopeIngest && c.Scope != ScopeRead && c.Scope != ScopeAdmin && c.Scope != ScopeExport || !auditrecord.ValidHash(c.TokenSHA256) && !auditrecord.ValidHash(c.CertificateSHA256) || c.TokenSHA256 != "" && c.CertificateSHA256 != "" {
			return nil, ErrUnavailable
		}
		seen[c.ID] = true
		key := c.TokenSHA256 + c.CertificateSHA256
		if seen[key] {
			return nil, ErrUnavailable
		}
		seen[key] = true
	}
	return &Authenticator{append([]Credential(nil), credentials...)}, nil
}

func (a *Authenticator) authorize(r *http.Request, scope Scope) bool {
	if a == nil || r.TLS == nil {
		return false
	}
	certHash := ""
	if len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 {
		certHash = auditrecord.Hash(r.TLS.PeerCertificates[0].Raw)
	}
	bearer := r.Header.Get("Authorization")
	tokenHash := ""
	if strings.HasPrefix(bearer, "Bearer ") && len(bearer) >= 39 && len(bearer) <= 1024 {
		tokenHash = auditrecord.Hash([]byte(strings.TrimPrefix(bearer, "Bearer ")))
	}
	allowed := false
	for _, c := range a.credentials {
		certMatch := sameHash(certHash, c.CertificateSHA256)
		tokenMatch := sameHash(tokenHash, c.TokenSHA256)
		if c.Scope == scope && (certMatch || tokenMatch) {
			allowed = true
		}
	}
	return allowed
}

func sameHash(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	x, e := hex.DecodeString(a)
	y, f := hex.DecodeString(b)
	return e == nil && f == nil && subtle.ConstantTimeCompare(x, y) == 1
}

type Handler struct {
	service *Service
	auth    *Authenticator
	slots   chan struct{}
}

func NewHandler(s *Service, a *Authenticator, concurrency int) (*Handler, error) {
	if s == nil || a == nil || concurrency < 1 || concurrency > 4 {
		return nil, ErrUnavailable
	}
	return &Handler{s, a, make(chan struct{}, concurrency)}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	scope := ScopeIngest
	switch r.URL.Path {
	case "/v1/records":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	case "/v1/originals":
		scope = ScopeRead
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	case "/v1/ready":
		scope = ScopeAdmin
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	case "/v1/export-index":
		scope = ScopeExport
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	default:
		if strings.HasPrefix(r.URL.Path, "/v1/records/") || strings.HasPrefix(r.URL.Path, "/v1/anchors/") {
			scope = ScopeAdmin
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	if !h.auth.authorize(r, scope) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if scope == ScopeExport {
		h.exportIndex(w, r)
		return
	}
	if scope == ScopeAdmin {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/v1/records/") {
			receipt, err := h.service.Lookup(r.Context(), strings.TrimPrefix(r.URL.Path, "/v1/records/"), r.URL.Query().Get("sha256"))
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(receipt)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/anchors/") {
			anchor, err := h.service.Anchor(r.Context(), strings.TrimPrefix(r.URL.Path, "/v1/anchors/"), r.URL.Query().Get("nonce"))
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					w.WriteHeader(http.StatusNotFound)
					_ = json.NewEncoder(w).Encode(auditrecord.AnchorNotFoundResponse{Code: "anchor_not_found", InstallationID: strings.TrimPrefix(r.URL.Path, "/v1/anchors/"), Nonce: r.URL.Query().Get("nonce")})
				} else {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
				return
			}
			_ = json.NewEncoder(w).Encode(anchor)
			return
		}
		readinessContext, cancel := context.WithTimeout(r.Context(), h.service.config.Timeout)
		defer cancel()
		var archiveReady, governanceReady bool
		var readinessChecks sync.WaitGroup
		readinessChecks.Add(2)
		go func() {
			defer readinessChecks.Done()
			archiveReady = h.service.config.Archive.Ready(readinessContext) == nil
		}()
		go func() {
			defer readinessChecks.Done()
			governanceReady = h.service.config.GovernanceArchive.Ready(readinessContext) == nil
		}()
		readinessChecks.Wait()
		_ = json.NewEncoder(w).Encode(struct {
			Ready                         bool   `json:"ready"`
			ArchiveReady                  bool   `json:"archive_ready"`
			GovernanceReady               bool   `json:"governance_ready"`
			QualificationSHA256           string `json:"qualification_sha256"`
			GovernanceQualificationSHA256 string `json:"governance_qualification_sha256"`
			RetentionSeconds              int64  `json:"retention_seconds"`
			GovernanceRetentionSeconds    int64  `json:"governance_retention_seconds"`
		}{
			Ready:                         archiveReady && governanceReady,
			ArchiveReady:                  archiveReady,
			GovernanceReady:               governanceReady,
			QualificationSHA256:           h.service.config.Archive.Qualification().Digest,
			GovernanceQualificationSHA256: h.service.config.GovernanceArchive.Qualification().Digest,
			RetentionSeconds:              int64(h.service.config.Retention / time.Second),
			GovernanceRetentionSeconds:    int64(h.service.config.GovernanceRetention / time.Second),
		})
		return
	}
	if scope == ScopeRead {
		h.readOriginal(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, auditrecord.MaxAttachmentBytes+auditrecord.MaxEnvelopeBytes+(16<<10))
	raw, attachments, err := parseSubmission(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	receipt, err := h.service.Preserve(r.Context(), raw, attachments)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, auditrecord.ErrSchema) {
			status = http.StatusBadRequest
		}
		if errors.Is(err, ErrConflict) {
			status = http.StatusConflict
		}
		if errors.Is(err, ErrBusy) {
			status = http.StatusTooManyRequests
		}
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(receipt)
}

func parseSubmission(r *http.Request) ([]byte, []AttachmentInput, error) {
	typ, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, nil, auditrecord.ErrSchema
	}
	if typ == "application/json" {
		b, err := io.ReadAll(io.LimitReader(r.Body, auditrecord.MaxEnvelopeBytes+1))
		if err != nil {
			return nil, nil, auditrecord.ErrSchema
		}
		_, e, err := auditrecord.ExpectedFor(b)
		if err != nil || len(e.Attachments) != 0 {
			return nil, nil, auditrecord.ErrSchema
		}
		return b, nil, nil
	}
	if typ != "multipart/form-data" && typ != "multipart/mixed" || params["boundary"] == "" || len(params["boundary"]) > 70 {
		return nil, nil, auditrecord.ErrSchema
	}
	reader := multipart.NewReader(r.Body, params["boundary"])
	part, err := reader.NextPart()
	if err != nil || part.Header.Get("Content-ID") != "envelope" || part.Header.Get("Content-Type") != "application/json" {
		return nil, nil, auditrecord.ErrSchema
	}
	raw, err := io.ReadAll(io.LimitReader(part, auditrecord.MaxEnvelopeBytes+1))
	if err != nil {
		return nil, nil, auditrecord.ErrSchema
	}
	_, e, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return nil, nil, auditrecord.ErrSchema
	}
	inputs := make([]AttachmentInput, 0, len(e.Attachments))
	for _, a := range e.Attachments {
		p, err := reader.NextPart()
		if err != nil || p.Header.Get("Content-ID") != a.ID || p.Header.Get("Content-Type") != "application/octet-stream" {
			return nil, nil, auditrecord.ErrSchema
		}
		data, err := readExact(p, a.Bytes)
		if err != nil || int64(len(data)) != a.Bytes || auditrecord.Hash(data) != a.SHA256 {
			return nil, nil, auditrecord.ErrSchema
		}
		inputs = append(inputs, AttachmentInput{ID: a.ID, Reader: bytes.NewReader(data)})
	}
	if _, err = reader.NextPart(); err != io.EOF {
		return nil, nil, auditrecord.ErrSchema
	}
	return raw, inputs, nil
}

func (h *Handler) readOriginal(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, auditrecord.MaxReceiptBytes+4096)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var req struct {
		Object      auditrecord.ObjectRef `json:"object"`
		IntentToken string                `json:"intent_token"`
	}
	if auditrecord.Decode(b, &req, auditrecord.MaxReceiptBytes+4096) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	data, err := h.service.ReadOriginal(r.Context(), req.Object, req.IntentToken)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="protected-original"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func NewHTTPServer(address string, handler http.Handler, config *tls.Config) (*http.Server, error) {
	if address == "" || handler == nil || config == nil || config.InsecureSkipVerify || config.MinVersion < tls.VersionTLS12 || len(config.Certificates) == 0 || config.ClientCAs == nil || config.ClientAuth != tls.RequireAndVerifyClientCert && config.ClientAuth != tls.VerifyClientCertIfGiven {
		return nil, ErrUnavailable
	}
	return &http.Server{Addr: address, Handler: handler, TLSConfig: config.Clone(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0)}, nil
}
