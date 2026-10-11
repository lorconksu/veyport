package auditingest

import (
	"context"
	"net/http"
	"strings"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

// OriginalManifest returns metadata only. The global event ledger selects the
// exact immutable version; neither an S3 key nor a replacement version is trusted
// from an HTTP caller. Original envelope/attachment reads still require intent.
func (s *Service) OriginalManifest(ctx context.Context, event, hash, version string) ([]byte, error) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return nil, ErrBusy
	}
	if !auditrecord.ValidID(event) || !auditrecord.ValidHash(hash) || version == "" || len(version) > 1024 {
		return nil, auditrecord.ErrSchema
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	idx, err := s.readLedger(ctx, event)
	if err != nil || idx.EventType != auditrecord.ExecutionAdmission || idx.RecordSHA256 != hash || idx.Manifest.VersionID != version {
		return nil, ErrUnavailable
	}
	archive := s.archiveFor(idx.EventType)
	b, err := archive.Read(ctx, idx.Manifest)
	var m auditrecord.Manifest
	if err != nil || int64(len(b)) != idx.Manifest.Bytes || auditrecord.Hash(b) != idx.Manifest.SHA256 || auditrecord.Decode(b, &m, auditrecord.MaxEnvelopeBytes) != nil || m.SchemaVersion != 1 || m.EventID != event || m.RecordSHA256 != hash || m.Envelope.SHA256 != hash || !m.Envelope.Valid() || len(m.Attachments) > auditrecord.MaxAttachments || !m.RetainUntil.Equal(idx.Manifest.RetainUntil) || !s.config.Now().Before(m.RetainUntil) || archive.Verify(ctx, idx.Manifest, m.RetainUntil) != nil || archive.Verify(ctx, m.Envelope, m.RetainUntil) != nil {
		return nil, ErrUnavailable
	}
	for _, ref := range m.Attachments {
		if !ref.Valid() || !ref.RetainUntil.Equal(m.RetainUntil) || archive.Verify(ctx, ref, m.RetainUntil) != nil {
			return nil, ErrUnavailable
		}
	}
	return b, nil
}

func (h *Handler) originalManifest(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if len(q) != 2 || len(q["sha256"]) != 1 || len(q["version_id"]) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	b, err := h.service.OriginalManifest(r.Context(), strings.TrimPrefix(r.URL.Path, "/v1/manifests/"), q.Get("sha256"), q.Get("version_id"))
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}
