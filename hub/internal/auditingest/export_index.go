package auditingest

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

const MaxExportPage = 32

// ExportReference contains no original bytes. Ledger retention outlives execution
// originals; Expired references are skipped, while missing unexpired data fails.
type ExportReference struct {
	EventID      string                `json:"event_id"`
	EventType    string                `json:"event_type"`
	RecordSHA256 string                `json:"record_sha256"`
	Manifest     auditrecord.ObjectRef `json:"manifest"`
}
type ExportPage struct {
	Records []ExportReference `json:"records"`
	Next    string            `json:"next,omitempty"`
}
type ExportKeyPager interface {
	ExportKeys(context.Context, string, int) ([]string, bool, error)
}

// ExportKeys only enumerates the dedicated global event ledger. StartAfter is a
// bounded event ID, not a caller-controlled S3 prefix or continuation token.
func (a *S3Archive) ExportKeys(ctx context.Context, after string, limit int) ([]string, bool, error) {
	if limit < 1 || limit > MaxExportPage || after != "" && !auditrecord.ValidID(after) {
		return nil, false, auditrecord.ErrSchema
	}
	in := &s3.ListObjectsV2Input{Bucket: aws.String(a.config.Bucket), Prefix: aws.String("events/"), MaxKeys: aws.Int32(int32(limit))}
	if after != "" {
		in.StartAfter = aws.String("events/" + after)
	}
	out, err := a.api.ListObjectsV2(ctx, in)
	if err != nil || out == nil || len(out.Contents) > limit {
		return nil, false, ErrUnavailable
	}
	keys := make([]string, 0, len(out.Contents))
	prior := after
	for _, entry := range out.Contents {
		id := strings.TrimPrefix(aws.ToString(entry.Key), "events/")
		if !strings.HasPrefix(aws.ToString(entry.Key), "events/") || !auditrecord.ValidID(id) || id <= prior {
			return nil, false, ErrUnavailable
		}
		prior = id
		keys = append(keys, id)
	}
	if aws.ToBool(out.IsTruncated) && len(keys) == 0 {
		return nil, false, ErrUnavailable
	}
	return keys, aws.ToBool(out.IsTruncated), nil
}

func (s *Service) ExportIndex(ctx context.Context, after string, limit int) (ExportPage, error) {
	if limit < 1 || limit > MaxExportPage || after != "" && !auditrecord.ValidID(after) {
		return ExportPage{}, auditrecord.ErrSchema
	}
	pager, ok := s.config.GovernanceArchive.(ExportKeyPager)
	if !ok {
		return ExportPage{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	keys, more, err := pager.ExportKeys(ctx, after, limit)
	if err != nil || len(keys) > limit {
		return ExportPage{}, ErrUnavailable
	}
	page := ExportPage{Records: make([]ExportReference, 0, len(keys))}
	previous := after
	for _, id := range keys {
		if !auditrecord.ValidID(id) || id <= previous {
			return ExportPage{}, ErrUnavailable
		}
		previous = id
		idx, err := s.readLedger(ctx, id)
		if err != nil || idx.Manifest.Key != "manifests/"+id {
			return ExportPage{}, ErrUnavailable
		}
		page.Records = append(page.Records, ExportReference{idx.EventID, idx.EventType, idx.RecordSHA256, idx.Manifest})
	}
	if more {
		page.Next = previous
	}
	return page, nil
}

func (h *Handler) exportIndex(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for key, values := range q {
		if key != "after" && key != "limit" || len(values) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	limit := MaxExportPage
	if q.Has("limit") {
		var err error
		limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	if limit < 1 || limit > MaxExportPage || q.Get("after") != "" && !auditrecord.ValidID(q.Get("after")) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	page, err := h.service.ExportIndex(r.Context(), q.Get("after"), limit)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(page)
}

func (r ExportReference) valid() bool {
	return auditrecord.ValidID(r.EventID) && auditrecord.ValidHash(r.RecordSHA256) && r.Manifest.Valid() && r.Manifest.Key == "manifests/"+r.EventID && !r.Manifest.RetainUntil.IsZero()
}

func (r ExportReference) expired(now time.Time) bool { return !now.Before(r.Manifest.RetainUntil) }
