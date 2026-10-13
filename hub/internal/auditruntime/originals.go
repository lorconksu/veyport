package auditruntime

import (
	"context"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
)

// ResolveOriginalArchive preserves read evidence and retrieves originals from
// the execution's immutable destination. Historical reads do not require live
// execution transport, and never borrow a newer policy's credentials or trust.
func (r *Runtime) ResolveOriginalArchive(ctx context.Context, p model.PolicyVersion) (auditgate.OriginalArchive, error) {
	if ctx.Err() != nil || p.Version == 0 || p.SHA256 != auditrecord.Digest(p.Policy) {
		return auditgate.OriginalArchive{}, authorization.ErrNotReady
	}
	gate, e, err := r.archive(p.Policy)
	if err != nil {
		return auditgate.OriginalArchive{}, err
	}
	if e.reader == nil {
		return auditgate.OriginalArchive{}, authorization.ErrNotReady
	}
	if err := e.ready.check(ctx, e.config, time.Duration(p.Policy.RetentionHours)*time.Hour, false); err != nil {
		return auditgate.OriginalArchive{}, err
	}
	return auditgate.OriginalArchive{Ingest: gate.Preserver, Admin: e.admin, Reader: e.reader, Verifier: gate.Verifier}, nil
}
