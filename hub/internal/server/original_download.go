package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
)

func (s *Server) recordOriginalDelivery(a model.OriginalAccess, archive auditgate.OriginalArchive, state, suffix string, n int64, now time.Time) error {
	a.BytesWritten = n
	raw, err := originalEnvelope(a, state, suffix, now)
	if err != nil {
		return err
	}
	policy, err := s.store.GetPolicyVersion(a.PolicyVersion)
	if err != nil {
		return err
	}
	retain := now.Add(time.Duration(policy.Policy.RetentionHours) * time.Hour)
	if err = s.store.RecordOriginalOutcome(a.ID, state, n, raw, retain, now); err != nil {
		_ = s.store.MarkOriginalPermanent(a.ID)
		return err
	}
	// Client cancellation cannot cancel delivery-result preservation. This
	// bounded operation never retries any read or recreates a consumed permit.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	receipt, err := preserveOriginal(ctx, archive, raw, retain, s.now(), false)
	if err == nil {
		err = s.store.ConfirmOriginalEvidence(a.ID+"."+suffix, receipt.Manifest, s.now())
	}
	if err != nil {
		s.wakeOriginalRecovery()
	}
	return err
}

func (s *Server) handleOriginalDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	handle := r.PathValue("handle")
	if len(handle) != 64 || !auditrecord.ValidHash(handle) {
		originalError(w, authorization.ErrDenied)
		return
	}
	user, sid := UserIDFromContext(r.Context()), SessionIDFromContext(r.Context())
	if _, _, err := s.originalAuthority(user, sid, nil); err != nil {
		originalError(w, err)
		return
	}
	a, err := s.store.ConsumeOriginalAccess(auditrecord.Hash([]byte(handle)), user, sid, s.now(), s.lockoutPolicy().SessionIdle)
	if err != nil {
		originalError(w, err)
		return
	}
	// Consumption precedes network work. A failed/ambiguous open never permits
	// another download with this handle.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	policy, err := s.store.GetPolicyVersion(a.PolicyVersion)
	var archive auditgate.OriginalArchive
	if err == nil && policy.SHA256 == a.PolicySHA256 && s.originalAccess.ResolveArchive != nil {
		archive, err = s.originalAccess.ResolveArchive(ctx, policy)
	} else {
		err = authorization.ErrNotReady
	}
	if err != nil || archive.Reader == nil || archive.Ingest == nil || archive.Verifier == nil {
		_ = s.recordOriginalDelivery(a, archive, "unconfirmed", "result", 0, s.now())
		originalError(w, authorization.ErrNotReady)
		return
	}
	// Externally preserved start is required before opening any original body.
	if err = s.recordOriginalDelivery(a, archive, "started", "started", 0, s.now()); err != nil {
		_ = s.recordOriginalDelivery(a, archive, "unconfirmed", "result", 0, s.now())
		originalError(w, authorization.ErrNotReady)
		return
	}
	if _, e, err := s.originalAuthority(user, sid, &a.SecurityRevision); err != nil || e.PersonID != a.PersonID || !s.now().Before(a.ExpiresAt) {
		_ = s.recordOriginalDelivery(a, archive, "interrupted", "result", 0, s.now())
		originalError(w, authorization.ErrDenied)
		return
	}
	body, err := archive.Reader.ReadOriginal(ctx, a.Object, a.IntentToken)
	if err != nil {
		_ = s.recordOriginalDelivery(a, archive, "interrupted", "result", 0, s.now())
		originalError(w, authorization.ErrNotReady)
		return
	}
	defer body.Close()
	// Recheck after the upstream response and before the first original byte.
	if _, e, err := s.originalAuthority(user, sid, &a.SecurityRevision); err != nil || e.PersonID != a.PersonID || !s.now().Before(a.ExpiresAt) {
		_ = s.recordOriginalDelivery(a, archive, "interrupted", "result", 0, s.now())
		originalError(w, authorization.ErrDenied)
		return
	}
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = s.recordOriginalDelivery(a, archive, "interrupted", "result", 0, s.now())
		originalError(w, authorization.ErrNotReady)
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="execution-`+a.ExecutionID+`-`+a.Kind+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(a.Object.Bytes, 10))
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	var written int64
	state := "completed"
	for {
		if ctx.Err() != nil {
			state = "interrupted"
			break
		}
		if _, e, err := s.originalAuthority(user, sid, &a.SecurityRevision); err != nil || e.PersonID != a.PersonID {
			state = "interrupted"
			break
		}
		n, readErr := body.Read(buffer)
		if n > 0 {
			if written+int64(n) > a.Object.Bytes {
				state = "interrupted"
				break
			}
			// A role/session change while a network read blocked must also
			// prevent the newly received bytes from crossing this boundary.
			if _, e, err := s.originalAuthority(user, sid, &a.SecurityRevision); err != nil || e.PersonID != a.PersonID || ctx.Err() != nil {
				state = "interrupted"
				break
			}
			// The response write itself may block without observing ctx.Done.
			// Bound it in the underlying connection, with no writer goroutine.
			deadline := time.Now().Add(5 * time.Second)
			if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
				deadline = end
			}
			if err := controller.SetWriteDeadline(deadline); err != nil {
				state = "interrupted"
				break
			}
			m, writeErr := w.Write(buffer[:n])
			if m > 0 {
				written += int64(m)
				_, _ = hash.Write(buffer[:m])
			}
			if writeErr != nil || m != n {
				state = "interrupted"
				break
			}
			if err := controller.Flush(); err != nil {
				state = "interrupted"
				break
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				state = "interrupted"
			}
			break
		}
		if n == 0 {
			state = "interrupted"
			break
		}
	}
	if written != a.Object.Bytes || hex.EncodeToString(hash.Sum(nil)) != a.Object.SHA256 || ctx.Err() != nil {
		state = "interrupted"
	}
	_ = s.recordOriginalDelivery(a, archive, state, "result", written, s.now())
}
