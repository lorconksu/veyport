package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
	"github.com/wyiu/veyport/hub/internal/store"
)

type OriginalAccessConfig struct {
	ResolveArchive func(context.Context, model.PolicyVersion) (auditgate.OriginalArchive, error)
}

func (s *Server) registerOriginalAccessRoutes(mux *http.ServeMux, limiter *rateLimiter) {
	read := func(h http.HandlerFunc) http.Handler {
		return loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, h))
	}
	interactive := func(h http.HandlerFunc) http.Handler {
		return loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.interactiveOnly(h)))
	}
	mux.Handle("GET /api/executions", read(s.handleExecutionList))
	mux.Handle("GET /api/executions/{id}", read(s.handleExecutionDetail))
	mux.Handle("POST /api/executions/{id}/original-access/preview", interactive(s.handleOriginalPreview))
	mux.Handle("POST /api/executions/{id}/original-access/step-up", limiter.middleware(interactive(s.handleOriginalStepup)))
	mux.Handle("POST /api/executions/{id}/original-access", interactive(s.handleOriginalAccess))
	// The raw one-use handle must not appear in ordinary request logs.
	mux.Handle("GET /api/audit-originals/{handle}", originalRequestLog(s.authMiddleware(auth.TokenTypeAccess, s.interactiveOnly(http.HandlerFunc(s.handleOriginalDownload)))))
}

type originalStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *originalStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *originalStatusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *originalStatusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}
func originalRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &originalStatusWriter{ResponseWriter: w}
		next.ServeHTTP(wrapped, r)
		status := wrapped.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("%s /api/audit-originals/{handle} status=%d %s request_id=%s", r.Method, status, time.Since(start), RequestIDFromContext(r.Context()))
	})
}

func (s *Server) originalAuthority(user, sid string, revision *int) (*model.User, model.EffectiveCapabilities, error) {
	e, err := s.securityService().Effective(user)
	if err != nil || !e.Can(model.OriginalReadAction) || sid == "" {
		return nil, e, authorization.ErrDenied
	}
	u, err := s.store.GetUserByID(user)
	if err != nil || !u.TOTPEnabled || u.MustChangePassword || revision != nil && u.SecurityRevision != *revision {
		return nil, e, authorization.ErrDenied
	}
	sess, err := s.store.GetSession(sid)
	if err != nil || sess.UserID != user || session.Evaluate(session.StateFromModel(sess), s.now(), s.lockoutPolicy()) != session.VerdictOK {
		return nil, e, authorization.ErrDenied
	}
	return u, e, nil
}

func (s *Server) executionReadAllowed(user string) bool {
	e, err := s.securityService().Effective(user)
	return err == nil && e.Can("audit.read")
}

func executionView(e model.Execution) model.ExecutionView {
	var preparation *model.ExecutionPreparation
	if e.Preparation.PreparationID != "" {
		p := e.Preparation
		preparation = &p
	}
	// Remote error wording is not a structured redacted field. The stable
	// process/evidence state and exit status carry the investigable outcome.
	e.Reason = ""
	originals := []string{}
	if e.Enhanced && e.AdmissionReceipt != "" && preparation != nil {
		originals = append(originals, "envelope")
		if auditrecord.ValidHash(e.ScriptSHA256) {
			originals = append(originals, "script")
		}
	}
	return model.ExecutionView{Execution: &e, Preparation: preparation, Originals: originals}
}

func (s *Server) handleExecutionList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.executionReadAllowed(UserIDFromContext(r.Context())) {
		securityError(w, authorization.ErrDenied)
		return
	}
	q := r.URL.Query()
	allowed := map[string]bool{"limit": true, "offset": true, "actor_id": true, "node_id": true, "os_user": true, "policy_version": true, "state": true, "evidence_state": true}
	for name, values := range q {
		if !allowed[name] || len(values) != 1 || len(values[0]) > 256 {
			respondError(w, http.StatusBadRequest, "bounded execution filters required")
			return
		}
	}
	limit, offset := parsePagination(q, 50)
	if limit > 100 {
		limit = 100
	}
	f := model.ExecutionFilter{Limit: limit, Offset: offset, ActorID: q.Get("actor_id"), NodeID: q.Get("node_id"), OSUser: q.Get("os_user"), PolicyVersion: q.Get("policy_version"), State: q.Get("state"), EvidenceState: q.Get("evidence_state")}
	items, total, err := s.store.ListExecutions(f)
	if err != nil {
		respondError(w, http.StatusBadRequest, "execution list unavailable")
		return
	}
	views := make([]model.ExecutionView, 0, len(items))
	for _, e := range items {
		views = append(views, executionView(e))
	}
	respondJSON(w, http.StatusOK, map[string]any{"executions": views, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) handleExecutionDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.executionReadAllowed(UserIDFromContext(r.Context())) {
		securityError(w, authorization.ErrDenied)
		return
	}
	e, err := s.store.GetExecution(r.PathValue("id"))
	if err != nil {
		respondError(w, http.StatusNotFound, "execution not found")
		return
	}
	respondJSON(w, http.StatusOK, executionView(*e))
}

type originalRequest struct {
	Purpose     string   `json:"purpose"`
	Records     []string `json:"records"`
	Digest      string   `json:"digest,omitempty"`
	Code        string   `json:"code,omitempty"`
	StepupProof string   `json:"step_up_proof,omitempty"`
}
type originalSelection struct {
	execution *model.Execution
	policy    model.PolicyVersion
	archive   auditgate.OriginalArchive
	object    auditrecord.ObjectRef
	preview   model.OriginalPreview
	purpose   string
	kind      string
}

func validateOriginalRequest(req originalRequest) error {
	if req.Purpose != strings.TrimSpace(req.Purpose) || req.Purpose == "" || len(req.Purpose) > 1024 || !utf8.ValidString(req.Purpose) || len(req.Records) != 1 || req.Records[0] != "envelope" && req.Records[0] != "script" {
		return errors.New("purpose and one selected original required")
	}
	for _, c := range req.Purpose {
		if unicode.IsControl(c) {
			return errors.New("invalid purpose")
		}
	}
	return nil
}

func executionExpected(e *model.Execution, version uint64) auditrecord.Expected {
	i, l := e.Preparation.Identity, e.Preparation.Limits
	x := &auditrecord.ExecutionBinding{ExecutionID: e.ID, PreparationID: e.Preparation.PreparationID, BootID: e.Preparation.BootID, NodeID: e.NodeID, NodeName: e.NodeName, Identity: auditrecord.Identity{Username: i.Username, UID: i.UID, GID: i.GID, Groups: i.Groups, GroupsSHA256: i.GroupsSHA256, IdentitySHA256: i.IdentitySHA256, Home: i.Home, Shell: i.Shell, CWD: i.Cwd}, CommandSHA256: e.CommandSHA256, CommandBytes: int64(e.CommandLength), ScriptSHA256: e.ScriptSHA256, ScriptBytes: e.ScriptLength, PreparedUntil: time.UnixMilli(e.Preparation.ExpiresUnixMilli).UTC(), Limits: auditrecord.Limits{MaxFrameBytes: l.MaxFrameBytes, MaxBufferBytes: l.MaxBufferBytes, RuntimeSeconds: l.RuntimeSeconds, TermGraceSeconds: l.TermGraceSeconds, BlockedConsumerSeconds: l.BlockedConsumerSeconds}}
	actor := auditrecord.Actor{UserID: e.ActorID, PersonID: e.ActorPersonID, Name: e.ActorName, Provider: e.ActorProvider, Subject: e.ActorSubject}
	return auditrecord.Expected{EventID: e.AdmissionEventID, EventType: auditrecord.ExecutionAdmission, RecordSHA256: e.AdmissionRecordSHA256, ActorSHA256: auditrecord.Digest(actor), BindingSHA256: auditrecord.Digest(struct {
		Execution *auditrecord.ExecutionBinding `json:"execution"`
		Details   *auditrecord.Details          `json:"details"`
	}{x, nil}), PolicyVersion: version, PolicySHA256: e.PolicySHA256, Execution: x}
}

func (s *Server) selectOriginal(ctx context.Context, id string, req originalRequest) (originalSelection, error) {
	var selected originalSelection
	if err := validateOriginalRequest(req); err != nil {
		return selected, err
	}
	e, err := s.store.GetExecution(id)
	if err != nil || !e.Enhanced || e.AdmissionReceipt == "" || e.Preparation.PreparationID == "" || !auditrecord.ValidHash(e.AdmissionRecordSHA256) {
		return selected, store.ErrOriginalAccess
	}
	version, err := strconv.ParseUint(e.PolicyVersion, 10, 64)
	if err != nil || s.originalAccess.ResolveArchive == nil {
		return selected, authorization.ErrNotReady
	}
	p, err := s.store.GetPolicyVersion(version)
	if err != nil || p.SHA256 != e.PolicySHA256 {
		return selected, authorization.ErrNotReady
	}
	archive, err := s.originalAccess.ResolveArchive(ctx, p)
	if err != nil || archive.Ingest == nil || archive.Admin == nil || archive.Reader == nil || archive.Verifier == nil {
		return selected, authorization.ErrNotReady
	}
	claims, err := archive.Verifier.VerifyArchivedAdmission(e.AdmissionReceipt, executionExpected(e, version), s.now())
	if err != nil || !s.now().Before(claims.Manifest.RetainUntil) {
		return selected, authorization.ErrNotReady
	}
	raw, err := archive.Admin.Manifest(ctx, e.AdmissionEventID, e.AdmissionRecordSHA256, claims.Manifest)
	var m auditrecord.Manifest
	if err != nil || auditrecord.Hash(raw) != claims.Manifest.SHA256 || int64(len(raw)) != claims.Manifest.Bytes || auditrecord.Decode(raw, &m, auditrecord.MaxEnvelopeBytes) != nil || m.SchemaVersion != 1 || m.EventID != e.AdmissionEventID || m.RecordSHA256 != e.AdmissionRecordSHA256 || m.SigningKeyID != claims.KeyID || m.QualificationSHA256 != claims.QualificationSHA256 || !m.RetainUntil.Equal(claims.Manifest.RetainUntil) || !m.IssuedAt.Time.Equal(claims.IssuedAt.Time) || !m.ExpiresAt.Time.Equal(claims.ExpiresAt.Time) || !m.Envelope.Valid() || m.Envelope.Key != "envelopes/"+m.EventID+"/"+m.RecordSHA256 || m.Envelope.SHA256 != e.AdmissionRecordSHA256 || !m.Envelope.RetainUntil.Equal(m.RetainUntil) {
		return selected, authorization.ErrNotReady
	}
	object := m.Envelope
	if auditrecord.ValidHash(e.ScriptSHA256) {
		if len(m.Attachments) != 1 || !m.Attachments[0].Valid() || m.Attachments[0].SHA256 != e.ScriptSHA256 || m.Attachments[0].Bytes != e.ScriptLength || m.Attachments[0].Key != "attachments/"+m.EventID+"/"+m.RecordSHA256+"/script" || !m.Attachments[0].RetainUntil.Equal(m.RetainUntil) {
			return selected, authorization.ErrNotReady
		}
		if req.Records[0] == "script" {
			object = m.Attachments[0]
		}
	} else if len(m.Attachments) != 0 || req.Records[0] == "script" {
		return selected, store.ErrOriginalAccess
	}
	if !s.now().Before(object.RetainUntil) || object.Bytes > auditrecord.MaxAttachmentBytes {
		return selected, authorization.ErrNotReady
	}
	digest := auditrecord.Digest(struct {
		Action, ExecutionID, Purpose, Kind string
		Object                             auditrecord.ObjectRef
	}{model.OriginalReadAction, id, req.Purpose, req.Records[0], object})
	preview := model.OriginalPreview{Action: model.OriginalReadAction, Digest: digest, Records: []model.OriginalDescriptor{{Kind: req.Records[0], EventID: m.EventID, SHA256: object.SHA256, Bytes: object.Bytes, VersionID: object.VersionID}}}
	return originalSelection{execution: e, policy: p, archive: archive, object: object, preview: preview, purpose: req.Purpose, kind: req.Records[0]}, nil
}

func originalError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrOriginalAccess) {
		respondError(w, http.StatusForbidden, store.ErrOriginalAccess.Error())
		return
	}
	if errors.Is(err, authorization.ErrNotReady) || errors.Is(err, auditgate.ErrReceipt) {
		respondError(w, http.StatusServiceUnavailable, "original archive or required evidence unavailable")
		return
	}
	securityError(w, err)
}

func (s *Server) originalSelectionRequest(w http.ResponseWriter, r *http.Request) (originalSelection, originalRequest, bool) {
	w.Header().Set("Cache-Control", "no-store")
	var req originalRequest
	if _, _, err := s.originalAuthority(UserIDFromContext(r.Context()), SessionIDFromContext(r.Context()), nil); err != nil {
		originalError(w, err)
		return originalSelection{}, req, false
	}
	if err := decodeSecurity(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return originalSelection{}, req, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	selected, err := s.selectOriginal(ctx, r.PathValue("id"), req)
	if err != nil {
		originalError(w, err)
		return selected, req, false
	}
	return selected, req, true
}

func (s *Server) handleOriginalPreview(w http.ResponseWriter, r *http.Request) {
	selected, req, ok := s.originalSelectionRequest(w, r)
	if !ok {
		return
	}
	if req.Digest != "" || req.Code != "" || req.StepupProof != "" {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	respondJSON(w, http.StatusOK, selected.preview)
}

func (s *Server) handleOriginalStepup(w http.ResponseWriter, r *http.Request) {
	selected, req, ok := s.originalSelectionRequest(w, r)
	if !ok {
		return
	}
	if req.Digest != selected.preview.Digest || req.StepupProof != "" {
		originalError(w, store.ErrStepup)
		return
	}
	user, sid := UserIDFromContext(r.Context()), SessionIDFromContext(r.Context())
	u, _, err := s.originalAuthority(user, sid, nil)
	if err != nil || u.TOTPSecret == nil {
		originalError(w, store.ErrStepup)
		return
	}
	secret, err := s.decryptTOTPSecret(*u.TOTPSecret)
	if err != nil || !auth.ValidateTOTPWithReplayAt(s.totpCache, user, secret, req.Code, s.now()) {
		originalError(w, store.ErrStepup)
		return
	}
	proof, err := s.store.IssueStepup(user, sid, model.OriginalReadAction, req.Digest, s.now())
	if err != nil {
		originalError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"proof": proof, "expires_at": s.now().Add(5 * time.Minute)})
}

func originalEnvelope(a model.OriginalAccess, state, suffix string, now time.Time) ([]byte, error) {
	typ := auditrecord.OriginalReadResult
	if suffix == "intent" {
		typ = auditrecord.OriginalReadIntent
	}
	envelope := auditrecord.Envelope{SchemaVersion: 1, EventID: a.ID + "." + suffix, EventType: typ, Actor: a.Actor, PolicyVersion: a.PolicyVersion, PolicySHA256: a.PolicySHA256, OccurredAt: now.UTC(), Details: &auditrecord.Details{CorrelationID: a.ID, RequestID: a.ExecutionID, RequestSHA256: a.Digest, SessionSHA256: auditrecord.Hash([]byte(a.SessionID)), Reason: a.Purpose, State: state, Originals: []auditrecord.ObjectRef{a.Object}}}
	if typ == auditrecord.OriginalReadResult {
		envelope.Details.Delivery = &auditrecord.OriginalDelivery{BytesWritten: &a.BytesWritten, Scope: "hub_response"}
		if state == "unconfirmed" {
			envelope.Details.Delivery.BytesWritten = nil
		}
	}
	raw, err := json.Marshal(envelope)
	if err != nil || envelope.Validate() != nil {
		return nil, auditrecord.ErrSchema
	}
	return raw, nil
}

func preserveOriginal(ctx context.Context, archive auditgate.OriginalArchive, raw []byte, retain, now time.Time, live bool) (auditrecord.Receipt, error) {
	expected, _, err := auditrecord.ExpectedFor(raw)
	if err != nil || archive.Ingest == nil || archive.Verifier == nil {
		return auditrecord.Receipt{}, authorization.ErrNotReady
	}
	expected.MinRetainUntil = retain
	receipt, err := archive.Ingest.Preserve(ctx, raw, nil)
	if err != nil && archive.Admin != nil {
		receipt, err = archive.Admin.Lookup(ctx, expected.EventID, expected.RecordSHA256)
	}
	if err != nil {
		return receipt, authorization.ErrNotReady
	}
	var claims auditrecord.Claims
	if live {
		claims, err = archive.Verifier.Verify(receipt.Token, expected, now)
	} else {
		claims, err = archive.Verifier.VerifyReadEvidence(receipt.Token, expected, now)
	}
	if err != nil || auditrecord.Digest(claims.Manifest) != auditrecord.Digest(receipt.Manifest) {
		return receipt, auditgate.ErrReceipt
	}
	return receipt, nil
}

func (s *Server) handleOriginalAccess(w http.ResponseWriter, r *http.Request) {
	selected, req, ok := s.originalSelectionRequest(w, r)
	if !ok {
		return
	}
	if req.Digest != selected.preview.Digest || req.Code != "" {
		originalError(w, store.ErrStepup)
		return
	}
	user, sid := UserIDFromContext(r.Context()), SessionIDFromContext(r.Context())
	u, e, err := s.originalAuthority(user, sid, nil)
	if err != nil {
		originalError(w, err)
		return
	}
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		originalError(w, authorization.ErrNotReady)
		return
	}
	handle := hex.EncodeToString(random[:])
	now := s.now()
	a := model.OriginalAccess{ID: uuid.NewString(), ExecutionID: selected.execution.ID, UserID: user, PersonID: e.PersonID, SessionID: sid, SecurityRevision: u.SecurityRevision, PolicyVersion: selected.policy.Version, PolicySHA256: selected.policy.SHA256, Digest: req.Digest, Purpose: req.Purpose, Kind: selected.kind, Object: selected.object, Actor: auditrecord.Actor{UserID: user, PersonID: e.PersonID, Name: u.Username, Provider: string(u.AuthProvider), Subject: u.ExternalID}, HandleSHA256: auditrecord.Hash([]byte(handle)), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	a.Intent, err = originalEnvelope(a, "authorized", "intent", now)
	if err != nil {
		originalError(w, err)
		return
	}
	retain := now.Add(time.Duration(selected.policy.Policy.RetentionHours) * time.Hour)
	if err = s.store.CreateOriginalAccess(a, req.StepupProof, retain, now, s.lockoutPolicy()); err != nil {
		originalError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	receipt, err := preserveOriginal(ctx, selected.archive, a.Intent, retain, s.now(), true)
	cancel()
	if err != nil {
		s.wakeOriginalRecovery()
		originalError(w, err)
		return
	}
	expected, _, _ := auditrecord.ExpectedFor(a.Intent)
	expected.MinRetainUntil = retain
	claims, err := selected.archive.Verifier.Verify(receipt.Token, expected, s.now())
	if err != nil {
		s.wakeOriginalRecovery()
		originalError(w, err)
		return
	}
	expires := a.ExpiresAt
	if claims.ExpiresAt.Time.Before(expires) {
		expires = claims.ExpiresAt.Time
	}
	if err = s.store.AuthorizeOriginalAccess(a.ID, receipt.Token, expires, receipt.Manifest, s.now(), s.lockoutPolicy()); err != nil {
		s.wakeOriginalRecovery()
		originalError(w, err)
		return
	}
	s.auditSecurity(r, "audit.original_authorized", a.ID, req.Digest)
	respondJSON(w, http.StatusCreated, map[string]any{"handle": handle, "expires_at": expires, "download_url": "/api/audit-originals/" + handle})
}
