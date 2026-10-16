package server

import (
	"encoding/json"
	"github.com/wyiu/veyport/hub/internal/model"
	"log"
	"net/http"
	"time"
)

// Stable event IDs and a durable audited marker make retries safe after a crash
// between app termination, audit commit, and marker persistence.
func (s *Server) auditApplicationSessionEnds() error {
	var failure error
	s.applicationAuditMu.Lock()
	defer s.applicationAuditMu.Unlock()
	rows, e := s.store.UnauditedApplicationSessionEnds(100)
	if e != nil {
		return e
	}
	for _, ss := range rows {
		id := "application-session-end:" + ss.ID
		exists, e := s.store.ApplicationAuditExists(id)
		if e != nil {
			failure = e
			continue
		}
		if !exists {
			detail, _ := json.Marshal(map[string]string{"application_id": ss.ApplicationID, "session_id": ss.ID, "reason": ss.EndReason})
			e = s.store.LogAudit(model.AuditEntry{ID: id, UserID: &ss.UserID, Action: "application.session_ended", Target: &ss.ApplicationID, Detail: stringPtr(string(detail)), ResourceType: stringPtr("application"), ActorType: model.AuditActorTypeSystem, Outcome: model.AuditOutcomeSuccess})
			if e != nil {
				failure = e
				log.Printf("application session audit persistence unavailable")
				continue
			}
		}
		if e = s.store.MarkApplicationEndAudited(ss.ID); e != nil {
			failure = e
		}
	}
	return failure
}
func (s *Server) auditApplicationRequest(r *http.Request, a *model.Application, w *applicationWriter, started time.Time) {
	requestBytes := int64(0)
	if body, ok := r.Body.(*applicationBody); ok {
		requestBytes = body.bytes.Load()
	}
	detail, _ := json.Marshal(map[string]any{"application_id": a.ID, "node_id": a.NodeID, "route": a.Route, "method": r.Method, "status": w.status, "response_bytes": w.bytes.Load(), "request_bytes": requestBytes, "duration_ms": time.Since(started).Milliseconds()})
	uid := UserIDFromContext(r.Context())
	requestID := RequestIDFromContext(r.Context())
	s.auditLogRequest(r, model.AuditEntry{Action: "application.request", UserID: &uid, Target: &a.ID, Detail: stringPtr(string(detail)), CorrelationID: &requestID, ResourceType: stringPtr("application"), ActorType: model.AuditActorTypeUser, Outcome: model.AuditOutcomeSuccess})
}
