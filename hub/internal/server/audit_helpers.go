package server

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

func (s *Server) auditLogRequest(r *http.Request, entry model.AuditEntry) {
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	if entry.CorrelationID == nil {
		if requestID := RequestIDFromContext(r.Context()); requestID != "" {
			entry.CorrelationID = &requestID
		}
	}
	_ = s.store.LogAudit(entry)
}
