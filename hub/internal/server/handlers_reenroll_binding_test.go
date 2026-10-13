package server

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestReEnrollDenyBindsExactLiveRequest(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		status int
	}{
		{"valid", nil, http.StatusOK},
		{"stale", grpcserver.ErrNoPendingReEnroll, http.StatusConflict},
		{"duplicate", grpcserver.ErrReEnrollDecisionInProgress, http.StatusConflict},
		{"persistence-failure", errors.New("database update failed"), http.StatusInternalServerError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockReEnrollReleaser{err: tt.err}
			s := newTestServerWithReleaser(t, mock)
			if err := s.store.CreateReEnrollRequest(&model.ReEnrollRequest{ID: "bound-request", ServerID: "bound-server", RequestedAt: "2026-10-12 00:00:00", Status: "pending", AnomalyFlags: "{}"}); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/servers/bound-server/reenroll/deny", bytes.NewBufferString(`{"request_id":"bound-request"}`))
			r.SetPathValue("id", "bound-server")
			r = withUserID(r, "admin")
			w := httptest.NewRecorder()
			s.handleReEnrollDeny(w, r)
			if w.Code != tt.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if !mock.called || mock.serverID != "bound-server" || mock.requestID != "bound-request" || mock.adminID != "admin" {
				t.Fatalf("denial binding lost: %+v", mock)
			}
		})
	}
}

func TestReEnrollDenyPersistenceFailureReturnsNoSuccess(t *testing.T) {
	s := testServer(t)
	if err := s.store.CreateReEnrollRequest(&model.ReEnrollRequest{ID: "deny-persistence", ServerID: "bound-server", RequestedAt: "2026-10-12 00:00:00", Status: "pending", AnomalyFlags: "{}"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.DB().Exec(`CREATE TRIGGER refuse_deny BEFORE UPDATE ON reenroll_requests BEGIN SELECT RAISE(FAIL,'denial unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/servers/bound-server/reenroll/deny", bytes.NewBufferString(`{"request_id":"deny-persistence"}`))
	r.SetPathValue("id", "bound-server")
	r = withUserID(r, "admin")
	w := httptest.NewRecorder()
	s.handleReEnrollDeny(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if row, err := s.store.GetReEnrollRequest("deny-persistence"); err != nil || row.Status != "pending" {
		t.Fatalf("failed denial changed row: %+v %v", row, err)
	}
}
