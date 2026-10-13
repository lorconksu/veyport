package store_test

import (
	"errors"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestCreateCurrentReEnrollRequestReplacesAtomically(t *testing.T) {
	s := testStore(t)
	request := &model.ReEnrollRequest{ID: "request-old", ServerID: "bound-server", RequestedAt: "2026-10-12 00:00:00", Status: "pending", AnomalyFlags: "{}"}
	if err := s.CreateCurrentReEnrollRequest(request); err != nil {
		t.Fatal(err)
	}
	// Failed insertion must roll back expiry of the existing request.
	if err := s.CreateCurrentReEnrollRequest(request); err == nil {
		t.Fatal("duplicate request accepted")
	}
	if row, err := s.GetReEnrollRequest(request.ID); err != nil || row.Status != "pending" {
		t.Fatalf("failed replacement changed current request: %+v %v", row, err)
	}
	newRequest := *request
	newRequest.ID = "request-new"
	if err := s.CreateCurrentReEnrollRequest(&newRequest); err != nil {
		t.Fatal(err)
	}
	if row, err := s.GetReEnrollRequest(request.ID); err != nil || row.Status != "expired" {
		t.Fatalf("old request did not expire: %+v %v", row, err)
	}
	pending, err := s.ListPendingReEnroll()
	if err != nil || len(pending) != 1 || pending[0].ID != newRequest.ID {
		t.Fatalf("current pending requests: %+v %v", pending, err)
	}
	if err := s.DecidePendingReEnroll(request.ServerID, request.ID, "approved", "admin"); !errors.Is(err, store.ErrReEnrollNotPending) {
		t.Fatalf("late decision accepted: %v", err)
	}
	if err := s.DecidePendingReEnroll("another-server", newRequest.ID, "denied", "admin"); !errors.Is(err, store.ErrReEnrollNotPending) {
		t.Fatalf("wrong-server decision accepted: %v", err)
	}
	if err := s.DecidePendingReEnroll(newRequest.ServerID, newRequest.ID, "denied", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.DecidePendingReEnroll(newRequest.ServerID, newRequest.ID, "approved", "admin"); !errors.Is(err, store.ErrReEnrollNotPending) {
		t.Fatalf("denial was overwritten: %v", err)
	}
	row, err := s.GetReEnrollRequest(newRequest.ID)
	if err != nil || row.Status != "denied" || row.DecidedBy != "admin" {
		t.Fatalf("persisted decision: %+v %v", row, err)
	}
}

func TestCreateCurrentReEnrollRequestExpiryFailureRollsBack(t *testing.T) {
	s := testStore(t)
	request := &model.ReEnrollRequest{ID: "expiry-old", ServerID: "bound-server", RequestedAt: "2026-10-12 00:00:00", Status: "pending", AnomalyFlags: "{}"}
	if err := s.CreateCurrentReEnrollRequest(request); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`CREATE TRIGGER refuse_request_expiry BEFORE UPDATE ON reenroll_requests BEGIN SELECT RAISE(FAIL,'expiry unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	newRequest := *request
	newRequest.ID = "expiry-new"
	if err := s.CreateCurrentReEnrollRequest(&newRequest); err == nil {
		t.Fatal("replacement accepted failed expiry")
	}
	if row, err := s.GetReEnrollRequest(request.ID); err != nil || row.Status != "pending" {
		t.Fatalf("failed expiry changed request: %+v %v", row, err)
	}
	if _, err := s.GetReEnrollRequest(newRequest.ID); err == nil {
		t.Fatal("failed replacement inserted request")
	}
}

func TestPendingReEnrollDecisionDatabaseUnavailable(t *testing.T) {
	s := testStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateCurrentReEnrollRequest(&model.ReEnrollRequest{}); err == nil {
		t.Fatal("replacement accepted closed database")
	}
	if err := s.DecidePendingReEnroll("server", "request", "approved", "admin"); err == nil {
		t.Fatal("decision accepted closed database")
	}
}
