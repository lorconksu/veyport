package store_test

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/wyiu/veyport/hub/internal/model"
	"testing"
)

func TestExecutionMetadataClaimAndDeletedSnapshots(t *testing.T) {
	s := testStore(t)
	hash := sha256.Sum256([]byte("SECRET_EXECUTION_CANARY"))
	e := &model.Execution{ID: "exec", ActorID: "deleted-user", ActorName: "alice", NodeID: "deleted-node", NodeName: "web01", CommandSHA256: hex.EncodeToString(hash[:]), CommandLength: 23}
	if err := s.CreateUser(&model.User{ID: e.ActorID, Username: e.ActorName, Email: "alice@test.com", Role: model.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateServer(&model.Server{ID: e.NodeID, Name: e.NodeName, Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateExecution(e); err != nil {
		t.Fatal(err)
	}
	p := model.ExecutionPreparation{PreparationID: "prep", BootID: "boot", Identity: model.ExecutionIdentity{Username: "actual-root", UID: 0, GID: 0, Shell: "/bin/sh", Cwd: "/root"}}
	if err := s.PrepareExecution(e.ID, p); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimExecutionDispatch(e.ID, "prep"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimExecutionDispatch(e.ID, "prep"); err == nil {
		t.Fatal("duplicate dispatch claim succeeded")
	}
	if err := s.DeleteUser(e.ActorID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteServer(e.NodeID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetExecution(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ActorName != "alice" || got.NodeName != "web01" || got.Preparation.Identity.Username != "actual-root" || got.State != "dispatching" {
		t.Fatalf("lost snapshots: %+v", got)
	}
	if err := s.ReconcileExecutions(); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetExecution(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "outcome_unknown" || got.EvidenceState != "completion_unconfirmed" {
		t.Fatalf("restart retried uncertain launch: %+v", got)
	}
	var rawCount int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM executions WHERE preparation LIKE '%SECRET_EXECUTION_CANARY%'`).Scan(&rawCount); err != nil {
		t.Fatal(err)
	}
	if rawCount != 0 {
		t.Fatal("raw payload stored")
	}
}
