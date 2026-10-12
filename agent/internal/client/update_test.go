package client

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestUpdateHelpersNeverFallBackToBootstrapOrInsecureTransport(t *testing.T) {
	c := New(Config{HubAddr: "127.0.0.1:1", ServerID: "node", CertDir: t.TempDir(), DropzoneDir: t.TempDir(), Insecure: true, AgentVersion: "0.2.0-prototype.3", AgentRevision: "unknown"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.RunUpdateBootstrap(ctx, strings.Repeat("x", 64), "0.2.0-prototype.4", "revision"); err == nil {
		t.Fatal("bootstrap accepted unenrolled/insecure credentials")
	}
	if err := c.RunUpdateSupervisor(ctx, "valid-operation"); err == nil {
		t.Fatal("supervisor accepted unenrolled/insecure credentials")
	}
	send := make(chan *pb.AgentMessage, 4)
	if !c.handleUpdateMessage(ctx, &pb.HubMessage{Payload: &pb.HubMessage_AgentUpdateRequest{AgentUpdateRequest: &pb.AgentUpdateRequest{OperationId: "valid-operation"}}}, send) {
		t.Fatal("update request not dispatched")
	}
	select {
	case message := <-send:
		status := message.GetUpdateStatus()
		if status == nil || status.State != "failed" || status.Version != "0.2.0-prototype.3" || status.Sha256 == "" || status.BootId == "" {
			t.Fatalf("failure status=%v", status)
		}
	case <-ctx.Done():
		t.Fatal("update worker did not terminate")
	}
	deadline := time.Now().Add(time.Second)
	for len(c.updateWorkers) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("update worker leaked")
		}
		time.Sleep(time.Millisecond)
	}
	if !c.budget.Acquire() {
		t.Fatal("mTLS refusal locked ordinary admission")
	}
}

func TestDuplicateAndStaleControlDoNotChangeBoundOperation(t *testing.T) {
	c := New(Config{CertDir: t.TempDir(), DropzoneDir: t.TempDir()})
	send := make(chan *pb.AgentMessage, 1)
	c.updateWorkers <- struct{}{}
	if !c.handleUpdateMessage(context.Background(), &pb.HubMessage{Payload: &pb.HubMessage_AgentUpdateRequest{AgentUpdateRequest: &pb.AgentUpdateRequest{OperationId: "second-operation"}}}, send) {
		t.Fatal("duplicate update was not recognized")
	}
	if len(send) != 0 || len(c.updateWorkers) != 1 {
		t.Fatal("duplicate spawned a worker or status")
	}
	if !c.handleUpdateMessage(context.Background(), &pb.HubMessage{Payload: &pb.HubMessage_UpdateConfirmation{UpdateConfirmation: &pb.UpdateConfirmation{OperationId: "stale-operation", State: "succeeded"}}}, send) {
		t.Fatal("confirmation not recognized")
	}
	if len(send) != 0 {
		t.Fatal("failed durable confirmation emitted success acknowledgement")
	}
	if c.handleUpdateMessage(context.Background(), &pb.HubMessage{Payload: &pb.HubMessage_HeartbeatAck{HeartbeatAck: &pb.HeartbeatAck{}}}, send) {
		t.Fatal("update dispatcher consumed ordinary heartbeat")
	}
}
