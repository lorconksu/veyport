package connmgr

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestMaintenanceReservationSerializesWithQueuedAdmission(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	conn := cm.Register("node", stream)
	entered, release := make(chan struct{}), make(chan struct{})
	reserved := make(chan error, 1)
	go func() {
		reserved <- cm.ReserveMaintenance(conn, "operation", func() error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sent := make(chan error, 1)
	go func() {
		sent <- cm.SendToAgentContext(ctx, "node", &pb.HubMessage{Payload: &pb.HubMessage_TerminalOpenRequest{TerminalOpenRequest: &pb.TerminalOpenRequest{SessionId: "queued"}}})
	}()
	select {
	case err := <-sent:
		t.Fatal("admission passed unfinished maintenance reservation", err)
	default:
	}
	close(release)
	if err := <-reserved; err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err == nil {
		t.Fatal("queued admission ignored newly reserved maintenance")
	}
	if len(stream.sent) != 0 {
		t.Fatal("queued terminal reached the agent")
	}
}

func TestMaintenanceRequiresCurrentLiveGenerationAndPreservesNewerLease(t *testing.T) {
	cm := New()
	old := cm.Register("node", &mockStream{})
	current := cm.Register("node", &mockStream{})
	called := false
	check := func() error { called = true; return nil }
	if err := cm.ReserveMaintenance(nil, "operation", check); err == nil {
		t.Fatal("nil generation reserved maintenance")
	}
	if err := cm.ReserveMaintenance(old, "operation", check); err == nil {
		t.Fatal("replaced generation reserved maintenance")
	}
	current.Close()
	if err := cm.ReserveMaintenance(current, "operation", check); err == nil {
		t.Fatal("closed generation reserved maintenance")
	}
	if called {
		t.Fatal("invalid generation reached the authority callback")
	}
	stream := &mockStream{}
	current = cm.Register("node", stream)
	denied := errors.New("grant revoked")
	if err := cm.ReserveMaintenance(current, "denied", func() error { return denied }); !errors.Is(err, denied) {
		t.Fatal("authority refusal ignored", err)
	}
	if err := cm.ReserveMaintenance(current, "new-operation", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := cm.ReserveMaintenance(current, "duplicate", func() error { return nil }); err == nil {
		t.Fatal("overlapping maintenance reserved")
	}
	cm.ReleaseMaintenance("node", "old-operation")
	for _, msg := range []*pb.HubMessage{{Payload: &pb.HubMessage_ExecutionPrepare{ExecutionPrepare: &pb.ExecutionPrepare{ExecutionId: "unsafe"}}}, {Payload: &pb.HubMessage_ExecutionAttach{ExecutionAttach: &pb.ExecutionAttachRequest{}}}} {
		if err := cm.SendToAgent("node", msg); err == nil {
			t.Fatal("old completion released new execution admission gate")
		}
	}
	if err := cm.SendToAgent("node", &pb.HubMessage{Payload: &pb.HubMessage_HeartbeatAck{HeartbeatAck: &pb.HeartbeatAck{}}}); err != nil {
		t.Fatal("maintenance blocked control health", err)
	}
	cm.ReleaseMaintenance("node", "new-operation")
	cm.SetMaintenance("node", "")
	if err := cm.SendToAgent("node", &pb.HubMessage{Payload: &pb.HubMessage_TerminalOpenRequest{TerminalOpenRequest: &pb.TerminalOpenRequest{SessionId: "safe"}}}); err != nil {
		t.Fatal("completed maintenance retained its admission gate", err)
	}
}
