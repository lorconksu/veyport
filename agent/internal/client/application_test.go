package client

import (
	"context"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func testApplicationOpen() *pb.ApplicationOpen {
	return &pb.ApplicationOpen{Binding: &pb.ApplicationBinding{ConnectionId: "connection", ApplicationId: "application", ConfigVersion: 1, NodeId: "node", ControlGeneration: "generation", BootId: "1234567890123456", ExpiresUnixMilli: time.Now().Add(30 * time.Second).UnixMilli()}, Target: &pb.ApplicationTarget{Scheme: "http", Hostname: "127.0.0.1", Port: 8080, AllowedCidrs: []string{"127.0.0.0/8"}}, AttachTicket: make([]byte, 32)}
}

func TestApplicationOpenCannotAcquireMaintenanceOrWrongIdentity(t *testing.T) {
	for _, kind := range []string{"maintenance", "wrong-node", "wrong-boot", "expired", "bad-scope"} {
		budget := sessionlimit.New(8)
		if kind == "maintenance" && !budget.TryMaintenance() {
			t.Fatal("maintenance fixture failed")
		}
		ctx, cancel := context.WithCancel(context.Background())
		send := make(chan *pb.AgentMessage, 2)
		e := &applicationTransport{ctx: ctx, cancel: cancel, nodeID: "node", bootID: "1234567890123456", budget: budget, send: send, sessions: make(map[string]*applicationSocket)}
		open := testApplicationOpen()
		switch kind {
		case "wrong-node":
			open.Binding.NodeId = "other"
		case "wrong-boot":
			open.Binding.BootId = "other"
		case "expired":
			open.Binding.ExpiresUnixMilli = time.Now().Add(-time.Second).UnixMilli()
		case "bad-scope":
			open.Target.AllowedCidrs = nil
		}
		if !e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ApplicationOpen{ApplicationOpen: open}}) {
			t.Fatal("open was not handled")
		}
		if budget.ActivityCount() != 0 {
			t.Fatalf("%s consumed activity", kind)
		}
		select {
		case response := <-send:
			if response.GetApplicationClosed() == nil {
				t.Fatal("missing refusal cleanup acknowledgement")
			}
		case <-time.After(time.Second):
			t.Fatal("missing refusal acknowledgement")
		}
		e.close()
	}
}
