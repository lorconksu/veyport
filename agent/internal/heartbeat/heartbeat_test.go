package heartbeat

import (
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestBuildMessage(t *testing.T) {
	msg := BuildMessage("server-123")
	hb := msg.GetHeartbeat()
	if hb == nil {
		t.Fatal("expected heartbeat payload")
	}
	if hb.ServerId != "server-123" {
		t.Fatalf("expected server_id 'server-123', got '%s'", hb.ServerId)
	}
	if hb.Timestamp == 0 {
		t.Fatal("expected non-zero timestamp")
	}
	if hb.SystemInfo == nil {
		t.Fatal("expected system_info to be populated")
	}
}

func TestNewTicker(t *testing.T) {
	ch := make(chan *pb.AgentMessage, 5)
	stop := make(chan struct{})
	go StartTicker("srv-1", 50*time.Millisecond, ch, stop)
	time.Sleep(150 * time.Millisecond)
	close(stop)
	count := len(ch)
	if count < 2 {
		t.Fatalf("expected at least 2 heartbeats, got %d", count)
	}
}
