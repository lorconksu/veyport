package connmgr

import (
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestRegisterAndGetConn(t *testing.T) {
	cm := New()
	cm.Register("s1", nil) // nil stream OK for unit tests
	conn := cm.GetConn("s1")
	if conn == nil {
		t.Fatal("expected connection for s1")
	}
	if conn.ServerID != "s1" {
		t.Fatalf("expected server ID 's1', got '%s'", conn.ServerID)
	}
}

func TestGetConn_NotFound(t *testing.T) {
	cm := New()
	conn := cm.GetConn("nonexistent")
	if conn != nil {
		t.Fatal("expected nil for missing connection")
	}
}

func TestUnregister(t *testing.T) {
	cm := New()
	cm.Register("s1", nil)
	cm.Unregister("s1")
	conn := cm.GetConn("s1")
	if conn != nil {
		t.Fatal("expected nil after unregister")
	}
}

func TestUnregisterIfCurrent(t *testing.T) {
	cm := New()
	oldStream := &mockStream{}
	newStream := &mockStream{}

	cm.Register("s1", oldStream)
	cm.Register("s1", newStream)

	if cm.UnregisterIfCurrent("s1", oldStream) {
		t.Fatal("expected stale stream unregister to be ignored")
	}
	if cm.GetConn("s1") == nil {
		t.Fatal("expected current connection to remain registered")
	}
	if !cm.UnregisterIfCurrent("s1", newStream) {
		t.Fatal("expected current stream unregister to succeed")
	}
	if cm.GetConn("s1") != nil {
		t.Fatal("expected connection to be removed after unregistering current stream")
	}
}

func TestActiveServerIDs(t *testing.T) {
	cm := New()
	cm.Register("s1", nil)
	cm.Register("s2", nil)
	ids := cm.ActiveServerIDs()
	if len(ids) != 2 {
		t.Fatalf("expected 2 active IDs, got %d", len(ids))
	}
	found := map[string]bool{}
	for _, id := range ids {
		found[id] = true
	}
	if !found["s1"] || !found["s2"] {
		t.Fatalf("expected s1 and s2, got %v", ids)
	}
}

func TestUpdateHeartbeat(t *testing.T) {
	cm := New()
	cm.Register("s1", nil)
	before := cm.GetConn("s1").LastSeen
	time.Sleep(10 * time.Millisecond)
	cm.UpdateHeartbeat("s1")
	after := cm.GetConn("s1").LastSeen
	if !after.After(before) {
		t.Fatal("expected LastSeen to advance after heartbeat")
	}
}

func TestStaleConnections(t *testing.T) {
	cm := New()
	cm.Register("s1", nil)
	cm.mu.Lock()
	cm.streams["s1"].LastSeen = time.Now().Add(-60 * time.Second)
	cm.mu.Unlock()
	cm.Register("s2", nil) // fresh
	stale := cm.StaleConnections(30 * time.Second)
	if len(stale) != 1 {
		t.Fatalf("expected 1 stale, got %d", len(stale))
	}
	if stale[0] != "s1" {
		t.Fatalf("expected s1 to be stale, got %s", stale[0])
	}
}

func TestSendToAgent_NotConnected(t *testing.T) {
	cm := New()
	err := cm.SendToAgent("nonexistent", &pb.HubMessage{})
	if err == nil {
		t.Fatal("expected error for missing connection")
	}
}
