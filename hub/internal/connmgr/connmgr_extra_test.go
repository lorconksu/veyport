package connmgr

import (
	"context"
	"testing"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/metadata"
)

// mockStream implements pb.AgentService_ConnectServer for testing SendToAgent.
type mockStream struct {
	ctx     context.Context
	sent    []*pb.HubMessage
	sendErr error
}

func (m *mockStream) Send(msg *pb.HubMessage) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, msg)
	return nil
}

func (m *mockStream) Recv() (*pb.AgentMessage, error) { return nil, nil }

func (m *mockStream) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}

func (m *mockStream) SendMsg(v interface{}) error  { return nil }
func (m *mockStream) RecvMsg(v interface{}) error  { return nil }
func (m *mockStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockStream) SendHeader(metadata.MD) error { return nil }
func (m *mockStream) SetTrailer(metadata.MD) {
	// no-op: mock stub for testing
}
func (m *mockStream) SendAndClose(*pb.HubMessage) error { return nil }

// TestSendToAgent_Connected verifies that SendToAgent sends to a connected stream.
func TestSendToAgent_Connected(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	cm.Register("s1", stream)

	msg := &pb.HubMessage{
		Payload: &pb.HubMessage_HeartbeatAck{
			HeartbeatAck: &pb.HeartbeatAck{Timestamp: 12345},
		},
	}

	if err := cm.SendToAgent("s1", msg); err != nil {
		t.Fatalf("send to connected agent: %v", err)
	}

	if len(stream.sent) != 1 {
		t.Fatalf("expected 1 message sent, got %d", len(stream.sent))
	}
}

// TestUpdateHeartbeat_NonExistentConn verifies that updating heartbeat for missing conn is safe.
func TestUpdateHeartbeat_NonExistentConn(t *testing.T) {
	cm := New()
	// Should not panic for non-existent connection
	cm.UpdateHeartbeat("nonexistent")
}

// TestStaleConnections_Empty verifies empty connmgr returns no stale connections.
func TestStaleConnections_Empty(t *testing.T) {
	cm := New()
	stale := cm.StaleConnections(30e9) // 30s in ns
	if len(stale) != 0 {
		t.Fatalf("expected 0 stale connections, got %d", len(stale))
	}
}

// TestActiveServerIDs_Empty verifies empty connmgr returns empty ID list.
func TestActiveServerIDs_Empty(t *testing.T) {
	cm := New()
	ids := cm.ActiveServerIDs()
	if len(ids) != 0 {
		t.Fatalf("expected 0 active IDs, got %d", len(ids))
	}
}
