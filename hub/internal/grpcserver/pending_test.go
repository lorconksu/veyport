package grpcserver

import (
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const testReqFull = "req-full"

func TestPendingRequests_RegisterAndDeliver(t *testing.T) {
	p := NewPendingRequests()
	ch := p.Register("s1", "req-1")
	defer p.Remove("s1", "req-1")

	resp := &pb.FileListResponse{RequestId: "req-1"}
	delivered := p.Deliver("s1", "req-1", resp)
	if !delivered {
		t.Fatal("expected delivery to succeed")
	}

	select {
	case msg := <-ch:
		got, ok := msg.(*pb.FileListResponse)
		if !ok {
			t.Fatalf("expected *FileListResponse, got %T", msg)
		}
		if got.RequestId != "req-1" {
			t.Fatalf("expected request_id 'req-1', got '%s'", got.RequestId)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for response")
	}
}

func TestPendingRequests_DeliverNotFound(t *testing.T) {
	p := NewPendingRequests()
	delivered := p.Deliver("s1", "nonexistent", &pb.FileListResponse{})
	if delivered {
		t.Fatal("expected delivery to fail for unknown request_id")
	}
}

func TestPendingRequests_Remove(t *testing.T) {
	p := NewPendingRequests()
	p.Register("s1", "req-1")
	p.Remove("s1", "req-1")
	delivered := p.Deliver("s1", "req-1", &pb.FileListResponse{})
	if delivered {
		t.Fatal("expected delivery to fail after remove")
	}
}

// TestPendingRequests_DeliverChannelFull verifies that Deliver returns false
// when the channel buffer is already full (default branch in select).
func TestPendingRequests_DeliverChannelFull(t *testing.T) {
	p := NewPendingRequests()
	p.Register("s1", testReqFull)
	defer p.Remove("s1", testReqFull)

	// First deliver fills the buffer (capacity 1)
	ok := p.Deliver("s1", testReqFull, &pb.FileListResponse{RequestId: testReqFull})
	if !ok {
		t.Fatal("first delivery should succeed")
	}

	// Second deliver should fail because the channel is full
	ok = p.Deliver("s1", testReqFull, &pb.FileListResponse{RequestId: testReqFull})
	if ok {
		t.Fatal("second delivery should fail (channel full)")
	}
}

func TestPendingRequests_CrossServerIsolation(t *testing.T) {
	p := NewPendingRequests()
	p.Register("s1", "req-1")
	defer p.Remove("s1", "req-1")

	// A different server trying to deliver to the same requestID should fail
	delivered := p.Deliver("s2", "req-1", &pb.FileListResponse{})
	if delivered {
		t.Fatal("expected delivery from different server to fail (cross-agent spoofing)")
	}

	// The correct server should succeed
	delivered = p.Deliver("s1", "req-1", &pb.FileListResponse{RequestId: "req-1"})
	if !delivered {
		t.Fatal("expected delivery from correct server to succeed")
	}
}
