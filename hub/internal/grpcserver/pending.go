package grpcserver

import (
	"sync"

	"google.golang.org/protobuf/proto"
)

// PendingRequests tracks in-flight request-response correlations.
// Keys are scoped per server (serverID:requestID) to prevent a
// compromised agent from delivering responses for another agent.
type PendingRequests struct {
	mu        sync.Mutex
	channels  map[string]chan proto.Message
	fileReads map[string]*pendingFileRead
}

func NewPendingRequests() *PendingRequests {
	return &PendingRequests{
		channels:  make(map[string]chan proto.Message),
		fileReads: make(map[string]*pendingFileRead),
	}
}

func makeKey(serverID, requestID string) string {
	return serverID + ":" + requestID
}

func (p *PendingRequests) Register(serverID, requestID string) chan proto.Message {
	ch := make(chan proto.Message, 1)
	p.mu.Lock()
	p.channels[makeKey(serverID, requestID)] = ch
	p.mu.Unlock()
	return ch
}

func (p *PendingRequests) Deliver(serverID, requestID string, msg proto.Message) bool {
	key := makeKey(serverID, requestID)
	p.mu.Lock()
	ch, ok := p.channels[key]
	p.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- msg:
		return true
	default:
		return false
	}
}

func (p *PendingRequests) Remove(serverID, requestID string) {
	p.mu.Lock()
	key := makeKey(serverID, requestID)
	delete(p.channels, key)
	read := p.fileReads[key]
	delete(p.fileReads, key)
	p.mu.Unlock()
	if read != nil {
		read.mu.Lock()
		read.finished = true
		read.data = nil
		read.mu.Unlock()
	}
}
