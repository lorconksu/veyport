package connmgr

import (
	"context"
	"fmt"
	"sync"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

type AgentConn struct {
	ServerID  string
	Stream    pb.AgentService_ConnectServer
	LastSeen  time.Time
	SendMu    sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
}

func (c *AgentConn) Done() <-chan struct{} { return c.done }
func (c *AgentConn) Close()                { c.closeOnce.Do(func() { close(c.done) }) }

type ConnManager struct {
	mu      sync.RWMutex
	streams map[string]*AgentConn
}

func New() *ConnManager {
	return &ConnManager{
		streams: make(map[string]*AgentConn),
	}
}

// Register returns the exact installed generation, even if a concurrent
// reconnect replaces it before the caller starts watching Done.
func (cm *ConnManager) Register(serverID string, stream pb.AgentService_ConnectServer) *AgentConn {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if previous := cm.streams[serverID]; previous != nil {
		previous.Close()
	}
	connection := &AgentConn{
		ServerID: serverID,
		Stream:   stream,
		LastSeen: time.Now(),
		done:     make(chan struct{}),
	}
	cm.streams[serverID] = connection
	return connection
}

func (cm *ConnManager) Unregister(serverID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if conn := cm.streams[serverID]; conn != nil {
		conn.Close()
	}
	delete(cm.streams, serverID)
}

func (cm *ConnManager) UnregisterIfCurrent(serverID string, stream pb.AgentService_ConnectServer) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	conn, ok := cm.streams[serverID]
	if !ok || conn.Stream != stream {
		return false
	}
	conn.Close()
	delete(cm.streams, serverID)
	return true
}

func (cm *ConnManager) GetConn(serverID string) *AgentConn {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.streams[serverID]
}

func (cm *ConnManager) ActiveServerIDs() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	ids := make([]string, 0, len(cm.streams))
	for id := range cm.streams {
		ids = append(ids, id)
	}
	return ids
}

func (cm *ConnManager) UpdateHeartbeat(serverID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if conn, ok := cm.streams[serverID]; ok {
		conn.LastSeen = time.Now()
	}
}

func (cm *ConnManager) StaleConnections(maxAge time.Duration) []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	cutoff := time.Now().Add(-maxAge)
	var stale []string
	for id, conn := range cm.streams {
		if conn.LastSeen.Before(cutoff) {
			stale = append(stale, id)
		}
	}
	return stale
}

func (cm *ConnManager) SendToAgent(serverID string, msg *pb.HubMessage) error {
	conn := cm.GetConn(serverID)
	if conn == nil {
		return fmt.Errorf("agent not connected: %s", serverID)
	}
	conn.SendMu.Lock()
	defer conn.SendMu.Unlock()
	return conn.Stream.Send(msg)
}

// SendToAgentContext bounds a control send. Timeout closes the registered
// Connect handler, which cancels the underlying gRPC stream and its blocked
// sender. Callers reserve execution capacity before using this method.
func (cm *ConnManager) SendToAgentContext(ctx context.Context, serverID string, msg *pb.HubMessage) error {
	conn := cm.GetConn(serverID)
	if conn == nil {
		return fmt.Errorf("agent not connected: %s", serverID)
	}
	result := make(chan error, 1)
	go func() {
		conn.SendMu.Lock()
		defer conn.SendMu.Unlock()
		select {
		case <-conn.Done():
			result <- fmt.Errorf("agent disconnected: %s", serverID)
			return
		default:
		}
		result <- conn.Stream.Send(msg)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		conn.Close()
		return ctx.Err()
	case <-conn.Done():
		return fmt.Errorf("agent disconnected: %s", serverID)
	}
}
