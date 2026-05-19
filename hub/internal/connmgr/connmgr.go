package connmgr

import (
	"fmt"
	"sync"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

type AgentConn struct {
	ServerID string
	Stream   pb.AgentService_ConnectServer
	LastSeen time.Time
	SendMu   sync.Mutex
}

type ConnManager struct {
	mu      sync.RWMutex
	streams map[string]*AgentConn
}

func New() *ConnManager {
	return &ConnManager{
		streams: make(map[string]*AgentConn),
	}
}

func (cm *ConnManager) Register(serverID string, stream pb.AgentService_ConnectServer) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.streams[serverID] = &AgentConn{
		ServerID: serverID,
		Stream:   stream,
		LastSeen: time.Now(),
	}
}

func (cm *ConnManager) Unregister(serverID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.streams, serverID)
}

func (cm *ConnManager) UnregisterIfCurrent(serverID string, stream pb.AgentService_ConnectServer) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	conn, ok := cm.streams[serverID]
	if !ok || conn.Stream != stream {
		return false
	}
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
