package connmgr

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

type AgentConn struct {
	ServerID     string
	Stream       pb.AgentService_ConnectServer
	LastSeen     time.Time
	SendMu       sync.Mutex
	DeliveryMu   sync.Mutex
	GenerationMu sync.Mutex
	GenerationID string
	done         chan struct{}
	closeOnce    sync.Once
}

func (c *AgentConn) Done() <-chan struct{} { return c.done }
func (c *AgentConn) Close()                { c.closeOnce.Do(func() { close(c.done) }) }

type ConnManager struct {
	mu             sync.RWMutex
	streams        map[string]*AgentConn
	retiring       map[string]*AgentConn
	maintenance    map[string]string
	activities     map[activityKey]*activityRecord
	uncertain      map[string]bool
	activityNodes  map[string]int
	activityCounts map[*AgentConn]uint32
}

func New() *ConnManager {
	return &ConnManager{
		streams:        make(map[string]*AgentConn),
		retiring:       make(map[string]*AgentConn),
		maintenance:    make(map[string]string),
		activities:     make(map[activityKey]*activityRecord),
		uncertain:      make(map[string]bool),
		activityNodes:  make(map[string]int),
		activityCounts: make(map[*AgentConn]uint32),
	}
}

// Register returns the exact installed generation, even if a concurrent
// reconnect replaces it before the caller starts watching Done.
func (cm *ConnManager) Register(serverID string, stream pb.AgentService_ConnectServer) *AgentConn {
	connection := &AgentConn{
		ServerID:     serverID,
		Stream:       stream,
		LastSeen:     time.Now(),
		GenerationID: uuid.NewString(),
		done:         make(chan struct{}),
	}
	for {
		cm.mu.Lock()
		previous := cm.streams[serverID]
		retiring := cm.retiring[serverID]
		if previous == nil && retiring == nil {
			cm.streams[serverID] = connection
			cm.mu.Unlock()
			return connection
		}
		cm.mu.Unlock()

		if retiring != nil {
			// A closing generation remains installed until every send that was
			// admitted before Close has left GenerationMu. This makes removal the
			// exact retirement boundary while allowing its Connect handler to
			// return immediately and cancel a flow-controlled transport.
			retiring.GenerationMu.Lock()
			cm.mu.Lock()
			if cm.retiring[serverID] != retiring {
				cm.mu.Unlock()
				retiring.GenerationMu.Unlock()
				continue
			}
			if cm.streams[serverID] == retiring {
				delete(cm.streams, serverID)
			}
			delete(cm.retiring, serverID)
			if cm.streams[serverID] == nil {
				cm.streams[serverID] = connection
				cm.mu.Unlock()
				retiring.GenerationMu.Unlock()
				return connection
			}
			cm.mu.Unlock()
			retiring.GenerationMu.Unlock()
			continue
		}

		if previous != nil {
			// Detach first so the old Connect handler can return and cancel a
			// flow-controlled Send. Installation still waits below until every
			// ordered send on the retired generation has actually finished.
			cm.detachIfCurrent(serverID, previous)
			continue
		}

	}
}

func (cm *ConnManager) Unregister(serverID string) {
	cm.mu.RLock()
	conn := cm.streams[serverID]
	cm.mu.RUnlock()
	if conn != nil {
		cm.detachIfCurrent(serverID, conn)
	}
}

func (cm *ConnManager) UnregisterIfCurrent(serverID string, stream pb.AgentService_ConnectServer) bool {
	cm.mu.RLock()
	conn := cm.streams[serverID]
	cm.mu.RUnlock()
	if conn == nil || conn.Stream != stream {
		return false
	}
	return cm.detachIfCurrent(serverID, conn)
}

// detachIfCurrent starts closing a generation without waiting for an in-flight
// Send. It stays installed but is hidden from callers until GenerationMu proves
// every admitted Send has finished; only then is it retired and replaceable.
func (cm *ConnManager) detachIfCurrent(serverID string, conn *AgentConn) bool {
	conn.DeliveryMu.Lock()
	defer conn.DeliveryMu.Unlock()
	cm.mu.Lock()
	if cm.streams[serverID] != conn {
		cm.mu.Unlock()
		return false
	}
	conn.Close()
	cm.endActivitiesLocked(conn)
	cm.retiring[serverID] = conn
	cm.mu.Unlock()
	go cm.finishRetirement(conn)
	return true
}

func (cm *ConnManager) finishRetirement(conn *AgentConn) {
	conn.GenerationMu.Lock()
	defer conn.GenerationMu.Unlock()
	cm.mu.Lock()
	if cm.retiring[conn.ServerID] == conn {
		if cm.streams[conn.ServerID] == conn {
			delete(cm.streams, conn.ServerID)
		}
		delete(cm.retiring, conn.ServerID)
	}
	cm.mu.Unlock()
}

func (cm *ConnManager) GetConn(serverID string) *AgentConn {
	cm.mu.RLock()
	conn := cm.streams[serverID]
	cm.mu.RUnlock()
	if conn != nil {
		select {
		case <-conn.Done():
			return nil
		default:
		}
	}
	return conn
}

// WithCurrentGeneration runs fn only while stream is the exact installed
// connection generation. Replacement and unregister wait for fn to finish, so
// a message that passed the check cannot be delivered after its generation was
// retired.
func (cm *ConnManager) WithCurrentGeneration(serverID string, stream pb.AgentService_ConnectServer, fn func(*AgentConn)) bool {
	cm.mu.RLock()
	conn := cm.streams[serverID]
	cm.mu.RUnlock()
	if conn == nil || conn.Stream != stream {
		return false
	}
	select {
	case <-conn.Done():
		return false
	default:
	}
	conn.DeliveryMu.Lock()
	defer conn.DeliveryMu.Unlock()
	cm.mu.RLock()
	current := cm.streams[serverID] == conn && conn.Stream == stream
	cm.mu.RUnlock()
	select {
	case <-conn.Done():
		current = false
	default:
	}
	if !current {
		return false
	}
	fn(conn)
	return true
}

func (cm *ConnManager) ActiveServerIDs() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	ids := make([]string, 0, len(cm.streams))
	for id, conn := range cm.streams {
		select {
		case <-conn.Done():
		default:
			ids = append(ids, id)
		}
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
	return cm.SendToConnectionChecked(context.Background(), conn, msg, func() error {
		if cm.GetConn(serverID) != conn {
			return fmt.Errorf("agent connection changed: %s", serverID)
		}
		return nil
	})
}

// SendToAgentContext bounds a control send. Timeout closes the registered
// Connect handler, which cancels the underlying gRPC stream and its blocked
// sender. Callers reserve execution capacity before using this method.
func (cm *ConnManager) SendToAgentContext(ctx context.Context, serverID string, msg *pb.HubMessage) error {
	return cm.SendToConnectionChecked(ctx, cm.GetConn(serverID), msg, nil)
}

// SendToConnectionChecked binds a send to one control generation. The final
// local check and send share that connection's send order with terminal closes;
// the check releases any policy/registry locks before network I/O starts.
func (cm *ConnManager) SendToConnectionChecked(ctx context.Context, conn *AgentConn, msg *pb.HubMessage, check func() error) error {
	return cm.SendToConnectionGuarded(ctx, conn, msg, func(send func() error) error {
		if check != nil {
			if err := check(); err != nil {
				return err
			}
		}
		return send()
	})
}

// SendToConnectionGuarded lets a caller hold its authorization boundary across
// both the final decision and the ordered stream send. The guard runs while the
// exact connection's SendMu is held; it must invoke send at most once.
func (cm *ConnManager) SendToConnectionGuarded(ctx context.Context, conn *AgentConn, msg *pb.HubMessage, guard func(send func() error) error) error {
	if conn == nil {
		return fmt.Errorf("agent not connected")
	}
	result := make(chan error, 1)
	go func() {
		conn.SendMu.Lock()
		defer conn.SendMu.Unlock()
		conn.GenerationMu.Lock()
		defer conn.GenerationMu.Unlock()
		select {
		case <-conn.Done():
			result <- fmt.Errorf("agent disconnected: %s", conn.ServerID)
			return
		case <-ctx.Done():
			result <- ctx.Err()
			return
		default:
		}
		send := func() error {
			if err := cm.prepareActivitySend(conn, msg); err != nil {
				return err
			}
			err := conn.Stream.Send(msg)
			if err != nil {
				cm.abandonMessage(conn, msg)
			}
			return err
		}
		var err error
		if guard != nil {
			err = guard(send)
		} else {
			err = send()
		}
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		conn.Close()
		return ctx.Err()
	case <-conn.Done():
		return fmt.Errorf("agent disconnected: %s", conn.ServerID)
	}
}

// ReserveMaintenance shares the exact control send order with admissions.
// The callback may acquire the policy/store lock; it must not send network data.
func (cm *ConnManager) ReserveMaintenance(conn *AgentConn, id string, check func() error) error {
	return cm.ReserveMaintenanceWithIdleAssertion(conn, id, false, check)
}

// Manual idle assertion may reconcile abandoned work only; live work always refuses.
func (cm *ConnManager) ReserveMaintenanceWithIdleAssertion(conn *AgentConn, id string, manual bool, check func() error) error {
	if conn == nil {
		return fmt.Errorf("agent not connected")
	}
	conn.SendMu.Lock()
	defer conn.SendMu.Unlock()
	if cm.GetConn(conn.ServerID) != conn {
		return fmt.Errorf("agent connection changed")
	}
	select {
	case <-conn.Done():
		return fmt.Errorf("agent disconnected")
	default:
	}
	cm.mu.RLock()
	active := cm.maintenance[conn.ServerID]
	cm.mu.RUnlock()
	if active != "" {
		return fmt.Errorf("agent maintenance is already reserved")
	}
	if err := cm.activityIdle(conn, manual); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	// Register may replace this generation while the local callback persists
	// authority. Commit freshness, idle state and maintenance together; never
	// apply an old manual assertion to a replacement connection.
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if !cm.liveLocked(conn) {
		return fmt.Errorf("agent connection changed during maintenance reservation")
	}
	if cm.maintenance[conn.ServerID] != "" {
		return fmt.Errorf("agent maintenance is already reserved")
	}
	if err := cm.activityIdleLocked(conn, manual); err != nil {
		return err
	}
	if manual {
		cm.clearAbandonedActivitiesLocked(conn)
	}
	cm.maintenance[conn.ServerID] = id
	return nil
}
func (cm *ConnManager) SetMaintenance(node, id string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if id == "" {
		delete(cm.maintenance, node)
	} else {
		cm.maintenance[node] = id
	}
}
func (cm *ConnManager) ReleaseMaintenance(node, id string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.maintenance[node] == id {
		delete(cm.maintenance, node)
	}
}
