package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/applicationtransport"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/proto/applicationproxy"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

const MaxApplicationTunnels = 128
const MaxNodeApplicationTunnels = 32
const ApplicationOpenTimeout = 10 * time.Second

var ErrApplicationUnavailable = errors.New("application transport unavailable")
var ErrApplicationCapacity = errors.New("application connection capacity reached")

type applicationCapability struct {
	connection *connmgr.AgentConn
	value      *pb.ApplicationCapabilities
}
type ApplicationTunnels struct {
	mu           sync.Mutex
	store        *store.Store
	connections  *connmgr.ConnManager
	validate     applicationtransport.Validator
	dial         applicationproxy.Dialer
	capabilities map[string]applicationCapability
	nodes        map[string]*applicationTunnel
	nodeCounts   map[string]int
	direct       map[*directApplicationConn]bool
	rpcSlots     chan struct{}
	rpcNodes     map[string]int
	closed       bool
}
type applicationTunnel struct {
	ctx       context.Context
	cancel    context.CancelFunc
	control   *connmgr.AgentConn
	binding   *pb.ApplicationBinding
	target    applicationtransport.Target
	ticket    [32]byte
	attached  bool
	activity  *connmgr.Activity
	conn      *applicationproxy.Conn
	ready     chan error
	readyOnce sync.Once
}

func (s *applicationTunnel) reportReady(err error) { s.readyOnce.Do(func() { s.ready <- err }) }

// NewApplicationTunnels requires a persisted-config validator. A missing one
// fails closed even on direct routes; HTTP authorization remains a separate gate.
func NewApplicationTunnels(st *store.Store, cm *connmgr.ConnManager, validate applicationtransport.Validator) *ApplicationTunnels {
	return &ApplicationTunnels{store: st, connections: cm, validate: validate, capabilities: make(map[string]applicationCapability), nodes: make(map[string]*applicationTunnel), nodeCounts: make(map[string]int), direct: make(map[*directApplicationConn]bool), rpcSlots: make(chan struct{}, MaxApplicationTunnels), rpcNodes: make(map[string]int)}
}
func (t *ApplicationTunnels) reserveRPC(node string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.rpcNodes[node] >= MaxNodeApplicationTunnels {
		return false
	}
	select {
	case t.rpcSlots <- struct{}{}:
		t.rpcNodes[node]++
		return true
	default:
		return false
	}
}
func (t *ApplicationTunnels) releaseRPC(node string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rpcNodes[node]--
	if t.rpcNodes[node] == 0 {
		delete(t.rpcNodes, node)
	}
	<-t.rpcSlots
}

// SetForbiddenEndpoints configures protected numeric listener addresses before
// the listeners start. A copied snapshot is used by every asynchronous dial.
func (t *ApplicationTunnels) SetForbiddenEndpoints(endpoints []netip.AddrPort) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dial.Forbidden = append([]netip.AddrPort(nil), endpoints...)
}

// Authorities are resolved afresh by the dialing side, closing DNS and Docker
// published-address gaps that a startup-only interface snapshot cannot cover.
func (t *ApplicationTunnels) SetForbiddenAuthorities(authorities []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dial.ForbiddenAuthorities = append([]string(nil), authorities...)
}
func (t *ApplicationTunnels) ApplicationAvailability(node string) (bool, bool) {
	if node == "" {
		return true, true
	}
	control := t.connections.GetConn(node)
	t.mu.Lock()
	defer t.mu.Unlock()
	capability := t.capabilities[node]
	return !t.closed && capability.connection == control && capability.value != nil && capability.value.RawTcp, control != nil && applicationControlOpen(control)
}
func applicationControlOpen(c *connmgr.AgentConn) bool {
	if c == nil {
		return false
	}
	select {
	case <-c.Done():
		return false
	default:
		return true
	}
}
func (t *ApplicationTunnels) ObserveCapabilities(node string, stream pb.AgentService_ConnectServer, value *pb.ApplicationCapabilities) error {
	control := t.connections.GetConn(node)
	if control == nil || control.Stream != stream || value == nil || value.ProtocolVersion != 1 || !value.RawTcp || len(value.BootId) < 16 || len(value.BootId) > 128 {
		return ErrApplicationUnavailable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.connections.GetConn(node) != control || !applicationControlOpen(control) {
		return ErrApplicationUnavailable
	}
	t.capabilities[node] = applicationCapability{control, proto.Clone(value).(*pb.ApplicationCapabilities)}
	return nil
}
func (t *ApplicationTunnels) DialApplication(ctx context.Context, target applicationtransport.Target) (net.Conn, error) {
	target = target.Copy()
	if t.validate == nil {
		return nil, ErrApplicationUnavailable
	}
	if err := applicationproxy.ValidateTarget(target); err != nil {
		return nil, err
	}
	if err := t.validate(ctx, target); err != nil {
		return nil, err
	}
	if target.NodeID == "" {
		return t.dialDirect(ctx, target)
	}
	return t.dialNode(ctx, target)
}
func (t *ApplicationTunnels) dialDirect(ctx context.Context, target applicationtransport.Target) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	c := &directApplicationConn{owner: t, done: make(chan struct{}), cancel: cancel}
	t.mu.Lock()
	if t.closed || len(t.nodes)+len(t.direct) >= MaxApplicationTunnels {
		t.mu.Unlock()
		cancel()
		return nil, ErrApplicationCapacity
	}
	t.direct[c] = true
	t.mu.Unlock()
	t.mu.Lock()
	dial := t.dial
	dial.Forbidden = append([]netip.AddrPort(nil), dial.Forbidden...)
	dial.ForbiddenAuthorities = append([]string(nil), dial.ForbiddenAuthorities...)
	t.mu.Unlock()
	conn, err := dial.DialTarget(ctx, target)
	if err != nil {
		c.Close()
		return nil, err
	}
	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		conn.Close()
		return nil, ErrApplicationUnavailable
	default:
	}
	c.Conn = conn
	c.mu.Unlock()
	// Configuration can change while DNS or the TCP handshake is in progress.
	if err := t.validate(ctx, target); err != nil {
		c.Close()
		return nil, err
	}
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-c.done:
		}
	}()
	return c, nil
}
func (t *ApplicationTunnels) dialNode(ctx context.Context, target applicationtransport.Target) (net.Conn, error) {
	if t.store == nil {
		return nil, ErrApplicationUnavailable
	}
	node, err := t.store.GetServerByID(target.NodeID)
	if err != nil || node.RegistrationToken != nil || node.Status != "online" {
		return nil, ErrApplicationUnavailable
	}
	control := t.connections.GetConn(target.NodeID)
	if !applicationControlOpen(control) {
		return nil, ErrApplicationUnavailable
	}
	child, cancel := context.WithCancel(ctx)
	s := &applicationTunnel{ctx: child, cancel: cancel, control: control, target: target, ready: make(chan error, 1)}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		cancel()
		return nil, err
	}
	s.ticket = sha256.Sum256(secret[:])
	t.mu.Lock()
	capability := t.capabilities[target.NodeID]
	if t.closed || len(t.nodes)+len(t.direct) >= MaxApplicationTunnels || t.nodeCounts[target.NodeID] >= MaxNodeApplicationTunnels {
		t.mu.Unlock()
		cancel()
		return nil, ErrApplicationCapacity
	}
	if capability.connection != control || capability.value == nil || !capability.value.RawTcp {
		t.mu.Unlock()
		cancel()
		return nil, ErrApplicationUnavailable
	}
	s.binding = &pb.ApplicationBinding{ConnectionId: uuid.NewString(), ApplicationId: target.ApplicationID, ConfigVersion: target.ConfigVersion, NodeId: target.NodeID, ControlGeneration: control.GenerationID, BootId: capability.value.BootId, ExpiresUnixMilli: time.Now().Add(30 * time.Second).UnixMilli()}
	t.nodes[s.binding.ConnectionId] = s
	t.nodeCounts[target.NodeID]++
	t.mu.Unlock()
	t.mu.Lock()
	forbidden := []string{}
	for _, authority := range t.dial.ForbiddenAuthorities {
		host, _, err := net.SplitHostPort(authority)
		if err != nil {
			forbidden = append(forbidden, authority)
			continue
		}
		ip, err := netip.ParseAddr(host)
		if host == "localhost" || (err == nil && (ip.IsLoopback() || ip.IsUnspecified())) {
			continue
		}
		forbidden = append(forbidden, authority)
	}
	for _, endpoint := range t.dial.Forbidden {
		if !endpoint.Addr().IsLoopback() && !endpoint.Addr().IsUnspecified() {
			forbidden = append(forbidden, endpoint.String())
		}
	}
	t.mu.Unlock()
	open := &pb.HubMessage{Payload: &pb.HubMessage_ApplicationOpen{ApplicationOpen: &pb.ApplicationOpen{Binding: proto.Clone(s.binding).(*pb.ApplicationBinding), Target: &pb.ApplicationTarget{Scheme: target.Scheme, Hostname: target.Hostname, Port: uint32(target.Port), AllowedCidrs: append([]string(nil), target.AllowedCIDRs...), ForbiddenAuthorities: forbidden}, AttachTicket: secret[:]}}}
	activity, err := t.connections.BeginRequest(control, open)
	if err != nil {
		t.remove(s)
		cancel()
		return nil, err
	}
	s.activity = activity
	sendCtx, sendCancel := context.WithTimeout(child, time.Second)
	err = t.connections.SendToConnectionChecked(sendCtx, control, open, func() error { return t.checkAdmission(s) })
	sendCancel()
	if err != nil {
		activity.Abandon()
		cancel()
		if activity.Dispatched() {
			go t.watch(s)
		} else {
			t.remove(s)
		}
		return nil, err
	}
	go t.watch(s)
	timer := time.NewTimer(ApplicationOpenTimeout)
	defer timer.Stop()
	select {
	case err := <-s.ready:
		if err != nil {
			cancel()
			return nil, err
		}
		if child.Err() != nil {
			return nil, child.Err()
		}
		return s.conn, nil
	case <-child.Done():
		cancel()
		return nil, child.Err()
	case <-timer.C:
		cancel()
		return nil, errors.New("application opening timed out")
	}
}
func (t *ApplicationTunnels) checkAdmission(s *applicationTunnel) error {
	if s.ctx.Err() != nil || t.connections.GetConn(s.target.NodeID) != s.control || !applicationControlOpen(s.control) || time.Now().UnixMilli() >= s.binding.ExpiresUnixMilli {
		return ErrApplicationUnavailable
	}
	if err := t.validate(s.ctx, s.target); err != nil {
		return err
	}
	node, err := t.store.GetServerByID(s.target.NodeID)
	if err != nil || node.RegistrationToken != nil || node.Status != "online" {
		return ErrApplicationUnavailable
	}
	return nil
}
func (t *ApplicationTunnels) watch(s *applicationTunnel) {
	select {
	case <-s.ctx.Done():
	case <-s.control.Done():
		s.cancel()
	}
	t.mu.Lock()
	conn := s.conn
	t.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	s.reportReady(ErrApplicationUnavailable)
	if !applicationControlOpen(s.control) {
		t.remove(s)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = t.connections.SendToConnectionChecked(ctx, s.control, &pb.HubMessage{Payload: &pb.HubMessage_ApplicationClose{ApplicationClose: &pb.ApplicationClose{Binding: proto.Clone(s.binding).(*pb.ApplicationBinding), ReasonCode: "cancelled"}}}, nil)
}
func (t *ApplicationTunnels) remove(s *applicationTunnel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nodes[s.binding.ConnectionId] != s {
		return
	}
	delete(t.nodes, s.binding.ConnectionId)
	t.nodeCounts[s.target.NodeID]--
	if t.nodeCounts[s.target.NodeID] == 0 {
		delete(t.nodeCounts, s.target.NodeID)
	}
}
func (t *ApplicationTunnels) ObserveClosed(node string, stream pb.AgentService_ConnectServer, closed *pb.ApplicationClosed) error {
	if closed == nil || closed.Binding == nil || closed.Binding.NodeId != node {
		return ErrApplicationUnavailable
	}
	t.mu.Lock()
	s := t.nodes[closed.Binding.ConnectionId]
	t.mu.Unlock()
	if s == nil {
		return nil
	}
	if s.control.Stream != stream || !proto.Equal(s.binding, closed.Binding) {
		return ErrApplicationUnavailable
	}
	t.connections.CompleteResponse(node, stream, closed)
	s.cancel()
	t.remove(s)
	return nil
}
func (t *ApplicationTunnels) EndConnection(node string, stream pb.AgentService_ConnectServer) {
	t.mu.Lock()
	if capability := t.capabilities[node]; capability.connection != nil && capability.connection.Stream == stream {
		delete(t.capabilities, node)
	}
	var sessions []*applicationTunnel
	for _, s := range t.nodes {
		if s.target.NodeID == node && s.control.Stream == stream {
			sessions = append(sessions, s)
		}
	}
	t.mu.Unlock()
	for _, s := range sessions {
		s.cancel()
		t.remove(s)
	}
}
func (t *ApplicationTunnels) Close() {
	t.mu.Lock()
	t.closed = true
	var sessions []*applicationTunnel
	for _, s := range t.nodes {
		sessions = append(sessions, s)
	}
	var direct []*directApplicationConn
	for c := range t.direct {
		direct = append(direct, c)
	}
	t.mu.Unlock()
	for _, s := range sessions {
		s.cancel()
	}
	for _, c := range direct {
		c.Close()
	}
}

type directApplicationConn struct {
	net.Conn
	mu     sync.Mutex
	owner  *ApplicationTunnels
	once   sync.Once
	done   chan struct{}
	cancel context.CancelFunc
}

func (c *directApplicationConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.done)
		if c.cancel != nil {
			c.cancel()
		}
		c.mu.Lock()
		if c.Conn != nil {
			err = c.Conn.Close()
		}
		c.mu.Unlock()
		c.owner.mu.Lock()
		delete(c.owner.direct, c)
		c.owner.mu.Unlock()
	})
	return err
}
func (c *directApplicationConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}
