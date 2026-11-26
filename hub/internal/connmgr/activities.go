package connmgr

import (
	"context"
	"errors"
	"strings"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

const MaxNodeActivities = 128
const MaxActivities = 4096

const (
	fileReadStopWait               = 2 * time.Second
	fileReadStopWriteHealthTimeout = 30 * time.Second
)

var ErrActivityBusy = errors.New("agent has active or unconfirmed file/upload/log work")
var ErrActivityCapacity = errors.New("agent activity capacity reached; wait for actual completion")

type ActivityKind string

const (
	ActivityList        ActivityKind = "file-list"
	ActivityRead        ActivityKind = "file-read"
	ActivityDelete      ActivityKind = "file-delete"
	ActivityUpload      ActivityKind = "upload"
	ActivityLog         ActivityKind = "log"
	ActivityApplication ActivityKind = "application"
)

type activityKey struct {
	connection *AgentConn
	id         string
	kind       ActivityKind
}
type activityRecord struct{ dispatched, abandoned bool }

// Activity keeps remote lifetime separate from its HTTP response waiter.
// Abandon never treats an already-dispatched worker as finished.
type Activity struct {
	manager *ConnManager
	key     activityKey
}

func (cm *ConnManager) BeginRequest(conn *AgentConn, msg *pb.HubMessage) (*Activity, error) {
	return cm.BeginRequestContext(context.Background(), conn, msg)
}

func (cm *ConnManager) BeginRequestContext(ctx context.Context, conn *AgentConn, msg *pb.HubMessage) (*Activity, error) {
	kind, id := messageActivity(msg)
	return cm.beginActivity(ctx, conn, id, kind)
}
func (cm *ConnManager) CompleteResponse(node string, stream pb.AgentService_ConnectServer, msg proto.Message) bool {
	var kind ActivityKind
	var id string
	switch p := msg.(type) {
	case *pb.FileListResponse:
		kind, id = ActivityList, p.GetRequestId()
	case *pb.FileReadResponse:
		if p.ChunkOffset != nil && (!p.GetDone() || len(p.GetData()) != 0) {
			return false
		}
		kind, id = ActivityRead, p.GetRequestId()
	case *pb.FileDeleteResponse:
		kind, id = ActivityDelete, p.GetRequestId()
	case *pb.FileUploadAck:
		kind, id = ActivityUpload, p.GetRequestId()
	case *pb.LogStreamChunk:
		if !p.GetDone() {
			return false
		}
		kind, id = ActivityLog, p.GetRequestId()
	case *pb.ApplicationClosed:
		kind, id = ActivityApplication, p.GetBinding().GetConnectionId()
	default:
		return false
	}
	return cm.CompleteActivity(node, stream, id, kind)
}

func (a *Activity) Connection() *AgentConn { return a.key.connection }
func (a *Activity) Dispatched() bool {
	a.manager.mu.RLock()
	defer a.manager.mu.RUnlock()
	r := a.manager.activities[a.key]
	return r != nil && r.dispatched
}
func (a *Activity) Abandon() { a.manager.abandonActivity(a.key) }
func (a *Activity) Send(ctx context.Context, msg *pb.HubMessage) error {
	kind, id := messageActivity(msg)
	if kind != a.key.kind || id != a.key.id {
		return errors.New("activity message binding differs")
	}
	return a.manager.SendToConnectionChecked(ctx, a.key.connection, msg, func() error {
		return a.claimDispatch(ctx)
	})
}

// claimDispatch is the cancellation and generation boundary immediately before
// putting an admitted request on the wire. Abandon keeps committed work live.
func (a *Activity) claimDispatch(ctx context.Context) error {
	a.manager.mu.Lock()
	defer a.manager.mu.Unlock()
	r := a.manager.activities[a.key]
	if r == nil || r.abandoned || !a.manager.liveLocked(a.key.connection) {
		return errors.New("activity is no longer admitted")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.dispatched = true
	return nil
}

// SendImageRead lets a preview leave while awaiting admission or transport.
// After commit only the write health limit can close its shared connection.
func (a *Activity) SendImageRead(ctx context.Context, msg *pb.HubMessage, writeTimeout time.Duration) error {
	req := msg.GetFileReadRequest()
	if a.key.kind != ActivityRead || req.GetMode() != pb.FileReadMode_FILE_READ_MODE_IMAGE || req.GetRequestId() != a.key.id {
		return errors.New("image read message binding differs")
	}
	conn := a.key.connection
	if err := conn.SendMu.lockContext(ctx, conn); err != nil {
		return err
	}
	result := make(chan error)
	go func() {
		err := a.writeImageRead(ctx, conn, msg, writeTimeout)
		// A rendezvous transfers cancellation cleanup to the caller. If
		// the caller has already left, this writer owns cleanup.
		select {
		case result <- err:
		case <-ctx.Done():
			if err == nil {
				a.CancelImageRead()
			}
		case <-conn.Done():
		}
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-conn.Done():
		return errors.New("agent disconnected")
	}
}

func (a *Activity) writeImageRead(ctx context.Context, conn *AgentConn, msg *pb.HubMessage, writeTimeout time.Duration) error {
	defer conn.SendMu.Unlock()
	conn.GenerationMu.Lock()
	defer conn.GenerationMu.Unlock()
	if err := a.claimDispatch(ctx); err != nil {
		return err
	}
	return conn.withWriteHealthDeadline(writeTimeout, func() error { return a.manager.sendPrepared(conn, msg) })
}

func (a *Activity) CancelImageRead() {
	ctx, cancel := context.WithTimeout(context.Background(), fileReadStopWait)
	defer cancel()
	a.TryCancelFileRead(ctx)
}

// TryCancelFileRead skips a congested control writer. The caller can stop
// waiting independently of the write. An admitted write keeps both locks
// until gRPC returns and has its own connection-health deadline. The agent's
// read deadline is the fallback, and the stop never releases the activity.
func (a *Activity) TryCancelFileRead(ctx context.Context) {
	if a.key.kind != ActivityRead || !a.Dispatched() {
		return
	}
	conn := a.key.connection
	if !conn.SendMu.TryLock() {
		return
	}
	if !conn.GenerationMu.TryLock() {
		conn.SendMu.Unlock()
		return
	}
	msg := &pb.HubMessage{Payload: &pb.HubMessage_FileReadCancel{
		FileReadCancel: &pb.FileReadCancel{RequestId: a.key.id},
	}}
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		defer conn.SendMu.Unlock()
		defer conn.GenerationMu.Unlock()
		_ = a.manager.sendLocked(ctx, conn, msg, func(send func() error) error {
			return conn.withWriteHealthDeadline(fileReadStopWriteHealthTimeout, send)
		})
	}()
	select {
	case <-sent:
	case <-ctx.Done():
	case <-conn.Done():
	}
}

func validActivity(id string, kind ActivityKind) bool {
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "\x00\r\n") {
		return false
	}
	switch kind {
	case ActivityList, ActivityRead, ActivityDelete, ActivityUpload, ActivityLog, ActivityApplication:
		return true
	}
	return false
}
func (cm *ConnManager) BeginActivity(conn *AgentConn, id string, kind ActivityKind) (*Activity, error) {
	return cm.beginActivity(context.Background(), conn, id, kind)
}

func (cm *ConnManager) beginActivity(ctx context.Context, conn *AgentConn, id string, kind ActivityKind) (*Activity, error) {
	if conn == nil || !validActivity(id, kind) {
		return nil, errors.New("invalid activity binding")
	}
	if err := conn.SendMu.lockContext(ctx, conn); err != nil {
		return nil, err
	}
	defer conn.SendMu.Unlock()
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !cm.liveLocked(conn) {
		return nil, errors.New("agent connection changed or closed")
	}
	if cm.maintenance[conn.ServerID] != "" {
		return nil, errors.New("agent update maintenance is active")
	}
	key := activityKey{conn, id, kind}
	if cm.activities[key] != nil {
		return nil, errors.New("activity already admitted")
	}
	if err := cm.addActivityLocked(key); err != nil {
		return nil, err
	}
	return &Activity{cm, key}, nil
}
func (cm *ConnManager) liveLocked(conn *AgentConn) bool {
	if cm.streams[conn.ServerID] != conn {
		return false
	}
	select {
	case <-conn.Done():
		return false
	default:
		return true
	}
}
func (cm *ConnManager) addActivityLocked(key activityKey) error {
	if cm.activityNodes[key.connection.ServerID] >= MaxNodeActivities || len(cm.activities)+len(cm.uncertain) >= MaxActivities {
		return ErrActivityCapacity
	}
	cm.activities[key] = &activityRecord{}
	cm.activityNodes[key.connection.ServerID]++
	return nil
}
func (cm *ConnManager) removeActivityLocked(key activityKey) {
	if cm.activities[key] == nil {
		return
	}
	delete(cm.activities, key)
	node := key.connection.ServerID
	cm.activityNodes[node]--
	if cm.activityNodes[node] == 0 {
		// Completion can precede an already-queued count zero. Retain this
		// slot until count reconciliation so reconnect cannot allocate a new
		// uncertainty slot after another node filled the global capacity.
		if cm.activityCounts[key.connection] > 0 {
			cm.uncertain[node] = true
			cm.activityNodes[node] = 1
		} else {
			delete(cm.activityNodes, node)
		}
	}
}
func messageActivity(msg *pb.HubMessage) (ActivityKind, string) {
	switch p := msg.Payload.(type) {
	case *pb.HubMessage_FileListRequest:
		return ActivityList, p.FileListRequest.GetRequestId()
	case *pb.HubMessage_FileReadRequest:
		return ActivityRead, p.FileReadRequest.GetRequestId()
	case *pb.HubMessage_FileDeleteRequest:
		return ActivityDelete, p.FileDeleteRequest.GetRequestId()
	case *pb.HubMessage_FileUploadRequest:
		return ActivityUpload, p.FileUploadRequest.GetRequestId()
	case *pb.HubMessage_LogStreamRequest:
		return ActivityLog, p.LogStreamRequest.GetRequestId()
	case *pb.HubMessage_ApplicationOpen:
		return ActivityApplication, p.ApplicationOpen.GetBinding().GetConnectionId()
	}
	return "", ""
}

// prepareActivitySend runs under SendMu, covering direct internal sends too.
func (cm *ConnManager) prepareActivitySend(conn *AgentConn, msg *pb.HubMessage) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if !cm.liveLocked(conn) {
		return errors.New("agent connection changed or closed")
	}
	kind, id := messageActivity(msg)
	admission := kind != "" || msg.GetTerminalOpenRequest() != nil || msg.GetExecutionPrepare() != nil || msg.GetExecutionAttach() != nil
	key := activityKey{conn, id, kind}
	if admission && cm.maintenance[conn.ServerID] != "" && cm.activities[key] == nil {
		return errors.New("agent update maintenance is active")
	}
	if kind == "" {
		return nil
	}
	if !validActivity(id, kind) {
		return errors.New("invalid activity binding")
	}
	if cm.activities[key] == nil {
		if kind == ActivityUpload && msg.GetFileUploadRequest().GetFilename() == "" {
			return errors.New("upload continuation has no admitted upload")
		}
		if err := cm.addActivityLocked(key); err != nil {
			return err
		}
	}
	cm.activities[key].dispatched = true
	return nil
}
func (cm *ConnManager) abandonMessage(conn *AgentConn, msg *pb.HubMessage) {
	kind, id := messageActivity(msg)
	if kind != "" {
		cm.abandonActivity(activityKey{conn, id, kind})
	}
}
func (cm *ConnManager) abandonActivity(key activityKey) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if r := cm.activities[key]; r != nil {
		if !r.dispatched {
			cm.removeActivityLocked(key)
		} else {
			r.abandoned = true
		}
	}
}

// CompleteActivity releases only the exact current generation and typed request.
func (cm *ConnManager) CompleteActivity(node string, stream pb.AgentService_ConnectServer, id string, kind ActivityKind) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	conn := cm.streams[node]
	if conn == nil || conn.Stream != stream {
		return false
	}
	key := activityKey{conn, id, kind}
	if cm.activities[key] == nil {
		return false
	}
	cm.removeActivityLocked(key)
	return true
}

// A disconnected generation can still own workers. Collapse its entries into
// one bounded uncertainty slot, never a timeout-based claim of completion.
func (cm *ConnManager) endActivitiesLocked(conn *AgentConn) {
	unknown := cm.activityCounts[conn] > 0
	delete(cm.activityCounts, conn)
	for key, r := range cm.activities {
		if key.connection == conn {
			unknown = unknown || r.dispatched
			cm.removeActivityLocked(key)
		}
	}
	if unknown && !cm.uncertain[conn.ServerID] {
		cm.uncertain[conn.ServerID] = true
		cm.activityNodes[conn.ServerID]++
	}
}

// Ordered zero observations clear carried/count-reconciliation uncertainty.
// Current request records remain authoritative even when a zero was queued earlier.
func (cm *ConnManager) ObserveActivityCapabilities(node string, stream pb.AgentService_ConnectServer, version, count uint32) error {
	if version != 1 || count > MaxNodeActivities {
		return errors.New("unsupported activity capability")
	}
	conn := cm.GetConn(node)
	if conn == nil || conn.Stream != stream {
		return errors.New("stale activity capability")
	}
	conn.SendMu.Lock()
	defer conn.SendMu.Unlock()
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if !cm.liveLocked(conn) {
		return errors.New("stale activity capability")
	}
	// A positive reconnect count without known requests represents carried work.
	// Reserve its eventual uncertainty slot now, so disconnect cannot exceed caps.
	if count > 0 && cm.activityNodes[node] == 0 {
		if len(cm.activities)+len(cm.uncertain) >= MaxActivities {
			return ErrActivityCapacity
		}
		cm.uncertain[node] = true
		cm.activityNodes[node]++
	}
	if count > 0 {
		cm.activityCounts[conn] = count
	} else {
		delete(cm.activityCounts, conn)
	}
	if count == 0 {
		cm.clearUncertainLocked(node)
	}
	return nil
}
func (cm *ConnManager) clearUncertainLocked(node string) {
	if cm.uncertain[node] {
		delete(cm.uncertain, node)
		cm.activityNodes[node]--
		if cm.activityNodes[node] == 0 {
			delete(cm.activityNodes, node)
		}
	}
}
func (cm *ConnManager) activityIdle(conn *AgentConn, manual bool) error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.activityIdleLocked(conn, manual)
}
func (cm *ConnManager) activityIdleLocked(conn *AgentConn, manual bool) error {
	if cm.activityCounts[conn] > 0 {
		return ErrActivityBusy
	}
	if cm.uncertain[conn.ServerID] && !manual {
		return ErrActivityBusy
	}
	for key, r := range cm.activities {
		if key.connection.ServerID == conn.ServerID && (!manual || !r.abandoned) {
			return ErrActivityBusy
		}
	}
	return nil
}
func (cm *ConnManager) clearAbandonedActivitiesLocked(conn *AgentConn) {
	for key, r := range cm.activities {
		if key.connection == conn && r.abandoned {
			cm.removeActivityLocked(key)
		}
	}
	cm.clearUncertainLocked(conn.ServerID)
}
