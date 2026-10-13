package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/proto/updateutil"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const MaxAgentArtifactBytes int64 = 128 << 20

var ErrAgentUpdateDenied = errors.New("agent updates require a live interactive administrator session and an installation that has never enrolled governance")

type updateCapability struct {
	connection *connmgr.AgentConn
	value      *pb.UpdateCapabilities
}
type AgentUpdates struct {
	mu            sync.Mutex
	observationMu sync.Mutex
	store         *store.Store
	connections   *connmgr.ConnManager
	terminals     *TerminalSessions
	capabilities  map[string]updateCapability
	origins       map[string]*connmgr.AgentConn
	resolve       func(string, string) (model.AgentArtifact, error)
	now           func() time.Time
	transfers     chan struct{}
}
type AgentUpdateCheck struct {
	Supported                         bool                   `json:"supported"`
	Reason                            string                 `json:"reason,omitempty"`
	Current                           *pb.UpdateCapabilities `json:"current,omitempty"`
	Target                            model.AgentArtifact    `json:"target"`
	UpdateAvailable                   bool                   `json:"update_available"`
	BootstrapRequired                 bool                   `json:"bootstrap_required"`
	ConnectionID                      string                 `json:"connection_id"`
	BootstrapIdleConfirmationRequired bool                   `json:"bootstrap_idle_confirmation_required"`
	Operation                         *model.AgentUpdate     `json:"operation,omitempty"`
}

// One transfer/helper per node and at most32 active operations. No background
// polling is added: status and authenticated reconnects reconcile durable rows.
func NewAgentUpdates(st *store.Store, cm *connmgr.ConnManager, ts *TerminalSessions) (*AgentUpdates, error) {
	u := &AgentUpdates{store: st, connections: cm, terminals: ts, capabilities: make(map[string]updateCapability), origins: make(map[string]*connmgr.AgentConn), now: time.Now, transfers: make(chan struct{}, 16)}
	active, err := st.ActiveAgentUpdates()
	if err != nil {
		return nil, err
	}
	if len(active) > 32 {
		return nil, errors.New("too many unreconciled agent updates")
	}
	for _, op := range active {
		previous := op.State
		if updateInstallationIssued(op.State) {
			op.State = "unknown"
			op.Reason = "Hub restarted; awaiting exact enrolled-agent reconciliation"
		} else {
			op.State = "failed"
			op.Reason = "Hub restarted before installation authorization; create a new update"
		}
		op.UpdatedAt = u.now().UnixMilli()
		if err = st.UpdateAgentUpdate(op, previous); err != nil {
			return nil, err
		}
		if !op.Terminal() {
			u.connections.SetMaintenance(op.NodeID, op.ID)
			u.terminals.SetMaintenance(op.NodeID, op.ID)
			u.origins[op.ID] = nil
		} else {
			u.connections.ReleaseMaintenance(op.NodeID, op.ID)
			u.terminals.ReleaseMaintenance(op.NodeID, op.ID)
		}
	}
	return u, nil
}

// SetArtifactResolver is startup wiring, before listeners start.
func (u *AgentUpdates) SetArtifactResolver(fn func(string, string) (model.AgentArtifact, error)) {
	u.resolve = fn
}
func (u *AgentUpdates) authorizeAdmin(actor, sid string) error {
	if actor == "" || sid == "" {
		return ErrAgentUpdateDenied
	}
	user, err := u.store.GetUserByID(actor)
	if err != nil || user.MustChangePassword {
		return ErrAgentUpdateDenied
	}
	effective, err := authorization.New(u.store).Effective(actor)
	if err != nil || !effective.HasRole(model.RoleAdmin) {
		return ErrAgentUpdateDenied
	}
	sess, err := u.store.GetSession(sid)
	if err != nil || sess.UserID != actor || session.Evaluate(session.StateFromModel(sess), u.now(), lockout.Load(u.store.GetConfig)) != session.VerdictOK {
		return ErrAgentUpdateDenied
	}
	return nil
}
func (u *AgentUpdates) authorize(actor, sid, node string) error {
	if err := u.authorizeAdmin(actor, sid); err != nil {
		return err
	}
	enrolled, err := u.store.GovernanceEnrolled()
	if err != nil || enrolled {
		return ErrAgentUpdateDenied
	}
	if err = authorization.New(u.store).GuardInteractive(actor, node); err != nil {
		return ErrAgentUpdateDenied
	}
	srv, err := u.store.GetServerByID(node)
	if err != nil || srv.RegistrationToken != nil || srv.Status != "online" {
		return errors.New("agent is not enrolled and online")
	}
	return nil
}
func validUpdateCapabilities(c *pb.UpdateCapabilities) bool {
	if c == nil || c.ProtocolVersion != 1 || c.Os != "linux" || (c.Arch != "amd64" && c.Arch != "arm64") || len(c.BootId) < 16 || len(c.BootId) > 128 || len(c.Revision) > 128 || len(c.Reason) > 256 || strings.ContainsAny(c.BootId+c.Revision, "\x00\r\n") || updateutil.ValidateVersion(c.Version) != nil {
		return false
	}
	b, err := hex.DecodeString(c.Sha256)
	return err == nil && len(b) == 32 && strings.ToLower(c.Sha256) == c.Sha256
}
func (u *AgentUpdates) Capabilities(node string) *pb.UpdateCapabilities {
	u.mu.Lock()
	defer u.mu.Unlock()
	c := u.capabilities[node]
	if c.connection != u.connections.GetConn(node) || c.value == nil {
		return nil
	}
	return proto.Clone(c.value).(*pb.UpdateCapabilities)
}
func (u *AgentUpdates) ObserveCapabilities(node string, stream pb.AgentService_ConnectServer, c *pb.UpdateCapabilities) error {
	// Serialize identity persistence and cache publication across generations.
	// A new observation cannot commit before an older blocked version write,
	// and a stale observer is refused before touching SQL.
	u.observationMu.Lock()
	defer u.observationMu.Unlock()
	conn := u.connections.GetConn(node)
	if conn == nil || conn.Stream != stream || !validUpdateCapabilities(c) {
		return errors.New("invalid update capability or stale agent connection")
	}
	if c.ActivityQuiescenceVersion != 0 {
		if err := u.connections.ObserveActivityCapabilities(node, stream, c.ActivityQuiescenceVersion, c.ActiveActivities); err != nil {
			return err
		}
	}
	u.mu.Lock()
	previous := u.capabilities[node]
	unchangedVersion := previous.connection == conn && previous.value != nil && previous.value.Version == c.Version
	u.mu.Unlock()
	if !unchangedVersion {
		if err := u.store.UpdateObservedAgentVersion(node, c.Version); err != nil {
			return err
		}
	}
	u.mu.Lock()
	if u.connections.GetConn(node) != conn {
		u.mu.Unlock()
		return errors.New("agent connection changed during capability observation")
	}
	select {
	case <-conn.Done():
		u.mu.Unlock()
		return errors.New("agent connection closed during capability observation")
	default:
	}
	u.capabilities[node] = updateCapability{conn, proto.Clone(c).(*pb.UpdateCapabilities)}
	u.mu.Unlock()
	return nil
}
func (u *AgentUpdates) EndConnection(node string, stream pb.AgentService_ConnectServer) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if c := u.capabilities[node]; c.connection != nil && c.connection.Stream == stream {
		delete(u.capabilities, node)
	}
}
func (u *AgentUpdates) artifact(osName, arch string) (model.AgentArtifact, error) {
	if u.resolve == nil {
		return model.AgentArtifact{}, errors.New("Hub update distribution is unavailable")
	}
	a, err := u.resolve(osName, arch)
	if err != nil {
		return a, err
	}
	if a.Bytes <= 0 || a.Bytes > MaxAgentArtifactBytes {
		return a, errors.New("agent artifact exceeds update size bound")
	}
	return a, nil
}
func (u *AgentUpdates) Check(actor, sid, node string) (AgentUpdateCheck, error) {
	var result AgentUpdateCheck
	err := u.store.WithInteractivePolicy(func() error { return u.authorize(actor, sid, node) })
	if err != nil {
		return result, err
	}
	conn := u.connections.GetConn(node)
	if conn == nil {
		return result, errors.New("agent is not connected")
	}
	result.ConnectionID = conn.GenerationID
	c := u.Capabilities(node)
	arch := "amd64"
	if c != nil {
		arch = c.Arch
	}
	a, err := u.artifact("linux", arch)
	if err != nil {
		return result, err
	}
	result.Target = a
	result.Current = c
	if c == nil {
		// Release identity is common to the distribution. The old agent's
		// architecture is learned only by authenticated preserving bootstrap.
		result.Target.Arch = ""
		result.Target.SHA256 = ""
		result.Target.Bytes = 0
		result.Target.BinaryPath = ""
		result.BootstrapRequired = true
		result.BootstrapIdleConfirmationRequired = true
		result.Reason = "agent requires a preserving one-time bootstrap"
	} else if !c.Supported {
		result.Reason = c.Reason
	} else {
		cmp, e := updateutil.CompareVersions(a.Version, c.Version)
		if e != nil {
			return result, e
		}
		if cmp < 0 {
			return result, errors.New("Hub agent artifact would downgrade this node")
		}
		if cmp == 0 && a.SHA256 != c.Sha256 {
			return result, errors.New("same-version agent artifact differs; automatic replacement refused")
		}
		if c.ActivityQuiescenceVersion != 1 {
			result.BootstrapRequired = true
			result.BootstrapIdleConfirmationRequired = true
			result.Reason = "agent cannot prove complete file/upload/log quiescence; preserving manual bootstrap requires direct SSH idle confirmation"
		} else {
			result.Supported = true
			result.UpdateAvailable = cmp > 0
		}
	}
	if op, e := u.store.LatestAgentUpdate(node); e == nil {
		result.Operation = &op
	} else if !errors.Is(e, sql.ErrNoRows) {
		return result, e
	}
	return result, nil
}

type BootstrapIdleAssertion struct {
	Confirmed    bool
	ConnectionID string
	Original     updateutil.BootstrapOriginal
}

func (u *AgentUpdates) validateOriginalAssertion(node string, original updateutil.BootstrapOriginal) error {
	if u.Capabilities(node) != nil {
		return errors.New("original binary assertion is only valid for a legacy agent without update capabilities")
	}
	srv, err := u.store.GetServerByID(node)
	if err != nil {
		return err
	}
	if srv.AgentVersion != nil && updateutil.ValidateVersion(*srv.AgentVersion) == nil && *srv.AgentVersion != original.Version {
		return errors.New("original version assertion contradicts the enrolled agent's observed version")
	}
	return nil
}

func (u *AgentUpdates) Start(ctx context.Context, actor, sid, node, expectedVersion, expectedRevision string, assertions ...BootstrapIdleAssertion) (model.AgentUpdate, string, error) {
	check, err := u.Check(actor, sid, node)
	if err != nil {
		return model.AgentUpdate{}, "", err
	}
	if check.Target.Version != expectedVersion || check.Target.Revision != expectedRevision {
		return model.AgentUpdate{}, "", errors.New("Hub artifact changed; check again")
	}
	var idle BootstrapIdleAssertion
	if len(assertions) > 1 {
		return model.AgentUpdate{}, "", errors.New("invalid bootstrap idle assertion")
	}
	if len(assertions) == 1 {
		idle = assertions[0]
	}
	if err := idle.Original.Validate(); err != nil {
		return model.AgentUpdate{}, "", err
	}
	if idle.Original.Present() {
		if !check.BootstrapRequired || check.Current != nil {
			return model.AgentUpdate{}, "", errors.New("original binary assertion is only valid for a legacy agent without update capabilities")
		}
		cmp, err := updateutil.CompareVersions(check.Target.Version, idle.Original.Version)
		if err != nil || cmp <= 0 {
			return model.AgentUpdate{}, "", errors.New("bootstrap target must advance the operator-asserted original version")
		}
		if err := u.validateOriginalAssertion(node, idle.Original); err != nil {
			return model.AgentUpdate{}, "", err
		}
	}
	if check.BootstrapRequired {
		if !idle.Confirmed || idle.ConnectionID == "" || idle.ConnectionID != check.ConnectionID {
			return model.AgentUpdate{}, "", errors.New("preserving bootstrap requires explicit bootstrap_idle_confirmed and the freshly checked connection_id after direct SSH verification of idle agent work")
		}
	} else if idle.Confirmed || idle.ConnectionID != "" {
		return model.AgentUpdate{}, "", errors.New("bootstrap idle assertion is only valid for the preserving manual path")
	}
	if check.Operation != nil && !check.Operation.Terminal() && u.now().UnixMilli() >= check.Operation.ExpiresAt {
		if _, err = u.Status(node, check.Operation.ID); err != nil {
			return model.AgentUpdate{}, "", err
		}
	}
	if !check.BootstrapRequired && (!check.Supported || !check.UpdateAvailable) {
		return model.AgentUpdate{}, "", errors.New("agent update unavailable: " + check.Reason)
	}
	conn := u.connections.GetConn(node)
	if check.BootstrapRequired && (conn == nil || conn.GenerationID != idle.ConnectionID) {
		return model.AgentUpdate{}, "", errors.New("bootstrap checked connection changed")
	}
	now := u.now().UnixMilli()
	op := model.AgentUpdate{ID: uuid.NewString(), NodeID: node, ActorID: actor, SessionID: sid, State: "requested", Target: check.Target, ExpiresAt: now + 120000, CreatedAt: now, UpdatedAt: now}
	op.BootstrapIdleConfirmed = idle.Confirmed
	op.BootstrapConnectionID = idle.ConnectionID
	op.BootstrapOriginal = idle.Original
	ticket := ""
	if check.Current != nil {
		op.PreviousVersion = check.Current.Version
		op.PreviousRevision = check.Current.Revision
		op.PreviousSHA256 = check.Current.Sha256
		op.PreviousBootID = check.Current.BootId
	}
	if check.BootstrapRequired {
		for _, arch := range []string{"amd64", "arm64"} {
			a, e := u.artifact("linux", arch)
			if e != nil || a.Version != op.Target.Version || a.Revision != op.Target.Revision {
				return op, "", errors.New("bootstrap requires a complete matching Linux distribution")
			}
			op.BootstrapArtifacts = append(op.BootstrapArtifacts, a)
		}
		var raw [32]byte
		if _, err = rand.Read(raw[:]); err != nil {
			return op, "", err
		}
		ticket = hex.EncodeToString(raw[:])
		op.TicketHash = store.SecurityDigest([]byte(ticket))
		op.State = "bootstrap_required"
	}
	if idle.Original.Present() {
		// Serialize final admission with authenticated capability observations.
		// Artifact resolution above stays outside the observation lock.
		u.observationMu.Lock()
		defer u.observationMu.Unlock()
	}
	err = u.connections.ReserveMaintenanceWithIdleAssertion(conn, op.ID, idle.Confirmed, func() error {
		return u.store.WithInteractivePolicy(func() error {
			if err := u.authorize(actor, sid, node); err != nil {
				return err
			}
			if idle.Original.Present() {
				if err := u.validateOriginalAssertion(node, idle.Original); err != nil {
					return err
				}
			}
			if idle.Confirmed {
				if err := u.audit(op, "manual_bootstrap_idle_confirmed"); err != nil {
					return err
				}
			}
			u.mu.Lock()
			if len(u.origins) >= 32 {
				u.mu.Unlock()
				return errors.New("agent update capacity reached")
			}
			u.origins[op.ID] = conn
			u.mu.Unlock()
			if err := u.terminals.ReserveMaintenance(node, op.ID); err != nil {
				u.mu.Lock()
				delete(u.origins, op.ID)
				u.mu.Unlock()
				return err
			}
			if err := u.store.CreateAgentUpdate(op); err != nil {
				u.terminals.ReleaseMaintenance(node, op.ID)
				u.mu.Lock()
				delete(u.origins, op.ID)
				u.mu.Unlock()
				return err
			}
			return nil
		})
	})
	if err != nil {
		// A reconnect can invalidate the exact generation after the callback
		// persisted this preinstall operation. Retire only its own authority.
		u.finishBeforeInstall(op, "maintenance reservation refused before installation: "+err.Error())
		return op, "", err
	}
	if err = u.audit(op, "requested"); err != nil {
		u.finishBeforeInstall(op, "audit persistence failed")
		return op, "", err
	}
	if ticket != "" {
		return op, ticket, nil
	}
	err = u.connections.SendToConnectionChecked(ctx, conn, &pb.HubMessage{Payload: &pb.HubMessage_AgentUpdateRequest{AgentUpdateRequest: updateRequest(op)}}, func() error { return u.validateOperation(op) })
	if err != nil {
		u.finishBeforeInstall(op, "update dispatch failed before installation authorization")
		return op, "", err
	}
	return op, "", nil
}
func updateRequest(op model.AgentUpdate) *pb.AgentUpdateRequest {
	return &pb.AgentUpdateRequest{OperationId: op.ID, Version: op.Target.Version, Revision: op.Target.Revision, Sha256: op.Target.SHA256, Bytes: op.Target.Bytes, ExpiresUnixMilli: op.ExpiresAt}
}
func (u *AgentUpdates) validateOperation(op model.AgentUpdate) error {
	if err := u.validateOrigin(op); err != nil {
		return err
	}
	return u.store.WithInteractivePolicy(func() error { return u.authorize(op.ActorID, op.SessionID, op.NodeID) })
}
func (u *AgentUpdates) validateOrigin(op model.AgentUpdate) error {
	u.mu.Lock()
	conn, exists := u.origins[op.ID]
	u.mu.Unlock()
	if !exists || conn == nil || u.connections.GetConn(op.NodeID) != conn {
		return errors.New("update's original enrolled connection changed")
	}
	if !u.now().Before(time.UnixMilli(op.ExpiresAt)) {
		return errors.New("agent update authorization expired")
	}
	return nil
}
func (u *AgentUpdates) release(op model.AgentUpdate) {
	u.connections.ReleaseMaintenance(op.NodeID, op.ID)
	u.terminals.ReleaseMaintenance(op.NodeID, op.ID)
	u.mu.Lock()
	delete(u.origins, op.ID)
	u.mu.Unlock()
}
func (u *AgentUpdates) audit(op model.AgentUpdate, state string) error {
	detail := fmt.Sprintf("operation=%s requester=%s state=%s version=%s revision=%s sha256=%s", op.ID, op.ActorID, state, op.Target.Version, op.Target.Revision, op.Target.SHA256)
	if op.BootstrapIdleConfirmed {
		detail += " bootstrap_idle_confirmed=true connection=" + op.BootstrapConnectionID
	}
	if op.BootstrapOriginal.Present() {
		detail += " original_identity_source=operator_assertion original_version=" + op.BootstrapOriginal.Version + " original_sha256=" + op.BootstrapOriginal.SHA256
	}
	actorType := "agent"
	var userID *string
	if state == "requested" || state == "installation_authorized" || state == "recovery_acknowledged" || state == "manual_bootstrap_idle_confirmed" {
		actorType = "user"
		userID = &op.ActorID
	}
	return u.store.LogAudit(model.AuditEntry{UserID: userID, Action: "server.agent_update." + state, Target: &op.NodeID, Detail: &detail, Outcome: state, ActorType: actorType, CorrelationID: &op.ID})
}
func updateInstallationIssued(state string) bool {
	switch state {
	case "installing", "unknown", "confirmation_pending", "rollback_confirmation_pending":
		return true
	}
	return false
}
func (u *AgentUpdates) finishBeforeInstall(op model.AgentUpdate, reason string) {
	latest, err := u.store.GetAgentUpdate(op.ID)
	if err != nil || latest.Terminal() || updateInstallationIssued(latest.State) {
		return
	}
	previous := latest.State
	latest.State = "failed"
	latest.Reason = reason
	latest.UpdatedAt = u.now().UnixMilli()
	if u.store.UpdateAgentUpdate(latest, previous) == nil {
		u.release(latest)
	}
}
func (u *AgentUpdates) Status(node, id string) (model.AgentUpdate, error) {
	var op model.AgentUpdate
	var err error
	if id == "" {
		op, err = u.store.LatestAgentUpdate(node)
	} else {
		op, err = u.store.GetAgentUpdate(id)
	}
	if err != nil {
		return op, err
	}
	if op.NodeID != node {
		return model.AgentUpdate{}, sql.ErrNoRows
	}
	if !op.Terminal() && u.now().UnixMilli() >= op.ExpiresAt {
		previous := op.State
		if updateInstallationIssued(op.State) {
			op.State = "unknown"
			op.Reason = "installation outcome unconfirmed; awaiting enrolled-agent reconciliation"
		} else {
			op.State = "expired"
			op.Reason = "update authorization expired before installation"
		}
		op.UpdatedAt = u.now().UnixMilli()
		if err = u.store.UpdateAgentUpdate(op, previous); err != nil {
			return op, err
		}
		if op.Terminal() {
			u.release(op)
		}
	}
	return op, nil
}
func (h *Handler) updateService(ctx context.Context) (string, *AgentUpdates, error) {
	node, err := h.executionNode(ctx)
	if err != nil {
		return "", nil, err
	}
	if h.updates == nil {
		return "", nil, status.Error(codes.Unavailable, "agent update service unavailable")
	}
	return node, h.updates, nil
}
func (h *Handler) DownloadUpdate(req *pb.UpdateArtifactRequest, stream pb.AgentService_DownloadUpdateServer) error {
	node, u, err := h.updateService(stream.Context())
	if err != nil {
		return err
	}
	op, err := u.store.GetAgentUpdate(req.GetOperationId())
	if err != nil || op.NodeID != node || (op.State != "requested" && op.State != "downloading") {
		return status.Error(codes.PermissionDenied, "update operation is unavailable")
	}
	if err = u.validateOperation(op); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	select {
	case u.transfers <- struct{}{}:
		defer func() { <-u.transfers }()
	default:
		return status.Error(codes.ResourceExhausted, "agent update transfer capacity reached")
	}
	a, err := u.artifact(op.Target.OS, op.Target.Arch)
	if err != nil || a.SHA256 != op.Target.SHA256 || a.Version != op.Target.Version || a.Revision != op.Target.Revision {
		return status.Error(codes.FailedPrecondition, "Hub update artifact changed")
	}
	f, err := os.Open(a.BinaryPath)
	if err != nil {
		return err
	}
	defer f.Close()
	var offset int64
	buf := make([]byte, 32<<10)
	ctx, cancel := context.WithDeadline(stream.Context(), time.UnixMilli(op.ExpiresAt))
	defer cancel()
	for offset < a.Bytes {
		if err = u.validateOperation(op); err != nil {
			return status.Error(codes.PermissionDenied, err.Error())
		}
		n, e := f.Read(buf)
		if n > 0 {
			if offset+int64(n) > a.Bytes {
				return status.Error(codes.DataLoss, "artifact length changed")
			}
			sent := make(chan error, 1)
			go func() { sent <- stream.Send(&pb.UpdateArtifactChunk{Offset: offset, Data: buf[:n]}) }()
			select {
			case err = <-sent:
				if err != nil {
					return err
				}
			case <-ctx.Done():
				return ctx.Err()
			}
			offset += int64(n)
		}
		if e != nil {
			if e == io.EOF && offset == a.Bytes {
				break
			}
			return status.Error(codes.DataLoss, "artifact truncated")
		}
	}
	var extra [1]byte
	if n, _ := f.Read(extra[:]); n != 0 {
		return status.Error(codes.DataLoss, "artifact grew during download")
	}
	return nil
}
func (h *Handler) AuthorizeUpdate(ctx context.Context, req *pb.UpdateArtifactRequest) (*pb.UpdateAuthorization, error) {
	node, u, err := h.updateService(ctx)
	if err != nil {
		return nil, err
	}
	op, err := u.store.GetAgentUpdate(req.GetOperationId())
	if err != nil || op.NodeID != node || (op.State != "requested" && op.State != "downloading" && op.State != "installing") {
		return nil, status.Error(codes.PermissionDenied, "update operation unavailable")
	}
	if err = u.validateOperation(op); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	a, err := u.artifact(op.Target.OS, op.Target.Arch)
	if err != nil || a.SHA256 != op.Target.SHA256 || a.Version != op.Target.Version || a.Revision != op.Target.Revision {
		return nil, status.Error(codes.FailedPrecondition, "Hub artifact changed")
	}
	err = u.store.WithInteractivePolicy(func() error {
		if err := u.validateOrigin(op); err != nil {
			return err
		}
		if err := u.authorize(op.ActorID, op.SessionID, op.NodeID); err != nil {
			return err
		}
		if op.State != "installing" {
			previous := op.State
			op.State = "installing"
			op.UpdatedAt = u.now().UnixMilli()
			if err := u.audit(op, "installation_authorized"); err != nil {
				return err
			}
			return u.store.UpdateAgentUpdate(op, previous)
		}
		return nil
	})
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	return &pb.UpdateAuthorization{OperationId: op.ID, ExpiresUnixMilli: op.ExpiresAt}, nil
}

func (u *AgentUpdates) AcknowledgeRecovery(actor, sid, node, id, verifiedHash string) (model.AgentUpdate, error) {
	var result model.AgentUpdate
	err := u.store.WithInteractivePolicy(func() error {
		if err := u.authorize(actor, sid, node); err != nil {
			return err
		}
		op, err := u.store.GetAgentUpdate(id)
		if err != nil {
			return err
		}
		if op.NodeID != node || op.State != "unknown" || op.PreviousSHA256 == "" || verifiedHash != op.PreviousSHA256 || u.now().UnixMilli() < op.ExpiresAt+190000 {
			return errors.New("recovery requires the exact previous hash, an unknown operation and expiry plus190 seconds")
		}
		if !u.terminals.MaintenanceIdle(node, op.ID) {
			return errors.New("node is not idle in the same maintenance operation")
		}
		op.State = "recovery_acknowledged"
		op.Reason = "administrator attested direct SSH verification of the original binary; no remote artifact confirmation"
		op.UpdatedAt = u.now().UnixMilli()
		// The acknowledging administrator, rather than the initial requester, is
		// the audit actor. The original operation owner remains durable.
		attestation := op
		attestation.ActorID = actor
		if err = u.audit(attestation, op.State); err != nil {
			return err
		}
		if err = u.store.UpdateAgentUpdate(op, "unknown"); err != nil {
			return err
		}
		result = op
		u.release(op)
		return nil
	})
	return result, err
}
func (h *Handler) BootstrapUpdate(ctx context.Context, req *pb.UpdateBootstrapRequest) (*pb.AgentUpdateRequest, error) {
	node, u, err := h.updateService(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.GetTicket()) != 64 || !validUpdateCapabilities(req.GetCapabilities()) {
		return nil, status.Error(codes.InvalidArgument, "invalid bootstrap request")
	}
	hash := sha256.Sum256([]byte(req.Ticket))
	op, err := u.store.AgentUpdateByTicketHash(hex.EncodeToString(hash[:]))
	if err != nil || op.NodeID != node || !op.BootstrapIdleConfirmed {
		return nil, status.Error(codes.PermissionDenied, "bootstrap ticket unavailable")
	}
	if err = u.validateOperation(op); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if conn := u.connections.GetConn(node); conn == nil || conn.GenerationID != op.BootstrapConnectionID {
		return nil, status.Error(codes.PermissionDenied, "bootstrap checked connection changed")
	}
	c := req.Capabilities
	if op.BootstrapOriginal.Validate() != nil || req.OriginalIdentityAsserted != op.BootstrapOriginal.Present() || (op.BootstrapOriginal.Present() && (c.Version != op.BootstrapOriginal.Version || c.Sha256 != op.BootstrapOriginal.SHA256 || c.Revision != "unknown")) {
		return nil, status.Error(codes.FailedPrecondition, "bootstrap original identity does not match the operator assertion bound to this ticket")
	}
	a, err := u.artifact(c.Os, c.Arch)
	var bound model.AgentArtifact
	for _, allowed := range op.BootstrapArtifacts {
		if allowed.OS == c.Os && allowed.Arch == c.Arch {
			bound = allowed
		}
	}
	if err != nil || a.Version != op.Target.Version || a.Revision != op.Target.Revision || a.SHA256 != bound.SHA256 || a.Bytes != bound.Bytes {
		return nil, status.Error(codes.FailedPrecondition, "bootstrap Hub artifact changed")
	}
	if op.BootstrapOriginal.Present() {
		u.observationMu.Lock()
		defer u.observationMu.Unlock()
		if err := u.validateOriginalAssertion(node, op.BootstrapOriginal); err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		if err := u.validateOperation(op); err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
	}
	cmp, err := updateutil.CompareVersions(a.Version, c.Version)
	if err != nil || cmp < 0 || (cmp == 0 && a.SHA256 != c.Sha256) {
		return nil, status.Error(codes.FailedPrecondition, "bootstrap replacement would downgrade or change same-version artifact")
	}
	previous := op.State
	op.Target = a
	op.PreviousVersion = c.Version
	op.PreviousRevision = c.Revision
	op.PreviousSHA256 = c.Sha256
	op.PreviousBootID = c.BootId
	op.TicketHash = ""
	op.State = "requested"
	op.UpdatedAt = u.now().UnixMilli()
	if err = u.store.UpdateAgentUpdate(op, previous); err != nil {
		return nil, status.Error(codes.PermissionDenied, "bootstrap ticket already consumed")
	}
	return updateRequest(op), nil
}

func (u *AgentUpdates) ObserveStatus(node string, stream pb.AgentService_ConnectServer, value *pb.AgentUpdateStatus) error {
	if value == nil || len(value.OperationId) > 128 {
		return errors.New("invalid update status")
	}
	op, err := u.store.GetAgentUpdate(value.OperationId)
	if err != nil || op.NodeID != node {
		return errors.New("unknown node update operation")
	}
	conn := u.connections.GetConn(node)
	if conn == nil || conn.Stream != stream {
		return errors.New("stale update status connection")
	}
	c := u.Capabilities(node)
	if c == nil || value.Version != c.Version || value.Revision != c.Revision || value.Sha256 != c.Sha256 || value.BootId != c.BootId {
		return errors.New("update status does not match the running agent capability")
	}
	previous := op.State
	target := c.BootId != op.PreviousBootID && c.Version == op.Target.Version && c.Revision == op.Target.Revision && c.Sha256 == op.Target.SHA256
	original := c.BootId != op.PreviousBootID && c.Version == op.PreviousVersion && c.Revision == op.PreviousRevision && c.Sha256 == op.PreviousSHA256
	terminal := ""
	if value.State == "confirmed" && target && (op.State == "confirmation_pending" || op.State == "unknown" || op.State == "succeeded") && op.ObservedSHA256 == op.Target.SHA256 {
		terminal = "succeeded"
	}
	if value.State == "rollback_confirmed" && original && (op.State == "rollback_confirmation_pending" || op.State == "unknown" || op.State == "rolled_back") && op.ObservedSHA256 == op.PreviousSHA256 {
		terminal = "rolled_back"
	}
	if terminal != "" {
		if op.State != terminal {
			op.State = terminal
			op.Reason = "exact enrolled agent durably acknowledged the verified reconnect; supervised outcome confirmed"
			op.ObservedBootID = c.BootId
			op.UpdatedAt = u.now().UnixMilli()
			if err = u.audit(op, terminal); err != nil {
				return err
			}
			if err = u.store.UpdateAgentUpdate(op, previous); err != nil {
				return err
			}
		}
		u.release(op)
		return nil
	}
	confirmation, pending := "", ""
	if value.State == "reconnecting" && target && (updateInstallationIssued(op.State) || op.State == "succeeded") {
		confirmation, pending = "succeeded", "confirmation_pending"
	}
	if value.State == "rolled_back" && original && (updateInstallationIssued(op.State) || op.State == "succeeded" || op.State == "rolled_back") {
		confirmation, pending = "rolled_back", "rollback_confirmation_pending"
	}
	if confirmation != "" {
		alreadyFinal := op.State == confirmation
		if !alreadyFinal && (op.State != pending || op.ObservedBootID != c.BootId) {
			op.State = pending
			op.Reason = "exact enrolled identity reconnected; awaiting durable agent acknowledgement of Hub confirmation"
			op.ObservedVersion = c.Version
			op.ObservedRevision = c.Revision
			op.ObservedSHA256 = c.Sha256
			op.ObservedBootID = c.BootId
			op.UpdatedAt = u.now().UnixMilli()
			if err = u.audit(op, pending); err != nil {
				return err
			}
			if err = u.store.UpdateAgentUpdate(op, previous); err != nil {
				return err
			}
		}
		if alreadyFinal {
			u.release(op)
		}
		ctx, cancel := context.WithTimeout(stream.Context(), 5*time.Second)
		defer cancel()
		return u.connections.SendToConnectionChecked(ctx, conn, &pb.HubMessage{Payload: &pb.HubMessage_UpdateConfirmation{UpdateConfirmation: &pb.UpdateConfirmation{OperationId: op.ID, State: confirmation}}}, nil)
	}
	if op.Terminal() {
		return nil
	}
	if value.State == "installing" && op.State == "installing" {
		return nil
	}
	if value.State == "failed" && c.Version == op.PreviousVersion && c.Revision == op.PreviousRevision && c.Sha256 == op.PreviousSHA256 && c.BootId == op.PreviousBootID {
		if updateInstallationIssued(op.State) {
			op.State = "unknown"
			op.Reason = "agent reported failure after installation was authorized; replacement or rollback is unconfirmed"
		} else {
			op.State = "failed"
			op.Reason = "agent refused or failed before replacement"
		}
	} else if value.State == "downloading" && op.State == "requested" {
		op.State = "downloading"
	} else {
		return errors.New("invalid update status transition")
	}
	op.UpdatedAt = u.now().UnixMilli()
	if err = u.audit(op, op.State); err != nil {
		return err
	}
	if err = u.store.UpdateAgentUpdate(op, previous); err != nil {
		return err
	}
	if op.Terminal() {
		u.release(op)
	}
	return nil
}
