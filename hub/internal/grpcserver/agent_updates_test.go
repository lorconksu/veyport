package grpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type updateFixture struct {
	h      *Handler
	u      *AgentUpdates
	st     *store.Store
	stream *mockStream
	target model.AgentArtifact
	old    *pb.UpdateCapabilities
	body   []byte
}

func newUpdateFixture(t *testing.T) *updateFixture {
	t.Helper()
	h, st := testHandler(t)
	if err := st.CreateUser(&model.User{ID: "admin", Username: "admin", Email: "admin@example.com", Role: model.RoleAdmin, AuthProvider: model.AuthProviderLocal, TOTPEnabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.CreateSession(&model.Session{ID: "session", UserID: "admin", Kind: model.SessionKindCLI, CreatedAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	stream := &mockStream{}
	h.connMgr.Register("node", stream)
	ts := NewTerminalSessions()
	u, err := NewAgentUpdates(st, h.connMgr, ts)
	if err != nil {
		t.Fatal(err)
	}
	h.updates = u
	body := []byte("verified enrolled agent distribution fixture")
	sum := sha256.Sum256(body)
	path := filepath.Join(t.TempDir(), "agent")
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	a := model.AgentArtifact{OS: "linux", Arch: "amd64", Version: "2.0.1-prototype.4", Revision: strings.Repeat("f", 40), SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body)), BinaryPath: path}
	u.SetArtifactResolver(func(osName, arch string) (model.AgentArtifact, error) {
		result := a
		result.OS = osName
		result.Arch = arch
		return result, nil
	})
	c := &pb.UpdateCapabilities{ProtocolVersion: 1, Os: "linux", Arch: "amd64", Version: "0.1.0", Revision: "unknown", Sha256: strings.Repeat("a", 64), BootId: "original-boot-nonce", Supported: true, ActivityQuiescenceVersion: 1}
	if err = u.ObserveCapabilities("node", stream, c); err != nil {
		t.Fatal(err)
	}
	return &updateFixture{h, u, st, stream, a, c, body}
}

func TestAgentUpdateAuthorityUsesStoredCLISessionIdle(t *testing.T) {
	for _, tc := range []struct {
		name, kind              string
		gap                     time.Duration
		ended, absolute, wantOK bool
	}{
		{"cli20m", model.SessionKindCLI, 20 * time.Minute, false, false, true},
		{"cli45m", model.SessionKindCLI, 45 * time.Minute, false, false, true},
		{"cli46m", model.SessionKindCLI, 46 * time.Minute, false, false, false},
		{"web20m", model.SessionKindWeb, 20 * time.Minute, false, false, false},
		{"cliended", model.SessionKindCLI, 20 * time.Minute, true, false, false},
		{"cliabsolute", model.SessionKindCLI, 20 * time.Minute, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newUpdateFixture(t)
			now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
			f.u.now = func() time.Time { return now }
			if _, err := f.st.DB().Exec("UPDATE sessions SET kind=?,user_agent='vey/spoof',last_seen_at=? WHERE id='session'", tc.kind, now.Add(-tc.gap).Format("2006-01-02 15:04:05")); err != nil {
				t.Fatal(err)
			}
			if tc.ended {
				if _, err := f.st.EndSession("session", model.SessionEndRevokedAdmin, nil, now); err != nil {
					t.Fatal(err)
				}
			}
			if tc.absolute {
				if _, err := f.st.DB().Exec("UPDATE sessions SET expires_at=? WHERE id='session'", now.Format("2006-01-02 15:04:05")); err != nil {
					t.Fatal(err)
				}
			}
			err := f.u.authorizeAdmin("admin", "session")
			if tc.wantOK && err != nil || !tc.wantOK && !errors.Is(err, ErrAgentUpdateDenied) {
				t.Fatalf("agent update authority=%v, wantOK=%v", err, tc.wantOK)
			}
		})
	}
}
func (f *updateFixture) start(t *testing.T) model.AgentUpdate {
	t.Helper()
	op, _, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, f.idleAssertion())
	if err != nil {
		t.Fatal(err)
	}
	return op
}
func (f *updateFixture) idleAssertion() BootstrapIdleAssertion {
	c := f.u.Capabilities("node")
	if c == nil || c.Supported && c.ActivityQuiescenceVersion == 0 {
		return BootstrapIdleAssertion{Confirmed: true, ConnectionID: f.h.connMgr.GetConn("node").GenerationID}
	}
	return BootstrapIdleAssertion{}
}
func enrolledUpdateContext(node string) context.Context {
	now := time.Now()
	cert := &x509.Certificate{Raw: []byte(node), Subject: pkix.Name{CommonName: node}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}}})
}
func (f *updateFixture) authorize(t *testing.T, op model.AgentUpdate) {
	t.Helper()
	if _, err := f.h.AuthorizeUpdate(enrolledUpdateContext("node"), &pb.UpdateArtifactRequest{OperationId: op.ID}); err != nil {
		t.Fatal(err)
	}
}
func statusFor(op string, c *pb.UpdateCapabilities, state string) *pb.AgentUpdateStatus {
	return &pb.AgentUpdateStatus{OperationId: op, State: state, Version: c.Version, Revision: c.Revision, Sha256: c.Sha256, BootId: c.BootId}
}

func TestAgentUpdateCheckIsReadOnlyAndMaintenanceBlocksAdmissions(t *testing.T) {
	f := newUpdateFixture(t)
	check, err := f.u.Check("admin", "session", "node")
	if err != nil || !check.UpdateAvailable {
		t.Fatalf("check=%+v err=%v", check, err)
	}
	var rows int
	if err = f.st.DB().QueryRow("SELECT COUNT(*) FROM agent_updates").Scan(&rows); err != nil || rows != 0 {
		t.Fatal("check created durable operation")
	}
	if _, ok := f.u.terminals.Register("node", "active", "admin", ""); !ok {
		t.Fatal("check reserved maintenance")
	}
	if _, _, err = f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, f.idleAssertion()); err == nil {
		t.Fatal("updated busy node")
	}
	f.u.terminals.Remove("node", "active")
	op := f.start(t)
	if _, ok := f.u.terminals.Register("node", "after", "admin", ""); ok {
		t.Fatal("maintenance admitted terminal or prepared execution")
	}
	if err = f.h.connMgr.SendToAgent("node", &pb.HubMessage{Payload: &pb.HubMessage_TerminalOpenRequest{TerminalOpenRequest: &pb.TerminalOpenRequest{SessionId: "after"}}}); err == nil {
		t.Fatal("maintenance control send admitted terminal")
	}
	if _, _, err = f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, f.idleAssertion()); err == nil {
		t.Fatal("duplicate update admitted")
	}
	got, err := f.st.GetAgentUpdate(op.ID)
	if err != nil || got.ActorID != "admin" || got.SessionID != "session" || got.PreviousBootID != f.old.BootId {
		t.Fatalf("authority was not durably preserved: %+v %v", got, err)
	}
}
func TestAgentUpdateAuthorityVersionAndGovernanceDenials(t *testing.T) {
	for _, phase := range []string{"no-session", "viewer", "ended-session", "disabled", "password-reset", "historical-governance", "policy-integrity", "stale-artifact", "downgrade", "same-version-different-hash"} {
		t.Run(phase, func(t *testing.T) {
			f := newUpdateFixture(t)
			sid := "session"
			version := f.target.Version
			switch phase {
			case "no-session":
				sid = ""
			case "viewer":
				if err := f.st.UpdateUserRole("admin", model.RoleViewer); err != nil {
					t.Fatal(err)
				}
			case "ended-session":
				if _, err := f.st.EndSession("session", model.SessionEndRevokedSelf, nil, time.Now()); err != nil {
					t.Fatal(err)
				}
			case "disabled":
				if _, err := f.st.DB().Exec("UPDATE users SET disabled_at=datetime('now') WHERE id='admin'"); err != nil {
					t.Fatal(err)
				}
			case "password-reset":
				if _, err := f.st.DB().Exec("UPDATE users SET must_change_password=1 WHERE id='admin'"); err != nil {
					t.Fatal(err)
				}
			case "historical-governance":
				var raw string
				if err := f.st.DB().QueryRow("SELECT payload FROM audit_policy_versions WHERE version=1").Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if _, err := f.st.DB().Exec("INSERT INTO audit_policy_versions(version,payload,digest,request_id,created_at) VALUES(2,?,?,'approved',0)", raw, store.SecurityDigest([]byte(raw))); err != nil {
					t.Fatal(err)
				}
			case "policy-integrity":
				if _, err := f.st.DB().Exec("UPDATE audit_policy_versions SET digest=? WHERE version=1", strings.Repeat("0", 64)); err != nil {
					t.Fatal(err)
				}
			case "stale-artifact":
				version = "2.0.1-prototype.3"
			case "downgrade":
				f.old.Version = "9.0.0"
				if err := f.u.ObserveCapabilities("node", f.stream, f.old); err != nil {
					t.Fatal(err)
				}
			case "same-version-different-hash":
				f.old.Version = f.target.Version
				if err := f.u.ObserveCapabilities("node", f.stream, f.old); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := f.u.Start(context.Background(), "admin", sid, "node", version, f.target.Revision); err == nil {
				t.Fatal("unsafe update admitted")
			}
		})
	}
}

type updateDownloadStream struct {
	pb.AgentService_DownloadUpdateServer
	ctx     context.Context
	body    bytes.Buffer
	offset  int64
	sendErr error
	block   chan struct{}
}

func (s *updateDownloadStream) Context() context.Context { return s.ctx }
func (s *updateDownloadStream) Send(c *pb.UpdateArtifactChunk) error {
	if s.block != nil {
		<-s.block
	}
	if s.sendErr != nil {
		return s.sendErr
	}
	if c.Offset != s.offset || len(c.Data) > 32<<10 {
		return errors.New("invalid bounded artifact frame")
	}
	s.body.Write(c.Data)
	s.offset += int64(len(c.Data))
	return nil
}
func TestAgentUpdateRPCAuthenticatesIndependentlyAndBoundsTransfer(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	for _, ctx := range []context.Context{context.Background(), peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}}}), enrolledUpdateContext("other-node")} {
		if err := f.h.DownloadUpdate(&pb.UpdateArtifactRequest{OperationId: op.ID}, &updateDownloadStream{ctx: ctx}); err == nil {
			t.Fatal("download accepted enrollment or different identity")
		}
		if _, err := f.h.AuthorizeUpdate(ctx, &pb.UpdateArtifactRequest{OperationId: op.ID}); err == nil {
			t.Fatal("installation accepted enrollment or different identity")
		}
	}
	stream := &updateDownloadStream{ctx: enrolledUpdateContext("node")}
	if err := f.h.DownloadUpdate(&pb.UpdateArtifactRequest{OperationId: op.ID}, stream); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream.body.Bytes(), f.body) {
		t.Fatal("download changed bytes")
	}
	if _, err := f.st.EndSession("session", model.SessionEndRevokedAdmin, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.AuthorizeUpdate(enrolledUpdateContext("node"), &pb.UpdateArtifactRequest{OperationId: op.ID}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("revoked session retained install authority", err)
	}
}
func TestAgentUpdateBlockedDownloadExpiresAndReleasesGlobalSlot(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	previous := op.State
	op.ExpiresAt = time.Now().Add(50 * time.Millisecond).UnixMilli()
	if err := f.st.UpdateAgentUpdate(op, previous); err != nil {
		t.Fatal(err)
	}
	stream := &updateDownloadStream{ctx: enrolledUpdateContext("node"), block: make(chan struct{})}
	defer close(stream.block)
	start := time.Now()
	err := f.h.DownloadUpdate(&pb.UpdateArtifactRequest{OperationId: op.ID}, stream)
	if err == nil || time.Since(start) > time.Second || len(f.u.transfers) != 0 {
		t.Fatal("blocked update exceeded deadline or leaked transfer slot", err)
	}
}
func TestAgentUpdateSuccessRequiresFreshConnectionExactArtifactAndPersistsAfterRestart(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	f.authorize(t, op)
	if err := f.u.ObserveStatus("node", f.stream, statusFor(op.ID, f.old, "reconnecting")); err == nil {
		t.Fatal("old binary claimed success")
	}
	stream := &mockStream{}
	f.h.connMgr.Register("node", stream)
	caps := &pb.UpdateCapabilities{ProtocolVersion: 1, Os: "linux", Arch: "amd64", Version: f.target.Version, Revision: f.target.Revision, Sha256: f.target.SHA256, BootId: "fresh-process-nonce", Supported: true}
	if err := f.u.ObserveCapabilities("node", stream, caps); err != nil {
		t.Fatal(err)
	}
	if err := f.u.ObserveStatus("node", f.stream, statusFor(op.ID, caps, "reconnecting")); err == nil {
		t.Fatal("stale connection claimed new artifact")
	}
	// Observation remains authoritative after the initiator's login is revoked.
	if _, err := f.st.EndSession("session", model.SessionEndRevokedSelf, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.u.ObserveStatus("node", stream, statusFor(op.ID, caps, "reconnecting")); err != nil {
		t.Fatal(err)
	}
	if pending, e := f.st.GetAgentUpdate(op.ID); e != nil || pending.State != "confirmation_pending" {
		t.Fatal("reconnect falsely finalized without durable agent acknowledgement", pending, e)
	}
	if err := f.u.ObserveStatus("node", stream, statusFor(op.ID, caps, "confirmed")); err != nil {
		t.Fatal(err)
	}
	got, err := f.st.GetAgentUpdate(op.ID)
	if err != nil || got.State != "succeeded" || got.ObservedSHA256 != f.target.SHA256 || got.ObservedBootID != caps.BootId {
		t.Fatalf("success evidence lost %+v %v", got, err)
	}
	if len(stream.sent) != 1 || stream.sent[0].GetUpdateConfirmation().State != "succeeded" {
		t.Fatal("durable confirmation missing")
	}
	if _, ok := f.u.terminals.Register("node", "after", "admin", ""); !ok {
		t.Fatal("verified success retained maintenance")
	}
	if _, err = NewAgentUpdates(f.st, f.h.connMgr, NewTerminalSessions()); err != nil {
		t.Fatal(err)
	}
	got, err = f.st.GetAgentUpdate(op.ID)
	if err != nil || got.State != "succeeded" {
		t.Fatal("restart changed confirmed success")
	}
}
func TestAgentUpdateRestartDoesNotReissueInstallationAndAllowsExactRollback(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	f.authorize(t, op)
	u, err := NewAgentUpdates(f.st, f.h.connMgr, NewTerminalSessions())
	if err != nil {
		t.Fatal(err)
	}
	f.h.updates = u
	u.SetArtifactResolver(f.u.resolve)
	got, err := f.st.GetAgentUpdate(op.ID)
	if err != nil || got.State != "unknown" || got.PreviousBootID != f.old.BootId {
		t.Fatal("restart failed closed metadata", got, err)
	}
	if _, err = f.h.AuthorizeUpdate(enrolledUpdateContext("node"), &pb.UpdateArtifactRequest{OperationId: op.ID}); err == nil {
		t.Fatal("restart retried uncertain installation")
	}
	stream := &mockStream{}
	f.h.connMgr.Register("node", stream)
	c := proto.Clone(f.old).(*pb.UpdateCapabilities)
	c.BootId = "fresh-rollback-nonce"
	if err = u.ObserveCapabilities("node", stream, c); err != nil {
		t.Fatal(err)
	}
	if err = u.ObserveStatus("node", stream, statusFor(op.ID, c, "rolled_back")); err != nil {
		t.Fatal(err)
	}
	if err = u.ObserveStatus("node", stream, statusFor(op.ID, c, "rollback_confirmed")); err != nil {
		t.Fatal(err)
	}
	got, err = f.st.GetAgentUpdate(op.ID)
	if err != nil || got.State != "rolled_back" || got.ObservedSHA256 != f.old.Sha256 {
		t.Fatal("exact rollback evidence missing", got, err)
	}
}
func TestAgentUpdateBootstrapIsOneUseNodeBoundRedactedAndRecoveryExplicit(t *testing.T) {
	f := newUpdateFixture(t)
	f.u.EndConnection("node", f.stream)
	op, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, f.idleAssertion())
	if err != nil || ticket == "" || op.State != "bootstrap_required" {
		t.Fatal("bootstrap not issued", err)
	}
	public, _ := json.Marshal(op)
	if bytes.Contains(public, []byte(ticket)) || bytes.Contains(public, []byte(op.TicketHash)) {
		t.Fatal("ticket disclosed in operation")
	}
	request := &pb.UpdateBootstrapRequest{Ticket: ticket, Capabilities: f.old}
	if _, err = f.h.BootstrapUpdate(enrolledUpdateContext("other-node"), request); err == nil {
		t.Fatal("ticket accepted other node")
	}
	result, err := f.h.BootstrapUpdate(enrolledUpdateContext("node"), request)
	if err != nil || result.OperationId != op.ID {
		t.Fatal("bootstrap failed", err)
	}
	if _, err = f.h.BootstrapUpdate(enrolledUpdateContext("node"), request); err == nil {
		t.Fatal("ticket reused")
	}
	f.authorize(t, op)
	unknown, err := f.u.Status("node", op.ID)
	if err != nil || unknown.State != "installing" {
		t.Fatal("installation not persisted", err)
	}
	oldstate := unknown.State
	unknown.State = "unknown"
	if err = f.st.UpdateAgentUpdate(unknown, oldstate); err != nil {
		t.Fatal(err)
	}
	if _, err = f.u.AcknowledgeRecovery("admin", "session", "node", op.ID, f.old.Sha256); err == nil {
		t.Fatal("acknowledged while supervisor may still run")
	}
	f.u.now = func() time.Time { return time.UnixMilli(op.ExpiresAt + 190000) }
	if _, err = f.u.AcknowledgeRecovery("admin", "session", "node", op.ID, f.target.SHA256); err == nil {
		t.Fatal("acknowledged wrong original hash")
	}
	recovered, err := f.u.AcknowledgeRecovery("admin", "session", "node", op.ID, f.old.Sha256)
	if err != nil || recovered.State != "recovery_acknowledged" || recovered.ObservedSHA256 != "" {
		t.Fatal("recovery fabricated confirmation", recovered, err)
	}
}

// Assert generated streaming RPC shape stays compatible with the service.
var _ pb.AgentService_DownloadUpdateServer = (*updateDownloadStream)(nil)

func TestOldAgentUpdateConfirmationCannotReleaseNewerMaintenance(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	f.authorize(t, op)
	stream := &mockStream{}
	f.h.connMgr.Register("node", stream)
	c := proto.Clone(f.old).(*pb.UpdateCapabilities)
	c.Version = f.target.Version
	c.Revision = f.target.Revision
	c.Sha256 = f.target.SHA256
	c.BootId = "fresh-updated-process"
	if err := f.u.ObserveCapabilities("node", stream, c); err != nil {
		t.Fatal(err)
	}
	if err := f.u.ObserveStatus("node", stream, statusFor(op.ID, c, "reconnecting")); err != nil {
		t.Fatal(err)
	}
	if err := f.u.ObserveStatus("node", stream, statusFor(op.ID, c, "confirmed")); err != nil {
		t.Fatal(err)
	}
	f.target.Version = "2.0.2-prototype.1"
	f.u.SetArtifactResolver(func(string, string) (model.AgentArtifact, error) { return f.target, nil })
	newOp := f.start(t)
	if err := f.u.ObserveStatus("node", stream, statusFor(op.ID, c, "reconnecting")); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.u.terminals.Register("node", "unsafe", "admin", ""); ok {
		t.Fatal("old completion cleared newer terminal maintenance")
	}
	if err := f.h.connMgr.SendToAgent("node", &pb.HubMessage{Payload: &pb.HubMessage_ExecutionPrepare{ExecutionPrepare: &pb.ExecutionPrepare{ExecutionId: "unsafe"}}}); err == nil {
		t.Fatal("old completion cleared newer control maintenance")
	}
	f.u.mu.Lock()
	_, exists := f.u.origins[newOp.ID]
	f.u.mu.Unlock()
	if !exists {
		t.Fatal("old completion removed new operation authority")
	}
}
func TestAgentUpdateConcurrentNodesCannotExceedGlobalOperationLimit(t *testing.T) {
	f := newUpdateFixture(t)
	const nodes = 40
	for i := 0; i < nodes; i++ {
		id := fmt.Sprintf("node-%d", i)
		if err := f.st.CreateServer(&model.Server{ID: id, Name: id, Status: "online", Labels: "{}"}); err != nil {
			t.Fatal(err)
		}
		stream := &mockStream{}
		f.h.connMgr.Register(id, stream)
		if err := f.u.ObserveCapabilities(id, stream, f.old); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	accepted := make(chan string, nodes)
	for i := 0; i < nodes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("node-%d", i)
			if op, _, err := f.u.Start(context.Background(), "admin", "session", id, f.target.Version, f.target.Revision, f.idleAssertion()); err == nil {
				accepted <- op.ID
			}
		}(i)
	}
	wg.Wait()
	close(accepted)
	if len(accepted) != 32 {
		t.Fatalf("accepted %d concurrent operations; expected32", len(accepted))
	}
	f.u.mu.Lock()
	count := len(f.u.origins)
	f.u.mu.Unlock()
	if count != 32 {
		t.Fatalf("reserved%d operations", count)
	}
}

func TestAgentUpdateStartReplacesExpiredPreinstallButNeverRetriesAuthorizedInstall(t *testing.T) {
	for _, phase := range []string{"bootstrap_required", "installing"} {
		t.Run(phase, func(t *testing.T) {
			f := newUpdateFixture(t)
			if phase == "bootstrap_required" {
				f.u.EndConnection("node", f.stream)
			}
			op, _, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, f.idleAssertion())
			if err != nil {
				t.Fatal(err)
			}
			if phase == "installing" {
				f.authorize(t, op)
			}
			f.u.now = func() time.Time { return time.UnixMilli(op.ExpiresAt + 1) }
			second, _, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, f.idleAssertion())
			old, e := f.st.GetAgentUpdate(op.ID)
			if e != nil {
				t.Fatal(e)
			}
			if phase == "bootstrap_required" {
				if err != nil || second.ID == op.ID || old.State != "expired" {
					t.Fatal("expired ticket could not be replaced", second, old, err)
				}
			} else if err == nil || old.State != "unknown" {
				t.Fatal("authorized installation retried", old, err)
			}
		})
	}
}

func TestAgentUpdateDispatchAndAuditFailureReleaseOnlyPreinstallReservation(t *testing.T) {
	for _, phase := range []string{"dispatch", "audit"} {
		t.Run(phase, func(t *testing.T) {
			f := newUpdateFixture(t)
			if phase == "dispatch" {
				f.stream.sendErr = errors.New("control transport refused")
			} else {
				if _, err := f.st.DB().Exec(`CREATE TRIGGER update_audit_outage BEFORE INSERT ON audit_logs WHEN NEW.action LIKE 'server.agent_update.%' BEGIN SELECT RAISE(ABORT,'fixture audit outage'); END`); err != nil {
					t.Fatal(err)
				}
			}
			op, _, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, f.idleAssertion())
			if err == nil {
				t.Fatal("failed dispatch/audit returned success")
			}
			got, err := f.st.GetAgentUpdate(op.ID)
			if err != nil || got.State != "failed" {
				t.Fatal("preinstall failure not durable", got, err)
			}
			if _, ok := f.u.terminals.Register("node", "recovery", "admin", ""); !ok {
				t.Fatal("preinstall failure retained maintenance")
			}
			if _, err = f.h.AuthorizeUpdate(enrolledUpdateContext("node"), &pb.UpdateArtifactRequest{OperationId: op.ID}); err == nil {
				t.Fatal("failed operation retained installation authority")
			}
		})
	}
}
func TestAgentUpdateFailureAfterAuthorizationRetainsUnknownAndMaintenance(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	if err := f.u.ObserveStatus("node", f.stream, statusFor(op.ID, f.old, "downloading")); err != nil {
		t.Fatal(err)
	}
	f.authorize(t, op)
	if err := f.u.ObserveStatus("node", f.stream, statusFor(op.ID, f.old, "failed")); err != nil {
		t.Fatal(err)
	}
	got, err := f.st.GetAgentUpdate(op.ID)
	if err != nil || got.State != "unknown" {
		t.Fatal("authorized failure falsely completed", got, err)
	}
	if _, ok := f.u.terminals.Register("node", "unsafe", "admin", ""); ok {
		t.Fatal("uncertain helper allowed new execution")
	}
	wrong := statusFor(op.ID, f.old, "reconnecting")
	wrong.Sha256 = f.target.SHA256
	if err = f.u.ObserveStatus("node", f.stream, wrong); err == nil {
		t.Fatal("inconsistent current metadata accepted")
	}
	if err = f.u.ObserveStatus("node", f.stream, nil); err == nil {
		t.Fatal("missing status accepted")
	}
}
func TestAgentUpdateDownloadFailuresAndGlobalTransferBound(t *testing.T) {
	for _, phase := range []string{"capacity", "send", "truncated", "grown", "missing", "changed-manifest", "oversize"} {
		t.Run(phase, func(t *testing.T) {
			f := newUpdateFixture(t)
			op := f.start(t)
			stream := &updateDownloadStream{ctx: enrolledUpdateContext("node")}
			switch phase {
			case "capacity":
				for i := 0; i < cap(f.u.transfers); i++ {
					f.u.transfers <- struct{}{}
				}
			case "send":
				stream.sendErr = errors.New("fixture send failed")
			case "truncated":
				if err := os.WriteFile(f.target.BinaryPath, []byte("short"), 0600); err != nil {
					t.Fatal(err)
				}
			case "grown":
				if err := os.WriteFile(f.target.BinaryPath, append(f.body, 'x'), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(f.target.BinaryPath); err != nil {
					t.Fatal(err)
				}
			case "changed-manifest":
				f.target.Version = "2.0.2"
				f.u.SetArtifactResolver(func(string, string) (model.AgentArtifact, error) { return f.target, nil })
			case "oversize":
				f.target.Bytes = MaxAgentArtifactBytes + 1
				f.u.SetArtifactResolver(func(string, string) (model.AgentArtifact, error) { return f.target, nil })
			}
			err := f.h.DownloadUpdate(&pb.UpdateArtifactRequest{OperationId: op.ID}, stream)
			if err == nil {
				t.Fatal("unsafe/failed transfer returned success")
			}
			if phase == "capacity" {
				if status.Code(err) != codes.ResourceExhausted {
					t.Fatal("unbounded concurrent transfer", err)
				}
			} else if len(f.u.transfers) != 0 {
				t.Fatal("failed transfer retained slot")
			}
		})
	}
}

func TestAgentUpdateLostFirstConfirmationNeverReportsLegacyRollbackSuccess(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	f.authorize(t, op)
	stream := &mockStream{sendErr: errors.New("confirmation delivery lost")}
	f.h.connMgr.Register("node", stream)
	c := proto.Clone(f.old).(*pb.UpdateCapabilities)
	c.Version = f.target.Version
	c.Revision = f.target.Revision
	c.Sha256 = f.target.SHA256
	c.BootId = "fresh-candidate-boot"
	if err := f.u.ObserveCapabilities("node", stream, c); err != nil {
		t.Fatal(err)
	}
	if err := f.u.ObserveStatus("node", stream, statusFor(op.ID, c, "reconnecting")); err == nil {
		t.Fatal("missing confirmation delivery ignored")
	}
	got, err := f.st.GetAgentUpdate(op.ID)
	if err != nil || got.State != "confirmation_pending" {
		t.Fatal("lost confirmation falsely succeeded", got, err)
	}
	// The supervisor restored a legacy agent, which reconnects without the new
	// capability/report protocol. An online heartbeat cannot prove its digest.
	f.h.connMgr.Register("node", &mockStream{})
	f.u.now = func() time.Time { return time.UnixMilli(op.ExpiresAt + 1) }
	got, err = f.u.Status("node", op.ID)
	if err != nil || got.State != "unknown" {
		t.Fatal("legacy rollback kept stale success", got, err)
	}
	if _, ok := f.u.terminals.Register("node", "unsafe", "admin", ""); ok {
		t.Fatal("unconfirmed rollback released maintenance")
	}
}
func TestAgentUpdateLostFinalAckAndAuditFailureRecoverThroughReconnect(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	f.authorize(t, op)
	stream := &mockStream{ctx: enrolledUpdateContext("node")}
	f.h.connMgr.Register("node", stream)
	c := proto.Clone(f.old).(*pb.UpdateCapabilities)
	c.Version = f.target.Version
	c.Revision = f.target.Revision
	c.Sha256 = f.target.SHA256
	c.BootId = "durably-confirmed-candidate"
	if err := f.u.ObserveCapabilities("node", stream, c); err != nil {
		t.Fatal(err)
	}
	if err := f.u.ObserveStatus("node", stream, statusFor(op.ID, c, "reconnecting")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`CREATE TRIGGER update_ack_outage BEFORE INSERT ON audit_logs WHEN NEW.action='server.agent_update.succeeded' BEGIN SELECT RAISE(ABORT,'fixture final audit outage'); END`); err != nil {
		t.Fatal(err)
	}
	message := &pb.AgentMessage{Payload: &pb.AgentMessage_UpdateStatus{UpdateStatus: statusFor(op.ID, c, "confirmed")}}
	if err := f.h.routeAgentMessage("node", stream, message); err == nil {
		t.Fatal("failed final persistence did not request control reconnect")
	}
	if _, err := f.st.DB().Exec("DROP TRIGGER update_ack_outage"); err != nil {
		t.Fatal(err)
	}
	u, err := NewAgentUpdates(f.st, f.h.connMgr, NewTerminalSessions())
	if err != nil {
		t.Fatal(err)
	}
	f.h.updates = u
	// The initiating account may have been deleted after installation. Final
	// observation audits the enrolled agent, retaining requester ID metadata.
	if err = f.st.DeleteUser("admin"); err != nil {
		t.Fatal(err)
	}
	newStream := &mockStream{ctx: enrolledUpdateContext("node")}
	f.h.connMgr.Register("node", newStream)
	if err = u.ObserveCapabilities("node", newStream, c); err != nil {
		t.Fatal(err)
	}
	if err = f.h.routeAgentMessage("node", newStream, message); err != nil {
		t.Fatal("durable final ack could not reconcile", err)
	}
	got, err := f.st.GetAgentUpdate(op.ID)
	if err != nil || got.State != "succeeded" {
		t.Fatal("final ack lost after reconnect/Hub restart", got, err)
	}
}
