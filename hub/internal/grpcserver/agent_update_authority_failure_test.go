package grpcserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// The artifact resolver is deliberately a barrier between the initial grant
// check and the policy-locked installation claim. These tests exercise a real
// late revocation rather than only refusing a previously invalid session.
func TestAgentUpdateFinalAuthorizationRechecksLateRevocation(t *testing.T) {
	for _, phase := range []string{"session", "connection", "policy", "artifact", "audit", "persistence"} {
		t.Run(phase, func(t *testing.T) {
			f := newUpdateFixture(t)
			op := f.start(t)
			f.u.SetArtifactResolver(func(string, string) (model.AgentArtifact, error) {
				switch phase {
				case "session":
					if _, err := f.st.EndSession("session", model.SessionEndRevokedAdmin, nil, time.Now()); err != nil {
						t.Fatal(err)
					}
				case "connection":
					f.h.connMgr.Register("node", &mockStream{})
				case "policy":
					if err := f.st.RequirePolicyRecovery(); err != nil {
						t.Fatal(err)
					}
				case "artifact":
					changed := f.target
					changed.SHA256 = strings.Repeat("c", 64)
					return changed, nil
				case "audit":
					if _, err := f.st.DB().Exec(`CREATE TRIGGER deny_update_admission_audit BEFORE INSERT ON audit_logs WHEN NEW.action='server.agent_update.installation_authorized' BEGIN SELECT RAISE(ABORT,'admission audit unavailable'); END`); err != nil {
						t.Fatal(err)
					}
				case "persistence":
					if _, err := f.st.DB().Exec(`CREATE TRIGGER deny_update_admission_state BEFORE UPDATE ON agent_updates WHEN NEW.state='installing' BEGIN SELECT RAISE(ABORT,'admission state unavailable'); END`); err != nil {
						t.Fatal(err)
					}
				}
				return f.target, nil
			})
			permit, err := f.h.AuthorizeUpdate(enrolledUpdateContext("node"), &pb.UpdateArtifactRequest{OperationId: op.ID})
			if err == nil || permit != nil {
				t.Fatal("late change yielded installation authority", phase, permit)
			}
			got, err := f.st.GetAgentUpdate(op.ID)
			if err != nil || got.State != "requested" {
				t.Fatal("denied admission changed durable installation state", got, err)
			}
			if _, ok := f.u.terminals.Register("node", "unsafe", "admin", ""); ok {
				t.Fatal("denied admission released an unresolved lease")
			}
		})
	}
}

func TestAgentUpdateInstallationPermitRepeatsOnlyBeforeOriginalConnectionChanges(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	f.authorize(t, op)
	permit, err := f.h.AuthorizeUpdate(enrolledUpdateContext("node"), &pb.UpdateArtifactRequest{OperationId: op.ID})
	if err != nil || permit.OperationId != op.ID || permit.ExpiresUnixMilli != op.ExpiresAt {
		t.Fatal("supervisor could not recheck original admission", permit, err)
	}
	f.h.connMgr.Register("node", &mockStream{})
	if _, err = f.h.AuthorizeUpdate(enrolledUpdateContext("node"), &pb.UpdateArtifactRequest{OperationId: op.ID}); err == nil {
		t.Fatal("replacement connection inherited installation authority")
	}
}

func TestAgentUpdateBootstrapPinsActualPlatformAndRejectsChangedOrExpiredArtifacts(t *testing.T) {
	for _, phase := range []string{"arm64", "changed-arm64-digest", "same-version", "downgrade", "expired", "invalid-capability"} {
		t.Run(phase, func(t *testing.T) {
			f := newUpdateFixture(t)
			f.u.EndConnection("node", f.stream)
			arm := f.target
			arm.Arch = "arm64"
			arm.SHA256 = strings.Repeat("b", 64)
			f.u.SetArtifactResolver(func(_ string, arch string) (model.AgentArtifact, error) {
				if arch == "arm64" {
					return arm, nil
				}
				return f.target, nil
			})
			op, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if op.Target.Arch != "" || op.Target.SHA256 != "" {
				t.Fatal("legacy node architecture was assumed")
			}
			c := proto.Clone(f.old).(*pb.UpdateCapabilities)
			c.Arch = "arm64"
			switch phase {
			case "changed-arm64-digest":
				arm.SHA256 = strings.Repeat("c", 64)
			case "same-version":
				c.Version = op.Target.Version
			case "downgrade":
				c.Version = "9.0.0"
			case "expired":
				f.u.now = func() time.Time { return time.UnixMilli(op.ExpiresAt + 1) }
			case "invalid-capability":
				c.Sha256 = "invalid"
			}
			request, err := f.h.BootstrapUpdate(enrolledUpdateContext("node"), &pb.UpdateBootstrapRequest{Ticket: ticket, Capabilities: c})
			if phase == "arm64" {
				if err != nil || request.Sha256 != strings.Repeat("b", 64) {
					t.Fatal("bootstrap chose the wrong pinned platform", request, err)
				}
				got, e := f.st.GetAgentUpdate(op.ID)
				if e != nil || got.Target.Arch != "arm64" {
					t.Fatal("actual platform was not durable", got, e)
				}
			} else {
				if err == nil || request != nil {
					t.Fatal("unsafe bootstrap accepted", phase)
				}
				got, e := f.st.GetAgentUpdate(op.ID)
				if e != nil || got.State != "bootstrap_required" || got.TicketHash == "" {
					t.Fatal("rejected bootstrap consumed its ticket", got, e)
				}
			}
		})
	}
}

func TestAgentUpdateRestartClosesPreinstallAndRefusesCorruptOrOverCapacityState(t *testing.T) {
	for _, phase := range []string{"preinstall", "corrupt", "capacity", "persistence"} {
		t.Run(phase, func(t *testing.T) {
			f := newUpdateFixture(t)
			op := f.start(t)
			switch phase {
			case "corrupt":
				if _, err := f.st.DB().Exec("UPDATE agent_updates SET metadata='invalid' WHERE id=?", op.ID); err != nil {
					t.Fatal(err)
				}
			case "capacity":
				for i := 0; i < 32; i++ {
					extra := op
					extra.ID = fmt.Sprintf("extra-%d", i)
					extra.NodeID = extra.ID
					extra.State = "installing"
					if err := f.st.CreateAgentUpdate(extra); err != nil {
						t.Fatal(err)
					}
				}
			case "persistence":
				if _, err := f.st.DB().Exec(`CREATE TRIGGER deny_update_restart BEFORE UPDATE ON agent_updates BEGIN SELECT RAISE(ABORT,'reconciliation persistence unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			}
			service, err := NewAgentUpdates(f.st, f.h.connMgr, f.u.terminals)
			if phase == "preinstall" {
				if err != nil {
					t.Fatal(err)
				}
				got, e := f.st.GetAgentUpdate(op.ID)
				if e != nil || got.State != "failed" {
					t.Fatal("restart replayed a preinstall grant", got, e)
				}
				if _, ok := service.terminals.Register("node", "safe", "admin", ""); !ok {
					t.Fatal("closed preinstall grant retained maintenance")
				}
			} else if err == nil || service != nil {
				t.Fatal("unsafe durable state started maintenance service", phase)
			}
		})
	}
}

func TestAgentUpdateRecoveryRefusesNewerLeaseBusyNodeAndFailedDurableAudit(t *testing.T) {
	for _, phase := range []string{"newer-lease", "busy", "audit", "persistence", "revoked"} {
		t.Run(phase, func(t *testing.T) {
			f := newUpdateFixture(t)
			op := f.start(t)
			f.authorize(t, op)
			f.u.now = func() time.Time { return time.UnixMilli(op.ExpiresAt + 190001) }
			if _, err := f.u.Status("node", op.ID); err != nil {
				t.Fatal(err)
			}
			switch phase {
			case "newer-lease":
				f.u.terminals.SetMaintenance("node", "new-operation")
			case "busy":
				f.u.terminals.mu.Lock()
				f.u.terminals.sessions["busy-synthetic"] = &terminalSession{serverID: "node"}
				f.u.terminals.mu.Unlock()
			case "audit":
				if _, err := f.st.DB().Exec(`CREATE TRIGGER deny_recovery_audit BEFORE INSERT ON audit_logs WHEN NEW.action='server.agent_update.recovery_acknowledged' BEGIN SELECT RAISE(ABORT,'recovery audit unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			case "persistence":
				if _, err := f.st.DB().Exec(`CREATE TRIGGER deny_recovery_state BEFORE UPDATE ON agent_updates WHEN NEW.state='recovery_acknowledged' BEGIN SELECT RAISE(ABORT,'recovery state unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				if _, err := f.st.EndSession("session", model.SessionEndRevokedAdmin, nil, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.u.AcknowledgeRecovery("admin", "session", "node", op.ID, f.old.Sha256); err == nil {
				t.Fatal("unsafe recovery acknowledgement succeeded", phase)
			}
			got, err := f.st.GetAgentUpdate(op.ID)
			if err != nil || got.State != "unknown" || got.ObservedSHA256 != "" {
				t.Fatal("failed recovery fabricated terminal evidence", got, err)
			}
			if err = f.h.connMgr.SendToAgent("node", &pb.HubMessage{Payload: &pb.HubMessage_TerminalOpenRequest{TerminalOpenRequest: &pb.TerminalOpenRequest{SessionId: "unsafe"}}}); err == nil {
				t.Fatal("failed recovery released control maintenance")
			}
		})
	}
}

func TestAgentUpdateUnknownOperationExpiredAuthorityAndUnavailableServiceRefuse(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	f.u.now = func() time.Time { return time.UnixMilli(op.ExpiresAt + 1) }
	if _, err := f.h.AuthorizeUpdate(enrolledUpdateContext("node"), &pb.UpdateArtifactRequest{OperationId: op.ID}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("expired installation grant accepted", err)
	}
	if _, err := f.u.Status("other-node", op.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("cross-node update metadata disclosed", err)
	}
	f.h.updates = nil
	if _, err := f.h.AuthorizeUpdate(enrolledUpdateContext("node"), &pb.UpdateArtifactRequest{OperationId: op.ID}); status.Code(err) != codes.Unavailable {
		t.Fatal("missing service not explicit", err)
	}
}

func TestAgentUpdateControlCapabilityRequiresEnrolledMTLSAndCurrentGeneration(t *testing.T) {
	f := newUpdateFixture(t)
	f.u.EndConnection("node", f.stream)
	message := &pb.AgentMessage{Payload: &pb.AgentMessage_UpdateCapabilities{UpdateCapabilities: f.old}}
	if err := f.h.routeAgentMessage("node", f.stream, message); err != nil {
		t.Fatal(err)
	}
	if f.u.Capabilities("node") != nil {
		t.Fatal("plaintext/enrollment control published update support")
	}
	verified := &mockStream{ctx: enrolledUpdateContext("node")}
	f.h.connMgr.Register("node", verified)
	if err := f.h.routeAgentMessage("node", verified, message); err != nil {
		t.Fatal(err)
	}
	if c := f.u.Capabilities("node"); c == nil || c.Sha256 != f.old.Sha256 {
		t.Fatal("verified current update capability not published")
	}
	invalid := proto.Clone(f.old).(*pb.UpdateCapabilities)
	invalid.BootId = "short"
	if err := f.h.routeAgentMessage("node", verified, &pb.AgentMessage{Payload: &pb.AgentMessage_UpdateCapabilities{UpdateCapabilities: invalid}}); err != nil {
		t.Fatal(err)
	}
	if c := f.u.Capabilities("node"); c == nil || c.BootId != f.old.BootId {
		t.Fatal("invalid boot metadata replaced enrolled capability")
	}
	if err := f.u.ObserveCapabilities("node", f.stream, f.old); err == nil {
		t.Fatal("old control generation changed capability")
	}
	op := f.start(t)
	if err := f.h.routeAgentMessage("node", verified, &pb.AgentMessage{Payload: &pb.AgentMessage_UpdateStatus{UpdateStatus: statusFor(op.ID, f.old, "downloading")}}); err != nil {
		t.Fatal(err)
	}
	got, err := f.st.GetAgentUpdate(op.ID)
	if err != nil || got.State != "downloading" {
		t.Fatal("verified current control status was not durable", got, err)
	}
}
