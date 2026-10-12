package grpcserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/proto/updateutil"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func TestBootstrapOriginalAssertionIsScopedDurableAndOperatorAttributed(t *testing.T) {
	for _, fault := range []string{"valid", "partial", "malformed", "wrong_digest_format", "native", "known_capabilities", "observed_version", "observed_prefix", "observed_build_metadata", "same_version", "downgrade", "unconfirmed", "stale"} {
		t.Run(fault, func(t *testing.T) {
			f := newUpdateFixture(t)
			if fault != "native" {
				f.u.EndConnection("node", f.stream)
			}
			if fault == "known_capabilities" {
				c := proto.Clone(f.old).(*pb.UpdateCapabilities)
				c.ActivityQuiescenceVersion = 0
				if err := f.u.ObserveCapabilities("node", f.stream, c); err != nil {
					t.Fatal(err)
				}
			}
			a := BootstrapIdleAssertion{Confirmed: true, ConnectionID: f.h.connMgr.GetConn("node").GenerationID, Original: updateutil.BootstrapOriginal{Version: "0.1.0", SHA256: f.old.Sha256}}
			switch fault {
			case "partial":
				a.Original.SHA256 = ""
			case "malformed":
				a.Original.Version = "dev"
			case "wrong_digest_format":
				a.Original.SHA256 = strings.Repeat("A", 64)
			case "observed_version":
				if err := f.st.UpdateObservedAgentVersion("node", "1.9.0"); err != nil {
					t.Fatal(err)
				}
			case "observed_prefix":
				if err := f.st.UpdateObservedAgentVersion("node", "v0.1.0"); err != nil {
					t.Fatal(err)
				}
			case "observed_build_metadata":
				a.Original.Version = "0.1.0+other"
				if err := f.st.UpdateObservedAgentVersion("node", "0.1.0+actual"); err != nil {
					t.Fatal(err)
				}
			case "same_version":
				a.Original.Version = f.target.Version
			case "downgrade":
				a.Original.Version = "9.0.0"
			case "unconfirmed":
				a.Confirmed = false
			case "stale":
				a.ConnectionID = "stale"
			}
			op, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, a)
			if fault != "valid" {
				if err == nil || ticket != "" {
					t.Fatal("unsafe assertion issued authority", fault, err)
				}
				var count int
				if err := f.st.DB().QueryRow("SELECT COUNT(*) FROM agent_updates").Scan(&count); err != nil || count != 0 {
					t.Fatal("refusal created authority", count, err)
				}
				return
			}
			if err != nil || len(ticket) != 64 {
				t.Fatal(op, err)
			}
			persisted, err := f.st.GetAgentUpdate(op.ID)
			if err != nil || persisted.BootstrapOriginal != a.Original {
				t.Fatal("original assertion not durable", persisted, err)
			}
			raw, _ := json.Marshal(persisted)
			if strings.Contains(string(raw), "bootstrap_original") || strings.Contains(string(raw), a.Original.SHA256) {
				t.Fatal("private authority leaked in public operation", string(raw))
			}
			var detail, actor string
			if err := f.st.DB().QueryRow("SELECT detail,actor_type FROM audit_logs WHERE action='server.agent_update.manual_bootstrap_idle_confirmed'").Scan(&detail, &actor); err != nil || actor != "user" || !strings.Contains(detail, "original_identity_source=operator_assertion") || !strings.Contains(detail, "original_version=0.1.0") || !strings.Contains(detail, a.Original.SHA256) {
				t.Fatal("assertion lost operator provenance", detail, actor, err)
			}
		})
	}
}

func TestBootstrapOriginalIdentityMustMatchTicketBeforeConsumption(t *testing.T) {
	for _, fault := range []string{"valid", "version", "digest", "revision", "marker_missing", "marker_unbound", "binding_malformed", "other_node", "replay"} {
		t.Run(fault, func(t *testing.T) {
			f := newUpdateFixture(t)
			f.u.EndConnection("node", f.stream)
			a := f.idleAssertion()
			if fault != "marker_unbound" {
				a.Original = updateutil.BootstrapOriginal{Version: f.old.Version, SHA256: f.old.Sha256}
			}
			op, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, a)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "binding_malformed" {
				op.BootstrapOriginal.SHA256 = "bad"
				if err := f.st.UpdateAgentUpdate(op, "bootstrap_required"); err != nil {
					t.Fatal(err)
				}
			}
			c := proto.Clone(f.old).(*pb.UpdateCapabilities)
			req := &pb.UpdateBootstrapRequest{Ticket: ticket, Capabilities: c, OriginalIdentityAsserted: true}
			switch fault {
			case "version":
				c.Version = "0.0.1"
			case "digest":
				c.Sha256 = strings.Repeat("b", 64)
			case "revision":
				c.Revision = strings.Repeat("c", 40)
			case "marker_missing":
				req.OriginalIdentityAsserted = false
			}
			ctx := enrolledUpdateContext("node")
			if fault == "other_node" {
				ctx = enrolledUpdateContext("other")
			}
			result, err := f.h.BootstrapUpdate(ctx, req)
			if fault == "valid" || fault == "replay" {
				if err != nil || result.OperationId != op.ID {
					t.Fatal(result, err)
				}
				persisted, err := f.st.GetAgentUpdate(op.ID)
				if err != nil || persisted.PreviousVersion != a.Original.Version || persisted.PreviousSHA256 != a.Original.SHA256 || persisted.BootstrapOriginal != a.Original || persisted.TicketHash != "" {
					t.Fatal("redeemed original binding lost", persisted, err)
				}
				if fault == "replay" {
					if _, err := f.h.BootstrapUpdate(ctx, req); err == nil {
						t.Fatal("assertion bypassed one-use ticket")
					}
				}
			} else {
				if err == nil || result != nil {
					t.Fatal("mismatched original consumed ticket", fault)
				}
				persisted, err := f.st.GetAgentUpdate(op.ID)
				if err != nil || persisted.State != "bootstrap_required" || persisted.TicketHash != op.TicketHash {
					t.Fatal("refusal consumed ticket", persisted, err)
				}
			}
		})
	}
}

func TestBootstrapOriginalAssertionRechecksIdentityAfterArtifactResolution(t *testing.T) {
	for _, fault := range []string{"admission_capabilities", "redemption_capabilities", "redemption_observed_version"} {
		t.Run(fault, func(t *testing.T) {
			f := newUpdateFixture(t)
			f.u.EndConnection("node", f.stream)
			a := f.idleAssertion()
			a.Original = updateutil.BootstrapOriginal{Version: f.old.Version, SHA256: f.old.Sha256}
			resolve := f.u.resolve
			calls := 0
			inject := func(osName, arch string) (model.AgentArtifact, error) {
				calls++
				if fault != "admission_capabilities" || calls == 2 {
					if fault == "redemption_observed_version" {
						if err := f.st.UpdateObservedAgentVersion("node", "1.9.0"); err != nil {
							t.Fatal(err)
						}
					} else if err := f.u.ObserveCapabilities("node", f.stream, f.old); err != nil {
						t.Fatal(err)
					}
				}
				return resolve(osName, arch)
			}
			if fault == "admission_capabilities" {
				f.u.SetArtifactResolver(inject)
			}
			op, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, a)
			if fault == "admission_capabilities" {
				if err == nil || ticket != "" {
					t.Fatal("late capabilities bypassed original assertion admission")
				}
				var count int
				if err := f.st.DB().QueryRow("SELECT COUNT(*) FROM agent_updates").Scan(&count); err != nil || count != 0 {
					t.Fatal("late observation created authority", count, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f.u.SetArtifactResolver(inject)
			if _, err := f.h.BootstrapUpdate(enrolledUpdateContext("node"), &pb.UpdateBootstrapRequest{Ticket: ticket, Capabilities: f.old, OriginalIdentityAsserted: true}); err == nil {
				t.Fatal("late enrolled identity change consumed assertion ticket")
			}
			persisted, err := f.st.GetAgentUpdate(op.ID)
			if err != nil || persisted.State != "bootstrap_required" || persisted.TicketHash != op.TicketHash {
				t.Fatal("late observation consumed ticket", persisted, err)
			}
		})
	}
}
