package sshgw

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/testaudit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// Install an exact, locally consistent synthetic approved history and private
// marker. Real quorum/MFA application is covered by HTTP/native integration;
// these unit tests isolate the subsequent live execution admission boundary.
func admissionApprovedPolicy(t *testing.T, s *Server, version uint64, policy model.AuditPolicy) model.PolicyVersion {
	t.Helper()
	change := model.SecurityChangePayload{Kind: "policy", Policy: &policy}
	if version == 2 {
		change.Kind = "bootstrap"
		change.Nominations = []model.SecurityNomination{
			{UserID: "admission-actor", PersonID: "synthetic-officer", Roles: []model.Role{model.RoleSecurityOfficer}},
			{UserID: "synthetic-approver-a", PersonID: "synthetic-approver-a", Roles: []model.Role{model.RoleSecurityApprover}},
			{UserID: "synthetic-approver-b", PersonID: "synthetic-approver-b", Roles: []model.Role{model.RoleSecurityApprover}},
		}
	}
	rawChange, err := json.Marshal(change)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := authorization.Normalize(authorization.Proposal{Reason: "Synthetic admission boundary fixture", ExpectedVersion: version - 1, Change: rawChange})
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("synthetic-admission-policy-%d", version)
	if _, err := s.cfg.Store.DB().Exec(`INSERT INTO security_changes(id,revision,requester_id,requester_person,requester_generation,expected_version,digest,reason,payload,state,created_at,expires_at) VALUES(?,1,'admission-actor','synthetic-officer',0,?,?,?,?,'applied',?,?)`, id, version-1, proposal.Digest, proposal.Proposal.Reason, proposal.Bytes, time.Now().Unix(), time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	digest := authorization.Digest(raw)
	if _, err := s.cfg.Store.DB().Exec(`INSERT INTO audit_policy_versions(version,payload,digest,request_id) VALUES(?,?,?,?) ON CONFLICT(version) DO UPDATE SET payload=excluded.payload,digest=excluded.digest,request_id=excluded.request_id`, version, raw, digest, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.cfg.Store.DB().Exec("UPDATE audit_policy_state SET active_version=?,state='enhanced' WHERE id=1", version); err != nil {
		t.Fatal(err)
	}
	if s.cfg.SecurityTransition.EnrollmentPath == "" {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		s.cfg.SecurityTransition = authorization.TransitionConfig{InstallationID: "synthetic-admission-installation", EnrollmentPath: filepath.Join(dir, "enrollment.json")}
	}
	marker, err := json.Marshal(authorization.EnrollmentMarker{InstallationID: s.cfg.SecurityTransition.InstallationID, Version: version, SHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.cfg.SecurityTransition.EnrollmentPath, marker, 0600); err != nil {
		t.Fatal(err)
	}
	stored, err := s.cfg.Store.GetPolicyVersion(version)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func liveAdmissionFixture(t *testing.T, command string) (*Server, *testaudit.Fixture, execParams, *pb.ExecutionPrepared, model.PolicyVersion) {
	t.Helper()
	s, archive, _, _, version := evidenceFailureFixture(t)
	u := &model.User{ID: "admission-actor", Username: "admission_actor", Email: "admission@synthetic.invalid", Role: model.RoleAdmin, AuthProvider: model.AuthProviderLocal}
	if err := s.cfg.Store.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.cfg.Store.CreateServer(&model.Server{ID: "node", Name: "synthetic-target", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	s.cfg.ConnMgr = connmgr.New()
	s.cfg.Terminals = grpcserver.NewTerminalSessions()
	s.cfg.Executions = grpcserver.NewExecutionSessions(s.cfg.Terminals, s.cfg.ConnMgr)
	control := newStubAgent(grpcserver.NewPendingRequests(), "node")
	s.cfg.ConnMgr.Register("node", control)
	s.cfg.Executions.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, ProtectedScript: true, BootId: "synthetic-boot"})
	version = admissionApprovedPolicy(t, s, 2, version.Policy)
	policy, err := s.securityService().PolicyForExecution(u.ID, "node")
	if err != nil || !policy.Enhanced {
		t.Fatal("fixture failed the real local continuity guard:", err)
	}
	u, err = s.cfg.Store.GetUserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.cfg.Executions.Register("node", "live-admission", u.ID, "", []byte(command))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.cfg.Executions.Remove("node", session.ID) })
	p := execParams{bridgeParams: bridgeParams{userID: u.ID, username: u.Username, serverID: "node", serverName: "synthetic-target"}, user: u, session: session, policy: policy}
	p.metadata, err = s.newExecutionMetadata(p, session.ID, command)
	if err != nil {
		t.Fatal(err)
	}
	prepared := &pb.ExecutionPrepared{Binding: &pb.ExecutionBinding{ExecutionId: session.ID, PreparationId: "prepared-admission", BootId: "synthetic-boot", NodeId: "node", ExpiresUnixMilli: time.Now().Add(45 * time.Second).UnixMilli()}, Identity: &pb.ExecutionIdentity{Username: "root", Groups: []uint32{0}, GroupsSha256: make([]byte, sha256.Size), IdentitySha256: make([]byte, sha256.Size), Home: "/root", Shell: "/bin/sh", Cwd: "/root"}, Limits: &pb.ExecutionLimits{MaxFrameBytes: 32768, MaxBufferBytes: 1 << 20, RuntimeSeconds: 60, TermGraceSeconds: 5, BlockedConsumerSeconds: 60}}
	p.metadata.Preparation = executionPreparation(prepared)
	if err := s.cfg.Store.CreateExecution(p.metadata); err != nil {
		t.Fatal(err)
	}
	if err := s.cfg.Store.PrepareExecution(session.ID, p.metadata.Preparation); err != nil {
		t.Fatal(err)
	}
	return s, archive, p, prepared, version
}

func admissionDispatchCount(t *testing.T, s *Server, id string) int {
	t.Helper()
	var count int
	if err := s.cfg.Store.DB().QueryRow("SELECT COUNT(*) FROM execution_dispatches WHERE execution_id=?", id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestProtectedAdmissionLiveAuthorityChangeCannotUseArchivedPermit(t *testing.T) {
	for _, change := range []string{"policy-before-claim", "policy-before-start", "node-before-start"} {
		t.Run(change, func(t *testing.T) {
			s, archive, p, prepared, version := liveAdmissionFixture(t, "id")
			if change == "policy-before-claim" {
				candidate := version.Policy
				candidate.RuntimeSeconds = 120
				admissionApprovedPolicy(t, s, 3, candidate)
			}
			receipt, expiry, beforeStart, err := s.admitProtectedExecution(context.Background(), p, "id", prepared, &protectedSubmission{})
			if len(archive.Originals.Envelopes()) != 1 {
				t.Fatal("test did not reach exact independent receipt preservation")
			}
			if change == "policy-before-claim" {
				if err == nil || receipt.Token == "" || expiry != 0 || beforeStart != nil || admissionDispatchCount(t, s, p.session.ID) != 0 {
					t.Fatal("new live policy allowed old prepared input to consume a dispatch")
				}
				stored, err := s.cfg.Store.GetExecution(p.session.ID)
				if err != nil || stored.State != "prepared" || stored.AdmissionDisposition != "archived_unused" {
					t.Fatal("refused old policy lost its archived-unused disposition")
				}
				return
			}
			if err != nil || receipt.Token == "" || expiry <= time.Now().UnixMilli() || beforeStart == nil || admissionDispatchCount(t, s, p.session.ID) != 1 {
				t.Fatal("valid exact admission did not consume one durable permit:", err)
			}
			if err := beforeStart(); err != nil {
				t.Fatal("unchanged launch authority was refused:", err)
			}
			if change == "policy-before-start" {
				candidate := version.Policy
				candidate.RuntimeSeconds = 120
				admissionApprovedPolicy(t, s, 3, candidate)
			} else if err := s.cfg.Store.UpdateServerStatus("node", "offline"); err != nil {
				t.Fatal(err)
			}
			if err := beforeStart(); err == nil || p.session.StartAttempted() {
				t.Fatal("authority changed after admission but still permitted a Start")
			}
			if admissionDispatchCount(t, s, p.session.ID) != 1 {
				t.Fatal("launch recheck replayed or removed a durable consumed permit")
			}
		})
	}
}

func TestProtectedAdmissionPersistenceFaultCannotLaunchOrReplayConsumedPermit(t *testing.T) {
	for _, phase := range []string{"submission", "receipt"} {
		t.Run(phase, func(t *testing.T) {
			s, archive, p, prepared, _ := liveAdmissionFixture(t, "id")
			column := "admission_event_id"
			if phase == "receipt" {
				column = "admission_receipt"
			}
			if _, err := s.cfg.Store.DB().Exec("CREATE TRIGGER admission_failure BEFORE UPDATE OF " + column + " ON executions BEGIN SELECT RAISE(ABORT,'synthetic admission durability refusal'); END"); err != nil {
				t.Fatal(err)
			}
			receipt, expiry, beforeStart, err := s.admitProtectedExecution(context.Background(), p, "id", prepared, &protectedSubmission{})
			if err == nil || expiry != 0 || beforeStart != nil || p.session.StartAttempted() {
				t.Fatal("failed local admission persistence returned launch authority")
			}
			count := admissionDispatchCount(t, s, p.session.ID)
			if phase == "submission" {
				if count != 0 || receipt.Token != "" || len(archive.Originals.Envelopes()) != 0 {
					t.Fatal("failed submission persistence reached the archive or dispatch")
				}
				return
			}
			if count != 1 || receipt.Token == "" || len(archive.Originals.Envelopes()) != 1 {
				t.Fatal("receipt persistence fault obscured the actual consumed permit")
			}
			if _, err := s.cfg.Store.DB().Exec("DROP TRIGGER admission_failure"); err != nil {
				t.Fatal(err)
			}
			if _, _, start, err := s.admitProtectedExecution(context.Background(), p, "id", prepared, &protectedSubmission{}); err == nil || start != nil || admissionDispatchCount(t, s, p.session.ID) != 1 {
				t.Fatal("local receipt repair retried an already consumed dispatch")
			}
		})
	}
}

func TestProtectedAdmissionDependencyAndBindingRefusalsPrecedeArchiveEffects(t *testing.T) {
	for _, phase := range []string{"policy-version", "resolver", "script-open", "invalid-binding", "wrong-consumer-id"} {
		t.Run(phase, func(t *testing.T) {
			command := "id"
			if phase == "script-open" {
				command = "/bin/sh -s"
			}
			s, archive, p, prepared, _ := liveAdmissionFixture(t, command)
			input := &protectedSubmission{}
			switch phase {
			case "policy-version":
				p.policy.SHA256 = auditrecord.Hash([]byte("another immutable policy"))
			case "resolver":
				s.cfg.ProtectedExecution.ResolveArchive = func(context.Context, model.PolicyVersion) (auditgate.Gate, error) {
					return auditgate.Gate{}, errors.New("exact destination unavailable")
				}
			case "script-open":
				input.file = &submissionFaultFile{}
				hash := sha256.Sum256([]byte("true\n"))
				input.hash, input.length = hash[:], 5
			case "invalid-binding":
				prepared.Binding.PreparationId = ""
			case "wrong-consumer-id":
				if err := (executionConsumer{server: s, params: p}).Claim(context.Background(), "other-execution", prepared.Binding.PreparationId, auditrecord.Hash([]byte("receipt"))); !errors.Is(err, auditgate.ErrReceipt) {
					t.Fatal("receipt consumer accepted another execution identity")
				}
				if admissionDispatchCount(t, s, p.session.ID) != 0 {
					t.Fatal("wrong consumer identity touched dispatch authority")
				}
				return
			}
			if _, _, start, err := s.admitProtectedExecution(context.Background(), p, command, prepared, input); err == nil || start != nil || admissionDispatchCount(t, s, p.session.ID) != 0 || len(archive.Originals.Envelopes()) != 0 {
				t.Fatal("missing exact prerequisite reached archive/dispatch effects")
			}
		})
	}
}
