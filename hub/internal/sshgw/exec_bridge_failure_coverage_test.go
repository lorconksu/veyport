package sshgw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Drive the real preparation registry and Execute handler. The fake agent
// supplies protocol responses and transport faults; it never runs a command.
type failingExecBridgeAgent struct {
	*stubAgent
	executions *grpcserver.ExecutionSessions
	handler    *grpcserver.Handler
	phase      string
	fixture    *fixture
	mu         sync.Mutex
	stream     *failingExecBridgeStream
}

func (a *failingExecBridgeAgent) Send(msg *pb.HubMessage) error {
	if err := a.stubAgent.Send(msg); err != nil {
		return err
	}
	if req := msg.GetExecutionPrepare(); req != nil {
		if a.phase == "prepare-send" {
			return errors.New("prepare transport unavailable")
		}
		hash := sha256.Sum256([]byte(req.Command))
		prepared := &pb.ExecutionPrepared{ExecutionId: req.ExecutionId, CommandSha256: hash[:], Limits: req.Limits,
			Binding:  &pb.ExecutionBinding{ExecutionId: req.ExecutionId, NodeId: req.NodeId, PreparationId: "bridge-preparation", BootId: "bridge-boot", ExpiresUnixMilli: time.Now().Add(30 * time.Second).UnixMilli()},
			Identity: &pb.ExecutionIdentity{Username: "root", Shell: "/bin/sh", Cwd: "/", Home: "/", GroupsSha256: make([]byte, 32), IdentitySha256: make([]byte, 32)}}
		if a.phase == "malformed-preparation" {
			prepared.Identity = nil
		}
		if a.phase == "expired-preparation" {
			prepared.Binding.ExpiresUnixMilli = time.Now().Add(30 * time.Millisecond).UnixMilli()
		}
		if accepted := a.executions.DeliverPrepared(testServerID, a, prepared); !accepted && a.phase != "malformed-preparation" {
			return errors.New("fixture preparation rejected unexpectedly")
		}
		if a.phase == "expired-preparation" {
			// A delayed control send can return after a valid prepared reply
			// has expired. Later attachment must refuse that exact preparation.
			<-time.After(time.Until(time.UnixMilli(prepared.Binding.ExpiresUnixMilli)) + time.Millisecond)
		}
	}
	if attach := msg.GetExecutionAttach(); attach != nil {
		if a.phase == "attach-send" {
			return errors.New("attach transport unavailable")
		}
		if a.phase == "attach-disconnect" {
			a.fixture.connMgr.UnregisterIfCurrent(testServerID, a)
			a.executions.EndConnection(testServerID, a, "execution transport lost")
			return nil
		}
		if a.phase == "credential-change" {
			if _, err := a.fixture.store.DB().Exec("UPDATE users SET must_change_password=1 WHERE id=?", testUserID); err != nil {
				return err
			}
		}
		// The test supplies the verified TLS peer state at the handler boundary;
		// certificate-chain verification itself is covered by transport tests.
		cert := &x509.Certificate{Raw: []byte("local-verified-fixture"), Subject: pkix.Name{CommonName: testServerID}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		ctx, cancel := context.WithCancel(peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}}}))
		stream := &failingExecBridgeStream{ctx: ctx, cancel: cancel, incoming: make(chan *pb.ExecutionAgentMessage, 2), done: make(chan struct{}), failStart: a.phase == "start-send"}
		stream.incoming <- &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Attach{Attach: attach}}
		a.mu.Lock()
		a.stream = stream
		a.mu.Unlock()
		go func() {
			defer close(stream.done)
			defer cancel()
			_ = a.handler.Execute(stream)
		}()
	}
	if msg.GetExecutionCancel() != nil {
		a.closeStream()
	}
	return nil
}

func (a *failingExecBridgeAgent) closeStream() {
	a.mu.Lock()
	stream := a.stream
	a.mu.Unlock()
	if stream != nil {
		stream.cancel()
	}
}

type failingExecBridgeStream struct {
	pb.AgentService_ExecuteServer
	ctx       context.Context
	cancel    context.CancelFunc
	incoming  chan *pb.ExecutionAgentMessage
	done      chan struct{}
	starts    atomic.Int32
	failStart bool
}

func (s *failingExecBridgeStream) Context() context.Context { return s.ctx }
func (s *failingExecBridgeStream) Recv() (*pb.ExecutionAgentMessage, error) {
	select {
	case msg := <-s.incoming:
		return msg, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *failingExecBridgeStream) Send(msg *pb.ExecutionHubMessage) error {
	if start := msg.GetStart(); start != nil {
		s.starts.Add(1)
		if s.failStart {
			return errors.New("Start reply lost")
		}
		s.incoming <- &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Started{Started: &pb.ExecutionStarted{Binding: start.Binding}}}
	}
	return nil
}

func TestExecBridgeFailureBoundariesPreserveClaimsAndCleanup(t *testing.T) {
	for _, phase := range []string{"submitted-audit", "prepare-send", "malformed-preparation", "preparation-write", "prepared-audit", "expired-preparation", "attach-send", "attach-disconnect", "credential-change", "dispatch-audit", "start-send", "running-write"} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t, nil)
			executions := grpcserver.NewExecutionSessions(f.terminals, f.connMgr)
			f.srv.cfg.Executions = executions
			a := &failingExecBridgeAgent{stubAgent: f.agent, executions: executions, phase: phase, fixture: f}
			f.connMgr.Register(testServerID, a)
			executions.SetCapabilities(testServerID, a, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "bridge-boot"})
			gs := grpcserver.New(grpcserver.Config{Store: f.store, ConnMgr: f.connMgr, TerminalSessions: f.terminals, ExecutionSessions: executions})
			a.handler = gs.Handler()
			t.Cleanup(gs.Stop)
			t.Cleanup(a.closeStream)
			const command = "CANARY_PRIVATE_COMMAND"
			u, err := f.store.GetUserByID(testUserID)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := authorization.New(f.store).PolicyForExecution(testUserID, testServerID)
			if err != nil {
				t.Fatal(err)
			}
			p := execParams{user: u, policy: policy, bridgeParams: bridgeParams{serverID: testServerID, serverName: testServerName, userID: testUserID, username: testUsername, remoteIP: "127.0.0.1"}}
			p.session, err = executions.Register(testServerID, "bridge-fault", testUserID, "", []byte(command))
			if err != nil {
				t.Fatal(err)
			}
			p.metadata, err = f.srv.newExecutionMetadata(p, p.session.ID, command)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.store.CreateExecution(p.metadata); err != nil {
				t.Fatal(err)
			}
			var trigger string
			switch phase {
			case "submitted-audit", "prepared-audit", "dispatch-audit":
				action := map[string]string{"submitted-audit": model.AuditExecutionSubmitted, "prepared-audit": model.AuditExecutionPrepared, "dispatch-audit": model.AuditExecutionDispatched}[phase]
				trigger = fmt.Sprintf("CREATE TRIGGER execution_test_fault BEFORE INSERT ON audit_logs WHEN NEW.action='%s' BEGIN SELECT RAISE(FAIL,'local audit unavailable'); END", action)
			case "preparation-write":
				trigger = "CREATE TRIGGER execution_test_fault BEFORE UPDATE OF preparation ON executions BEGIN SELECT RAISE(FAIL,'local preparation unavailable'); END"
			case "running-write":
				trigger = "CREATE TRIGGER execution_test_fault BEFORE UPDATE OF state ON executions WHEN NEW.state='running' BEGIN SELECT RAISE(FAIL,'local state unavailable'); END"
			}
			if trigger != "" {
				if _, err := f.store.DB().Exec(trigger); err != nil {
					t.Fatal(err)
				}
			}
			ch := newFakeChannel()
			t.Cleanup(func() { _ = ch.Close() })
			done := make(chan struct{})
			go func() { defer close(done); f.srv.runExec(ch, p, command) }()
			waitForDone(t, done, "execution failure cleanup")
			got, err := f.store.GetExecution(p.session.ID)
			if err != nil || got.FinishedAt == nil || got.ExitCode != nil || got.State == "exited" || !ch.isClosed() || len(f.terminals.ListByUser(testUserID)) != 0 {
				t.Fatalf("failure fabricated completion or retained registration: %+v %v", got, err)
			}
			wantState := "admission_failed"
			if phase == "dispatch-audit" {
				wantState = "launch_failed"
			} else if phase == "start-send" || phase == "running-write" {
				wantState = "outcome_unknown"
			}
			if got.State != wantState && !(phase == "running-write" && got.State == "cancelled") {
				t.Fatalf("wrong failure boundary: %s %+v", phase, got)
			}
			wantCode := uint32(exitAborted)
			if phase == "submitted-audit" {
				wantCode = 1
			}
			// Cancellation closes SSH I/O to unblock both relays. A transport
			// abort can therefore precede its best-effort final exit request.
			// Require the exact failure code when delivered, and never success;
			// the durable outcome and closed channel are checked above.
			hasStatus := false
			for _, request := range ch.requests() {
				if request.name == "exit-status" {
					hasStatus = true
					var status struct{ Status uint32 }
					if ssh.Unmarshal(request.payload, &status) != nil || status.Status != wantCode {
						t.Fatal("failure delivered a fabricated successful SSH exit")
					}
				}
			}
			if phase == "submitted-audit" && !hasStatus {
				t.Fatal("submission refusal did not deliver its final status")
			}
			var claims int
			if err := f.store.DB().QueryRow("SELECT COUNT(*) FROM execution_dispatches WHERE execution_id=?", p.session.ID).Scan(&claims); err != nil {
				t.Fatal(err)
			}
			claimed := phase == "dispatch-audit" || phase == "start-send" || phase == "running-write"
			if (claims == 1) != claimed || claims > 1 {
				t.Fatalf("failure crossed durable admission boundary: %s claims=%d", phase, claims)
			}
			a.mu.Lock()
			stream := a.stream
			a.mu.Unlock()
			if stream != nil {
				a.closeStream()
				waitForDone(t, stream.done, "execution RPC cleanup")
				wantStarts := int32(0)
				if phase == "start-send" || phase == "running-write" {
					wantStarts = 1
				}
				if stream.starts.Load() != wantStarts || p.session.StartAttempted() != (wantStarts != 0) {
					t.Fatal("failure concealed or fabricated a Start attempt")
				}
			}
			if phase == "submitted-audit" && len(a.messages()) != 0 {
				t.Fatal("ordinary audit failure contacted the execution agent")
			}
			if claimed && f.store.ClaimExecutionDispatch(p.session.ID, p.session.Binding().PreparationId) == nil {
				t.Fatal("failed or uncertain dispatch became replayable")
			}
		})
	}
}

func TestSSHExecSubmissionStorageAndCapacityFailuresNeverPrepare(t *testing.T) {
	for _, phase := range []string{"identity", "metadata", "capacity", "deleted-user", "deleted-node", "lost-grant"} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t, nil)
			f.connectAgent()
			f.srv.cfg.Executions = grpcserver.NewExecutionSessions(f.terminals, f.connMgr)
			f.srv.cfg.Executions.SetCapabilities(testServerID, f.agent, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "bridge-boot"})
			f.start()
			client := f.mustDial(testUsername + "+" + testServerName)
			var sql string
			switch phase {
			case "identity":
				sql = "DELETE FROM security_identity_links WHERE user_id='" + testUserID + "'"
			case "metadata":
				sql = "CREATE TRIGGER execution_test_fault BEFORE INSERT ON executions BEGIN SELECT RAISE(FAIL,'local metadata unavailable'); END"
			case "deleted-user":
				sql = "DELETE FROM users WHERE id='" + testUserID + "'"
			case "deleted-node":
				sql = "DELETE FROM servers WHERE id='" + testServerID + "'"
			case "lost-grant":
				sql = "UPDATE users SET role='viewer' WHERE id='" + testUserID + "'"
			case "capacity":
				for n := 0; n < 8; n++ {
					id := fmt.Sprintf("occupied-%d", n)
					if _, ok := f.terminals.Register(testServerID, id, testUserID, ""); !ok {
						t.Fatal("capacity fixture could not reserve its sessions")
					}
					t.Cleanup(func() { f.terminals.Remove(testServerID, id) })
				}
			}
			if sql != "" {
				if _, err := f.store.DB().Exec(sql); err != nil {
					t.Fatal(err)
				}
			}
			before := len(f.terminals.ListByUser(testUserID))
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			var stderr bytes.Buffer
			session.Stderr = &stderr
			result := make(chan error, 1)
			go func() { result <- session.Run("CANARY_PRIVATE_COMMAND") }()
			select {
			case err := <-result:
				var exit *ssh.ExitError
				if !errors.As(err, &exit) || exit.ExitStatus() != int(exitRefused) || stderr.Len() == 0 {
					t.Fatalf("submission failure lacked visible refusal: %v %q", err, stderr.String())
				}
			case <-time.After(waitTimeout):
				t.Fatal("SSH storage/capacity refusal stalled")
			}
			if len(f.terminals.ListByUser(testUserID)) != before || len(f.agent.messages()) != 0 {
				t.Fatal("refused submission prepared or retained a new session")
			}
			var count int
			if err := f.store.DB().QueryRow("SELECT COUNT(*) FROM executions").Scan(&count); err != nil || count != 0 {
				t.Fatalf("refused submission recorded a launchable execution: %d %v", count, err)
			}
		})
	}
}
