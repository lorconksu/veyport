package sshgw

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/crypto/ssh"
)

func newExecutionResponseFixture(t *testing.T, phase string, mutate func(*Config)) (*fixture, *failingExecBridgeAgent) {
	t.Helper()
	f := newFixture(t, mutate)
	executions := grpcserver.NewExecutionSessions(f.terminals, f.connMgr)
	f.srv.cfg.Executions = executions
	a := &failingExecBridgeAgent{stubAgent: f.agent, executions: executions, phase: phase, fixture: f}
	f.connMgr.Register(testServerID, a)
	executions.SetCapabilities(testServerID, a, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "bridge-boot"})
	gs := grpcserver.New(grpcserver.Config{Store: f.store, ConnMgr: f.connMgr, TerminalSessions: f.terminals, ExecutionSessions: executions})
	a.handler = gs.Handler()
	t.Cleanup(gs.Stop)
	t.Cleanup(a.closeStream)
	f.start()
	return f, a
}

func executionResponseStream(t *testing.T, a *failingExecBridgeAgent) *failingExecBridgeStream {
	t.Helper()
	var stream *failingExecBridgeStream
	waitFor(t, "execution Start attempt", func() bool {
		a.mu.Lock()
		stream = a.stream
		a.mu.Unlock()
		return stream != nil && stream.starts.Load() == 1
	})
	t.Cleanup(func() { a.closeStream(); waitForDone(t, stream.done, "execution RPC cleanup") })
	return stream
}

// The SSH listener, execution registry and RPC handler are real. The agent
// injects failures without launching a process or requiring owner credentials.
func TestSSHExecutionFailuresDeliverDiagnosticAndExitStatus(t *testing.T) {
	for _, fault := range []struct {
		phase, reason, state string
	}{
		{"prepare-send", "prepare transport unavailable", "admission_failed"},
		{"invalid-binding", "invalid execution preparation binding", "admission_failed"},
		{"malformed-preparation", "invalid prepared execution identity", "admission_failed"},
		{"attach-send", "attach transport unavailable", "admission_failed"},
		{"attach-disconnect", "execution transport lost", "admission_failed"},
		{"start-send", "execution transport lost", "outcome_unknown"},
	} {
		t.Run(fault.phase, func(t *testing.T) {
			f, a := newExecutionResponseFixture(t, fault.phase, func(c *Config) { c.ExecutionConsumerTimeout = 40 * time.Millisecond })
			client := f.mustDial(testUsername + "+" + testServerName)
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = session.Close() })
			var stderr bytes.Buffer
			session.Stderr = &stderr
			finished := make(chan error, 1)
			go func() { finished <- session.Run("hostname; id; uname -s") }()
			select {
			case err := <-finished:
				var exit *ssh.ExitError
				if !errors.As(err, &exit) || exit.ExitStatus() != int(exitAborted) {
					t.Fatalf("execution failure did not deliver exit %d: %v", exitAborted, err)
				}
				if !strings.Contains(stderr.String(), fault.reason) {
					t.Fatalf("execution failure did not explain %q: %q", fault.reason, stderr.String())
				}
			case <-time.After(waitTimeout):
				t.Fatal("failed execution did not finish over SSH")
			}
			prepare := a.waitForMessage(t, "execution preparation", func(msg *pb.HubMessage) bool { return msg.GetExecutionPrepare() != nil }).GetExecutionPrepare()
			got, err := f.store.GetExecution(prepare.ExecutionId)
			if err != nil || got.State != fault.state || got.FinishedAt == nil || got.ExitCode != nil || got.Reason != fault.reason {
				t.Fatalf("failed execution lost its durable outcome: %+v %v", got, err)
			}
			waitFor(t, "failed execution capacity release", func() bool { return len(f.terminals.ListByUser(testUserID)) == 0 })
			f.waitForAudit(model.AuditExecutionFinished)
			a.mu.Lock()
			stream := a.stream
			a.mu.Unlock()
			if stream != nil {
				a.closeStream()
				waitForDone(t, stream.done, "failed execution RPC cleanup")
			}
			// Finalization must stop its watchdog; a later session on this
			// healthy SSH connection remains usable beyond that deadline.
			<-time.After(80 * time.Millisecond)
			followup, err := client.NewSession()
			if err != nil {
				t.Fatalf("completed failure left a transport-close watchdog running: %v", err)
			}
			_ = followup.Close()
		})
	}
}

func TestSSHExecutionRevocationReportsFailureWithOpenStdin(t *testing.T) {
	f, a := newExecutionResponseFixture(t, "revocation", nil)
	client := f.mustDial(testUsername + "+" + testServerName)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	input, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close() })
	var stderr bytes.Buffer
	session.Stderr = &stderr
	finished := make(chan error, 1)
	go func() { finished <- session.Run("synthetic command") }()
	executionResponseStream(t, a)
	prepare := a.waitForMessage(t, "execution preparation", func(msg *pb.HubMessage) bool { return msg.GetExecutionPrepare() != nil }).GetExecutionPrepare()
	if !f.terminals.EndOne(testServerID, prepare.ExecutionId, 1, "operator revoked command access") {
		t.Fatal("execution was not live for revocation")
	}
	select {
	case err := <-finished:
		var exit *ssh.ExitError
		if !errors.As(err, &exit) || exit.ExitStatus() != int(exitAborted) || !strings.Contains(stderr.String(), "execution access revoked") {
			t.Fatalf("revoked execution lacked diagnostic or failure status: %v %q", err, stderr.String())
		}
	case <-time.After(waitTimeout):
		t.Fatal("revocation left the SSH execution blocked on stdin")
	}
	a.waitForMessage(t, "prepared execution cancellation", func(msg *pb.HubMessage) bool { return msg.GetExecutionCancel() != nil })
	waitFor(t, "revoked execution capacity release", func() bool { return len(f.terminals.ListByUser(testUserID)) == 0 })
	got, err := f.store.GetExecution(prepare.ExecutionId)
	if err != nil || got.State != "cancelled" || got.ExitCode != nil || got.FinishedAt == nil {
		t.Fatalf("revocation fabricated a process outcome: %+v %v", got, err)
	}
}

func TestSSHExecutionCompletionDrainsBinaryOutputBeforeDiagnostic(t *testing.T) {
	f, a := newExecutionResponseFixture(t, "completion", nil)
	client := f.mustDial(testUsername + "+" + testServerName)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	var stdout, stderr bytes.Buffer
	session.Stdout, session.Stderr = &stdout, &stderr
	finished := make(chan error, 1)
	go func() { finished <- session.Run("synthetic completion") }()
	stream := executionResponseStream(t, a)
	attach := a.waitForMessage(t, "execution attachment", func(msg *pb.HubMessage) bool { return msg.GetExecutionAttach() != nil }).GetExecutionAttach()
	output := []byte{'o', 0, 255, '\n'}
	errorOutput := []byte{'e', 0, 254, '\n'}
	for _, msg := range []*pb.ExecutionAgentMessage{
		{Payload: &pb.ExecutionAgentMessage_Stdout{Stdout: &pb.ExecutionData{Sequence: 0, Data: output}}},
		{Payload: &pb.ExecutionAgentMessage_Stderr{Stderr: &pb.ExecutionData{Sequence: 0, Data: errorOutput}}},
		{Payload: &pb.ExecutionAgentMessage_OutputEof{OutputEof: &pb.ExecutionOutputEOF{Output: pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT, Sequence: 1}}},
		{Payload: &pb.ExecutionAgentMessage_OutputEof{OutputEof: &pb.ExecutionOutputEOF{Output: pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR, Sequence: 1}}},
		{Payload: &pb.ExecutionAgentMessage_Result{Result: &pb.ExecutionResult{Binding: attach.Binding, State: "exited", ExitCode: 7, StdoutComplete: true, StderrComplete: true, Reason: "completion not durable"}}},
	} {
		select {
		case stream.incoming <- msg:
		case <-stream.ctx.Done():
			t.Fatal("execution transport ended before synthetic completion")
		case <-time.After(waitTimeout):
			t.Fatal("synthetic completion send stalled")
		}
	}
	select {
	case err := <-finished:
		var exit *ssh.ExitError
		if !errors.As(err, &exit) || exit.ExitStatus() != 7 {
			t.Fatalf("remote exit status changed during finalization: %v", err)
		}
		if !bytes.Equal(stdout.Bytes(), output) || !bytes.Equal(stderr.Bytes(), append(errorOutput, []byte("veyport: completion metadata unconfirmed\r\n")...)) {
			t.Fatalf("finalization lost or interleaved binary output/diagnostic: stdout=%q stderr=%q", stdout.Bytes(), stderr.Bytes())
		}
	case <-time.After(waitTimeout):
		t.Fatal("completed execution failed to finish over SSH")
	}
	waitFor(t, "completed execution capacity release", func() bool { return len(f.terminals.ListByUser(testUserID)) == 0 })
	got, err := f.store.GetExecution(attach.Binding.ExecutionId)
	if err != nil || got.State != "exited" || got.ExitCode == nil || *got.ExitCode != 7 || got.FinishedAt == nil || got.Reason != "completion metadata unconfirmed" {
		t.Fatalf("completion lost its observed process exit: %+v %v", got, err)
	}
}

func TestSSHExecutionStalledOutputConsumerReleasesRelays(t *testing.T) {
	for _, output := range []string{"stdout", "stderr"} {
		t.Run(output, func(t *testing.T) {
			f, a := newExecutionResponseFixture(t, "stalled", func(c *Config) { c.ExecutionConsumerTimeout = 40 * time.Millisecond })
			client := f.mustDial(testUsername + "+" + testServerName)
			ch := openRawSession(t, client)
			if !sendChannelRequest(t, ch, reqExec, ssh.Marshal(struct{ Command string }{"synthetic output"})) {
				t.Fatal("execution submission refused")
			}
			stream := executionResponseStream(t, a)
			fed := make(chan struct{})
			go func() {
				defer close(fed)
				for seq := uint64(0); seq < 64; seq++ {
					frame := &pb.ExecutionData{Sequence: seq, Data: bytes.Repeat([]byte("x"), grpcserver.MaxExecutionFrameBytes)}
					msg := &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Stdout{Stdout: frame}}
					if output == "stderr" {
						msg.Payload = &pb.ExecutionAgentMessage_Stderr{Stderr: frame}
					}
					select {
					case stream.incoming <- msg:
					case <-stream.ctx.Done():
						return
					}
				}
			}()
			t.Cleanup(func() { a.closeStream(); waitForDone(t, fed, "synthetic output producer cleanup") })
			a.waitForMessage(t, "stalled execution cancellation", func(msg *pb.HubMessage) bool { return msg.GetExecutionCancel() != nil })
			waitFor(t, "stalled execution capacity release", func() bool { return len(f.terminals.ListByUser(testUserID)) == 0 })
			prepare := a.waitForMessage(t, "execution preparation", func(msg *pb.HubMessage) bool { return msg.GetExecutionPrepare() != nil }).GetExecutionPrepare()
			got, err := f.store.GetExecution(prepare.ExecutionId)
			if err != nil || got.Reason != "SSH output consumer stalled" || got.State != "cancelled" || got.ExitCode != nil || got.FinishedAt == nil {
				t.Fatalf("stalled consumer did not retain cancellation evidence: %+v %v", got, err)
			}
			waitForDone(t, fed, "synthetic output producer cleanup")
		})
	}
}

type blockedExecutionConn struct {
	net.Conn
	blockWrites atomic.Bool
	closed      chan struct{}
	closeOnce   sync.Once
}

func (c *blockedExecutionConn) Write(data []byte) (int, error) {
	if c.blockWrites.Load() {
		<-c.closed
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(data)
}

func (c *blockedExecutionConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type blockedExecutionListener struct {
	net.Listener
	accepted chan *blockedExecutionConn
}

func (l *blockedExecutionListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	blocked := &blockedExecutionConn{Conn: conn, closed: make(chan struct{})}
	l.accepted <- blocked
	return blocked, nil
}

func TestSSHExecutionRevocationClosesStalledTransportAfterCancellingAgent(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	blockedListener := &blockedExecutionListener{Listener: listener, accepted: make(chan *blockedExecutionConn, 1)}
	f, a := newExecutionResponseFixture(t, "stalled-transport", func(c *Config) {
		c.ExecutionConsumerTimeout = 100 * time.Millisecond
		c.Listener = blockedListener
	})
	client := f.mustDial(testUsername + "+" + testServerName)
	conn := <-blockedListener.accepted
	ch := openRawSession(t, client)
	if !sendChannelRequest(t, ch, reqExec, ssh.Marshal(struct{ Command string }{"synthetic command"})) {
		t.Fatal("execution submission refused")
	}
	executionResponseStream(t, a)
	prepare := a.waitForMessage(t, "execution preparation", func(msg *pb.HubMessage) bool { return msg.GetExecutionPrepare() != nil }).GetExecutionPrepare()
	conn.blockWrites.Store(true)
	if !f.terminals.EndOne(testServerID, prepare.ExecutionId, 1, "operator revoked command access") {
		t.Fatal("execution was not live for revocation")
	}
	a.waitForMessage(t, "prepared execution cancellation", func(msg *pb.HubMessage) bool { return msg.GetExecutionCancel() != nil })
	select {
	case <-conn.closed:
	case <-time.After(waitTimeout):
		t.Fatal("finalization left a stalled SSH write or close unbounded")
	}
	waitFor(t, "stalled transport execution capacity release", func() bool { return len(f.terminals.ListByUser(testUserID)) == 0 })
	got, err := f.store.GetExecution(prepare.ExecutionId)
	if err != nil || got.State != "cancelled" || got.ExitCode != nil || got.FinishedAt == nil || got.Reason != "execution access revoked" {
		t.Fatalf("stalled transport lost revocation evidence: %+v %v", got, err)
	}
}
