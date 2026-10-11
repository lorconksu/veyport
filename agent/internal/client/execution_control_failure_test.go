package client

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/execution"
	"github.com/wyiu/veyport/agent/internal/executionidentity"
	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func TestExecutionTransportInitializationFailsClosedBeforeControlWorkers(t *testing.T) {
	_, enrolled := executionTestTLS(t)
	for _, fault := range []string{"unenrolled", "journal-not-directory", "spool-not-directory", "missing-node"} {
		t.Run(fault, func(t *testing.T) {
			t.Setenv("VEYPORT_EXECUTION_SPOOL_DIR", "")
			c := New(Config{HubAddr: "127.0.0.1:1", ServerID: "node", CertDir: t.TempDir(), DropzoneDir: t.TempDir()})
			if fault != "unenrolled" {
				c.certStore = enrolled
			}
			switch fault {
			case "journal-not-directory":
				if err := os.WriteFile(filepath.Join(c.certDir, "execution-journal"), []byte("not a journal directory"), 0600); err != nil {
					t.Fatal(err)
				}
			case "spool-not-directory":
				path := filepath.Join(t.TempDir(), "invalid-spool")
				if err := os.WriteFile(path, []byte("not an encrypted spool directory"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("VEYPORT_EXECUTION_SPOOL_DIR", path)
			case "missing-node":
				c.serverID = ""
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			control := make(chan *pb.AgentMessage, 1)
			transport, err := c.newExecutionTransport(ctx, sessionlimit.New(8), control, cancel)
			if err == nil || transport != nil {
				if transport != nil {
					transport.close()
				}
				t.Fatal("invalid protected transport configuration activated workers")
			}
			if len(control) != 0 || ctx.Err() != nil {
				t.Fatal("failed execution initialization changed ordinary control")
			}
		})
	}
}

func TestExecutionStandardTransportDoesNotRequireEncryptedSpool(t *testing.T) {
	_, enrolled := executionTestTLS(t)
	t.Setenv("VEYPORT_EXECUTION_SPOOL_DIR", "")
	c := New(Config{HubAddr: "127.0.0.1:1", ServerID: "node", CertDir: t.TempDir(), DropzoneDir: t.TempDir()})
	c.certStore = enrolled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e, err := c.newExecutionTransport(ctx, sessionlimit.New(8), make(chan *pb.AgentMessage, 1), cancel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.close)
	if e.manager.Capabilities().ProtectedScript {
		t.Fatal("Standard setup advertised unavailable encrypted script storage")
	}
	p := e.manager.Prepare(&pb.ExecutionPrepare{ExecutionId: "standard-independent", NodeId: "node", Command: "exit 42"})
	if p.Error != "" || p.Binding == nil {
		t.Fatalf("Standard setup required optional encrypted storage: %+v", p)
	}
	e.close()
	if got := e.manager.Status(p.ExecutionId); got.State != "not_found" {
		t.Fatalf("closing Standard transport retained unclaimed preparation: %+v", got)
	}
}

func TestExecutionPreparationSaturationKeepsStatusAndCancelAvailable(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	releaseResolve := sync.OnceFunc(func() { close(release) })
	j, err := execution.OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m, err := execution.NewManager(execution.Config{NodeID: "node", Journal: j, Resolve: func(runAs, cwd string) (*executionidentity.Identity, error) {
		if runAs == "held-fixture" {
			close(entered)
			<-release
			return nil, errors.New("synthetic identity lookup failure")
		}
		return executionidentity.Resolve(runAs, cwd)
	}})
	if err != nil {
		t.Fatal(err)
	}
	p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "existing-preparation", NodeId: "node", Command: "exit 42"})
	if p.Error != "" {
		t.Fatal(p.Error)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &executionTransport{ctx: ctx, cancel: cancel, manager: m, workers: make(chan struct{}, 1), responses: make(chan *pb.AgentMessage, 8)}
	t.Cleanup(func() { releaseResolve(); e.wg.Wait(); m.Close() })
	if !e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionPrepare{ExecutionPrepare: &pb.ExecutionPrepare{ExecutionId: "held", NodeId: "node", RunAsUser: "held-fixture", Command: "exit 0"}}}) {
		t.Fatal("held preparation escaped handler")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual preparation worker did not enter identity lookup")
	}
	if !e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionPrepare{ExecutionPrepare: &pb.ExecutionPrepare{ExecutionId: "overflow", NodeId: "node", Command: "exit 0"}}}) {
		t.Fatal("execution request escaped handler")
	}
	rejected := (<-e.responses).GetExecutionPrepared()
	if rejected == nil || rejected.ExecutionId != "overflow" || rejected.Error == "" || m.Status("overflow").State != "not_found" {
		t.Fatal("preparation overload accepted or claimed command")
	}
	if !e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionPrepare{}}) || (<-e.responses).GetExecutionPrepared().Error == "" {
		t.Fatal("saturated missing preparation was not rejected")
	}
	if !e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionStatusRequest{ExecutionStatusRequest: &pb.ExecutionStatusRequest{ExecutionId: p.ExecutionId}}}) {
		t.Fatal("status request escaped handler")
	}
	if got := (<-e.responses).GetExecutionStatus(); got == nil || got.State != "prepared" {
		t.Fatalf("preparation overload blocked status: %+v", got)
	}
	if !e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionCancel{ExecutionCancel: &pb.ExecutionCancel{Binding: p.Binding}}}) {
		t.Fatal("cancel request escaped handler")
	}
	if got := (<-e.responses).GetExecutionStatus(); got == nil || got.State != "not_found" {
		t.Fatalf("preparation overload blocked cancellation: %+v", got)
	}
	if ctx.Err() != nil {
		t.Fatal("bounded preparation rejection disconnected healthy control")
	}
	releaseResolve()
	e.wg.Wait()
	if got := (<-e.responses).GetExecutionPrepared(); got == nil || got.ExecutionId != "held" || got.Error == "" || m.Status("held").State != "not_found" {
		t.Fatal("released failed lookup created a preparation or lost its response")
	}
}

func TestExecutionControlRejectsForeignAttachmentAndIgnoresAbsentPayloads(t *testing.T) {
	m := outcomeFailureManager(t)
	p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "owned-preparation", NodeId: "node", Command: "exit 42"})
	if p.Error != "" {
		t.Fatal(p.Error)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &executionTransport{ctx: ctx, cancel: cancel, manager: m, workers: make(chan struct{}, 1), responses: make(chan *pb.AgentMessage, 8)}
	for _, attach := range []*pb.ExecutionAttachRequest{nil, {}, {Binding: p.Binding, Ticket: make([]byte, 31)}, {Binding: p.Binding, Ticket: make([]byte, 257)}} {
		if !e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionAttach{ExecutionAttach: attach}}) {
			t.Fatal("invalid attachment escaped handler")
		}
	}
	wrong := proto.Clone(p.Binding).(*pb.ExecutionBinding)
	wrong.NodeId = "another-node"
	if !e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ExecutionAttach{ExecutionAttach: &pb.ExecutionAttachRequest{Binding: wrong, Ticket: bytes.Repeat([]byte{1}, 32)}}}) {
		t.Fatal("foreign attachment escaped handler")
	}
	if got := (<-e.responses).GetExecutionStatus(); got == nil || got.State != "prepared" || !proto.Equal(got.Binding, p.Binding) {
		t.Fatalf("foreign attachment changed ownership: %+v", got)
	}
	for _, msg := range []*pb.HubMessage{{Payload: &pb.HubMessage_ExecutionCancel{}}, {Payload: &pb.HubMessage_ExecutionCancel{ExecutionCancel: &pb.ExecutionCancel{}}}, {Payload: &pb.HubMessage_ExecutionStatusRequest{}}} {
		if !e.handle(msg) {
			t.Fatal("absent execution payload escaped handler")
		}
	}
	if len(e.responses) != 0 || m.Status(p.ExecutionId).State != "prepared" || ctx.Err() != nil {
		t.Fatal("invalid control frame damaged another preparation")
	}
	if e.handle(&pb.HubMessage{Payload: &pb.HubMessage_HeartbeatAck{HeartbeatAck: &pb.HeartbeatAck{}}}) {
		t.Fatal("execution handler consumed ordinary control frame")
	}
}
