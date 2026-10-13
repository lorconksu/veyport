package client

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wyiu/veyport/agent/internal/execution"
	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	"github.com/wyiu/veyport/proto/protectedinput"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"
)

// The execution connection is separate from control/heartbeats and cannot use
// bootstrap TLS or the --insecure transport. One goroutine sends on each RPC.
func (c *Client) dialExecutionHub() (*grpc.ClientConn, error) {
	tlsCfg := c.certStore.TLSConfig()
	if tlsCfg == nil {
		return nil, fmt.Errorf("execution requires an enrolled mTLS certificate")
	}
	return grpc.NewClient(c.hubAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(256*1024), grpc.MaxCallSendMsgSize(256*1024)), grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}))
}

type executionTransport struct {
	gate          sync.Mutex
	closed        bool
	ctx           context.Context
	cancel        context.CancelFunc
	manager       *execution.Manager
	conn          *grpc.ClientConn
	client        pb.AgentServiceClient
	sendCh        chan<- *pb.AgentMessage
	responses     chan *pb.AgentMessage
	controlCancel context.CancelFunc
	workers       chan struct{}
	wg            sync.WaitGroup
}

func (c *Client) newExecutionTransport(ctx context.Context, budget *sessionlimit.Budget, sendCh chan<- *pb.AgentMessage, controlCancel context.CancelFunc) (*executionTransport, error) {
	conn, err := c.dialExecutionHub()
	if err != nil {
		return nil, err
	}
	journal, err := execution.OpenJournal(filepath.Join(c.certDir, "execution-journal"))
	if err != nil {
		conn.Close()
		return nil, err
	}
	spool := c.executionSpool
	if path := os.Getenv("VEYPORT_EXECUTION_SPOOL_DIR"); path != "" {
		storage, storageErr := protectedinput.New(path)
		if storageErr != nil {
			conn.Close()
			return nil, storageErr
		}
		spool = storage
	}
	manager, err := execution.NewManager(execution.Config{NodeID: c.serverID, Journal: journal, Budget: budget, Spool: spool})
	if err != nil {
		conn.Close()
		return nil, err
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	e := &executionTransport{ctx: sessionCtx, cancel: cancel, manager: manager, conn: conn, client: pb.NewAgentServiceClient(conn), sendCh: sendCh, workers: make(chan struct{}, 8), responses: make(chan *pb.AgentMessage, 16), controlCancel: controlCancel}
	e.wg.Add(1)
	go e.deliverControl()
	return e, nil
}
func (e *executionTransport) close() {
	e.cancel()
	e.gate.Lock()
	e.closed = true
	e.gate.Unlock()
	if e.conn != nil {
		_ = e.conn.Close()
	}
	e.manager.Close()
	e.wg.Wait()
}
func (e *executionTransport) deliverControl() {
	defer e.wg.Done()
	for {
		select {
		case msg := <-e.responses:
			select {
			case e.sendCh <- msg:
			case <-e.ctx.Done():
				return
			}
		case <-e.ctx.Done():
			return
		}
	}
}
func (e *executionTransport) send(msg *pb.AgentMessage) {
	select {
	case e.responses <- msg:
	case <-e.ctx.Done():
	default:
		// Control overload is explicit transport failure. It cannot leave a receive
		// loop blocked on a status reply and unable to honor subsequent cancellation.
		e.cancel()
		if e.controlCancel != nil {
			e.controlCancel()
		}
	}
}
func (e *executionTransport) status(id string) {
	e.send(&pb.AgentMessage{Payload: &pb.AgentMessage_ExecutionStatus{ExecutionStatus: e.manager.Status(id)}})
}
func (e *executionTransport) handle(msg *pb.HubMessage) bool {
	e.gate.Lock()
	defer e.gate.Unlock()
	if e.closed {
		return true
	}
	switch p := msg.Payload.(type) {
	case *pb.HubMessage_ExecutionPrepare:
		select {
		case e.workers <- struct{}{}:
			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				defer func() { <-e.workers }()
				prepared := e.manager.Prepare(p.ExecutionPrepare)
				e.send(&pb.AgentMessage{Payload: &pb.AgentMessage_ExecutionPrepared{ExecutionPrepared: prepared}})
			}()
		default:
			id := ""
			if p.ExecutionPrepare != nil {
				id = p.ExecutionPrepare.ExecutionId
			}
			e.send(&pb.AgentMessage{Payload: &pb.AgentMessage_ExecutionPrepared{ExecutionPrepared: &pb.ExecutionPrepared{ExecutionId: id, Error: "too many concurrent execution preparations"}}})
		}
		return true
	case *pb.HubMessage_ExecutionAttach:
		attach := p.ExecutionAttach
		if attach == nil || attach.Binding == nil || len(attach.Ticket) < 32 || len(attach.Ticket) > 256 {
			return true
		}
		if err := e.manager.Attach(attach.Binding); err != nil {
			e.status(attach.Binding.ExecutionId)
			return true
		}
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := e.serve(attach); err != nil {
				_ = e.manager.Cancel(&pb.ExecutionCancel{Binding: attach.Binding, Reason: "execution_transport_lost"})
				e.status(attach.Binding.ExecutionId)
			}
		}()
		return true
	case *pb.HubMessage_ExecutionCancel:
		if p.ExecutionCancel != nil {
			_ = e.manager.Cancel(p.ExecutionCancel)
			if p.ExecutionCancel.Binding != nil {
				e.status(p.ExecutionCancel.Binding.ExecutionId)
			}
		}
		return true
	case *pb.HubMessage_ExecutionStatusRequest:
		if p.ExecutionStatusRequest != nil {
			e.status(p.ExecutionStatusRequest.ExecutionId)
		}
		return true
	default:
		return false
	}
}
func (e *executionTransport) serve(attach *pb.ExecutionAttachRequest) error {
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	deadline := time.Until(time.UnixMilli(attach.Binding.ExpiresUnixMilli))
	if deadline <= 0 {
		return fmt.Errorf("execution attachment expired")
	}
	preparationTimer := time.AfterFunc(deadline, cancel)
	defer preparationTimer.Stop()
	stream, err := e.client.Execute(ctx)
	if err != nil {
		return err
	}
	send := func(msg *pb.ExecutionAgentMessage) error {
		return sendExecutionMessage(stream, cancel, msg, time.Minute)
	}
	if err = send(&pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Attach{Attach: attach}}); err != nil {
		return err
	}
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	if msg.GetAttached() == nil || !proto.Equal(msg.GetAttached().Binding, attach.Binding) {
		return fmt.Errorf("execution attachment binding mismatch")
	}
	var start *pb.ExecutionStart
	for start == nil {
		msg, err = stream.Recv()
		if err != nil {
			return err
		}
		switch payload := msg.Payload.(type) {
		case *pb.ExecutionHubMessage_ScriptChunk:
			err = e.manager.ScriptChunk(attach.Binding, payload.ScriptChunk)
		case *pb.ExecutionHubMessage_ScriptEof:
			err = e.manager.ScriptEOF(attach.Binding, payload.ScriptEof)
		case *pb.ExecutionHubMessage_Start:
			start = payload.Start
		default:
			err = fmt.Errorf("unexpected prelaunch execution message")
		}
		if err != nil {
			return err
		}
	}
	if start == nil || !proto.Equal(start.Binding, attach.Binding) {
		return fmt.Errorf("execution start required")
	}
	run, err := e.manager.Start(ctx, start)
	if err != nil {
		status := e.manager.Status(attach.Binding.ExecutionId)
		state := status.State
		if state == "not_found" || state == "prepared" {
			state = "launch_failed"
		}
		_ = send(&pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_StartFailed{StartFailed: &pb.ExecutionStartFailed{Binding: attach.Binding, State: state, Reason: err.Error()}}})
		_ = stream.CloseSend()
		return err
	}
	preparationTimer.Stop()
	defer func() { cancel(); run.Cancel("execution_transport_lost"); <-run.Done() }()
	recvErr := make(chan error, 1)
	go func() {
		err := receiveExecutionInput(stream, run, attach.Binding)
		if err != nil {
			run.Cancel("execution_transport_lost")
		}
		recvErr <- err
	}()
	resultSent := false
	for msg := range run.Messages() {
		if err = send(msg); err != nil {
			return err
		}
		if msg.GetResult() != nil {
			resultSent = true
		}
	}
	if !resultSent {
		return fmt.Errorf("execution completed without final result")
	}
	if err = stream.CloseSend(); err != nil {
		return err
	}
	// Hub EOF acknowledges its consumption of the final result. Cancelling the
	// RPC immediately after Send could discard gRPC's still-buffered final bytes.
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	select {
	case err = <-recvErr:
		if err == io.EOF {
			return nil
		}
		return err
	case <-timer.C:
		return fmt.Errorf("execution result delivery unconfirmed")
	case <-e.ctx.Done():
		return e.ctx.Err()
	}
}
func sendExecutionMessage(stream pb.AgentService_ExecuteClient, cancel context.CancelFunc, msg *pb.ExecutionAgentMessage, timeout time.Duration) error {
	timer := time.AfterFunc(timeout, cancel)
	defer timer.Stop()
	return stream.Send(msg)
}
func receiveExecutionInput(stream pb.AgentService_ExecuteClient, run *execution.Run, binding *pb.ExecutionBinding) error {
	invalid := false
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		if invalid {
			continue
		}
		switch p := msg.Payload.(type) {
		case *pb.ExecutionHubMessage_Input:
			err = run.Input(p.Input)
		case *pb.ExecutionHubMessage_InputEof:
			err = run.InputEOF(p.InputEof)
		case *pb.ExecutionHubMessage_Cancel:
			if p.Cancel == nil || !proto.Equal(p.Cancel.Binding, binding) {
				return fmt.Errorf("execution cancellation binding mismatch")
			}
			run.Cancel(p.Cancel.Reason)
		default:
			err = fmt.Errorf("unexpected execution input message")
		}
		if err != nil {
			invalid = true
			run.Cancel("invalid_execution_input")
		}
	}
}
