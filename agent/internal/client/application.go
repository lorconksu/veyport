package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	"github.com/wyiu/veyport/proto/applicationproxy"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"
)

const maxApplicationSockets = 32

type applicationTransport struct {
	mu             sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
	controlCancel  context.CancelFunc
	nodeID, bootID string
	budget         *sessionlimit.Budget
	conn           *grpc.ClientConn
	client         pb.AgentServiceClient
	send           chan<- *pb.AgentMessage
	sessions       map[string]*applicationSocket
	closed         bool
	wg             sync.WaitGroup
	dial           applicationproxy.Dialer
}
type applicationSocket struct {
	binding *pb.ApplicationBinding
	cancel  context.CancelFunc
}

func (c *Client) newApplicationTransport(ctx context.Context, budget *sessionlimit.Budget, send chan<- *pb.AgentMessage, controlCancel context.CancelFunc) (*applicationTransport, error) {
	if c.certStore == nil {
		return nil, errors.New("application transport requires enrolled certificate")
	}
	tlsCfg := c.certStore.TLSConfig()
	if tlsCfg == nil {
		return nil, errors.New("application transport requires enrolled certificate")
	}
	conn, err := grpc.NewClient(c.hubAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(256*1024), grpc.MaxCallSendMsgSize(256*1024)), grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}))
	if err != nil {
		return nil, err
	}
	child, cancel := context.WithCancel(ctx)
	var bootBytes [16]byte
	if _, err := rand.Read(bootBytes[:]); err != nil {
		conn.Close()
		cancel()
		return nil, err
	}
	boot := hex.EncodeToString(bootBytes[:])
	if raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		if value := strings.TrimSpace(string(raw)); len(value) >= 16 && len(value) <= 128 {
			boot = value
		}
	}
	dial := applicationproxy.Dialer{ForbiddenAuthorities: []string{c.hubAddr}}
	if hubHost, _, err := net.SplitHostPort(c.hubAddr); err == nil {
		dial.ForbiddenAuthorities = append(dial.ForbiddenAuthorities, net.JoinHostPort(hubHost, "8081"), net.JoinHostPort(hubHost, "2222"), net.JoinHostPort(hubHost, "443"), net.JoinHostPort(hubHost, "80"))
	}
	return &applicationTransport{ctx: child, cancel: cancel, controlCancel: controlCancel, nodeID: c.serverID, bootID: boot, budget: budget, conn: conn, client: pb.NewAgentServiceClient(conn), send: send, sessions: make(map[string]*applicationSocket), dial: dial}, nil
}
func (e *applicationTransport) capabilities() *pb.ApplicationCapabilities {
	return &pb.ApplicationCapabilities{ProtocolVersion: 1, RawTcp: true, BootId: e.bootID}
}
func (e *applicationTransport) close() {
	e.cancel()
	e.mu.Lock()
	e.closed = true
	for _, s := range e.sessions {
		s.cancel()
	}
	e.mu.Unlock()
	if e.conn != nil {
		e.conn.Close()
	}
	e.wg.Wait()
}
func (e *applicationTransport) emitClosed(binding *pb.ApplicationBinding, reason string) {
	if binding == nil {
		return
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case e.send <- &pb.AgentMessage{Payload: &pb.AgentMessage_ApplicationClosed{ApplicationClosed: &pb.ApplicationClosed{Binding: proto.Clone(binding).(*pb.ApplicationBinding), ReasonCode: reason}}}:
	case <-e.ctx.Done():
	case <-timer.C:
		if e.controlCancel != nil {
			e.controlCancel()
		}
	}
}
func (e *applicationTransport) handle(message *pb.HubMessage) bool {
	switch p := message.Payload.(type) {
	case *pb.HubMessage_ApplicationClose:
		if p.ApplicationClose == nil || p.ApplicationClose.Binding == nil {
			return true
		}
		e.mu.Lock()
		s := e.sessions[p.ApplicationClose.Binding.ConnectionId]
		if s != nil && proto.Equal(s.binding, p.ApplicationClose.Binding) {
			s.cancel()
		}
		e.mu.Unlock()
		return true
	case *pb.HubMessage_ApplicationOpen:
		e.open(p.ApplicationOpen)
		return true
	default:
		return false
	}
}
func (e *applicationTransport) open(open *pb.ApplicationOpen) {
	if open == nil || open.Binding == nil {
		return
	}
	// An expired or malformed retry still cannot acknowledge completion of an
	// existing socket with this connection ID.
	e.mu.Lock()
	duplicate := e.sessions[open.Binding.ConnectionId] != nil
	e.mu.Unlock()
	if duplicate {
		return
	}
	if !e.validOpen(open) {
		e.emitClosed(open.Binding, "invalid_admission")
		return
	}
	e.mu.Lock()
	if e.closed || e.ctx.Err() != nil {
		e.mu.Unlock()
		return
	}
	if e.sessions[open.Binding.ConnectionId] != nil {
		e.mu.Unlock()
		return
	}
	if len(e.sessions) >= maxApplicationSockets {
		e.mu.Unlock()
		e.emitClosed(open.Binding, "capacity")
		return
	}
	release, ok := e.budget.AcquireActivity()
	if !ok {
		e.mu.Unlock()
		e.emitClosed(open.Binding, "maintenance")
		return
	}
	ctx, cancel := context.WithCancel(e.ctx)
	s := &applicationSocket{binding: proto.Clone(open.Binding).(*pb.ApplicationBinding), cancel: cancel}
	e.sessions[s.binding.ConnectionId] = s
	e.wg.Add(1)
	e.mu.Unlock()
	copyOpen := proto.Clone(open).(*pb.ApplicationOpen)
	go func() {
		defer e.wg.Done()
		reason := e.serve(ctx, cancel, copyOpen)
		cancel()
		e.mu.Lock()
		delete(e.sessions, s.binding.ConnectionId)
		e.mu.Unlock()
		release()
		e.emitClosed(s.binding, reason)
	}()
}
func (e *applicationTransport) validOpen(open *pb.ApplicationOpen) bool {
	b := open.Binding
	if b.NodeId != e.nodeID || b.BootId != e.bootID || b.ConnectionId == "" || len(b.ConnectionId) > 128 || b.ControlGeneration == "" || len(b.ControlGeneration) > 128 || b.ExpiresUnixMilli <= time.Now().UnixMilli() || b.ExpiresUnixMilli > time.Now().Add(time.Minute).UnixMilli() || len(open.AttachTicket) != 32 || open.Target == nil || open.Target.Port > 65535 || len(open.Target.ForbiddenAuthorities) > 512 {
		return false
	}
	return applicationproxy.ValidateTarget(applicationTarget(open)) == nil
}
func applicationTarget(open *pb.ApplicationOpen) applicationproxy.Target {
	return applicationproxy.Target{ApplicationID: open.Binding.ApplicationId, ConfigVersion: open.Binding.ConfigVersion, NodeID: open.Binding.NodeId, Scheme: open.Target.Scheme, Hostname: open.Target.Hostname, Port: uint16(open.Target.Port), AllowedCIDRs: append([]string(nil), open.Target.AllowedCidrs...)}
}

// serve attaches before any backend DNS lookup or socket. Every copy/receive
// worker belongs to the RPC context; actual cleanup precedes the control ack.
func (e *applicationTransport) serve(ctx context.Context, cancel context.CancelFunc, open *pb.ApplicationOpen) string {
	opening := time.AfterFunc(10*time.Second, cancel)
	defer opening.Stop()
	stream, err := e.client.ApplicationProxy(ctx)
	if err != nil {
		return "transport"
	}
	if err := stream.Send(&pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Attach{Attach: &pb.ApplicationAttach{Binding: open.Binding, Ticket: open.AttachTicket}}}); err != nil {
		return "transport"
	}
	message, err := stream.Recv()
	if err != nil || message.GetAttached() == nil || !proto.Equal(message.GetAttached().Binding, open.Binding) {
		return "admission"
	}
	if ctx.Err() != nil || open.Binding.ExpiresUnixMilli <= time.Now().UnixMilli() {
		return "expired"
	}
	dial := e.dial
	dial.ForbiddenAuthorities = append(append([]string(nil), e.dial.ForbiddenAuthorities...), open.Target.ForbiddenAuthorities...)
	socket, err := dial.DialTarget(ctx, applicationTarget(open))
	if err != nil {
		_ = stream.Send(&pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_OpenFailed{OpenFailed: &pb.ApplicationOpenFailed{Binding: open.Binding, ReasonCode: "backend_unavailable"}}})
		return "backend_unavailable"
	}
	defer socket.Close()
	if ctx.Err() != nil {
		return "cancelled"
	}
	if err := stream.Send(&pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Opened{Opened: &pb.ApplicationOpened{Binding: open.Binding}}}); err != nil {
		return "transport"
	}
	opening.Stop()
	byteConn := applicationproxy.NewConn(ctx, func(frame applicationproxy.Frame) error {
		message := &pb.ApplicationAgentMessage{}
		if frame.EOF {
			message.Payload = &pb.ApplicationAgentMessage_Eof{Eof: &pb.ApplicationEOF{Sequence: frame.Sequence}}
		} else {
			message.Payload = &pb.ApplicationAgentMessage_Data{Data: &pb.ApplicationData{Sequence: frame.Sequence, Data: frame.Data}}
		}
		return stream.Send(message)
	}, cancel)
	var workers sync.WaitGroup
	defer func() { cancel(); socket.Close(); byteConn.Close(); workers.Wait(); <-byteConn.SenderDone() }()
	result := make(chan error, 3)
	workers.Add(3)
	go func() { defer workers.Done(); result <- receiveApplicationBytes(stream, byteConn, open.Binding) }()
	go func() {
		defer workers.Done()
		_, err := io.Copy(byteConn, socket)
		if err == nil {
			err = byteConn.CloseWrite()
		}
		result <- err
	}()
	go func() {
		defer workers.Done()
		_, err := io.Copy(applicationSocketWriter{socket}, byteConn)
		if err == nil {
			if half, ok := socket.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			}
		}
		result <- err
	}()
	completed := 0
	for {
		select {
		case <-ctx.Done():
			return "cancelled"
		case err := <-result:
			if err != nil {
				return "transport"
			}
			completed++
			if completed == 2 {
				return "complete"
			}
		}
	}
}

type applicationSocketWriter struct{ conn net.Conn }

func (w applicationSocketWriter) Write(data []byte) (int, error) {
	if err := w.conn.SetWriteDeadline(time.Now().Add(applicationproxy.WriteStallTimeout)); err != nil {
		return 0, err
	}
	return w.conn.Write(data)
}
func receiveApplicationBytes(stream pb.AgentService_ApplicationProxyClient, conn *applicationproxy.Conn, binding *pb.ApplicationBinding) error {
	for {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		if message == nil {
			return applicationproxy.ErrFrame
		}
		var frame applicationproxy.Frame
		if data := message.GetData(); data != nil {
			frame = applicationproxy.Frame{Sequence: data.Sequence, Data: data.Data}
		} else if eof := message.GetEof(); eof != nil {
			frame = applicationproxy.Frame{Sequence: eof.Sequence, EOF: true}
		} else if close := message.GetClose(); close != nil && proto.Equal(close.Binding, binding) {
			return net.ErrClosed
		} else {
			return applicationproxy.ErrFrame
		}
		if err := conn.Deliver(frame); err != nil {
			return err
		}
	}
}
