package grpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"time"

	"github.com/wyiu/veyport/proto/applicationproxy"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// applicationNode is independent from Connect's bootstrap exception, and
// additionally binds the certificate to the exact active control identity.
func (h *Handler) applicationNode(ctx context.Context) (string, time.Time, error) {
	node, err := h.executionNode(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	current := h.connMgr.GetConn(node)
	if current == nil {
		return "", time.Time{}, status.Error(codes.PermissionDenied, "application control connection unavailable")
	}
	p, _ := peer.FromContext(ctx)
	info := p.AuthInfo.(credentials.TLSInfo)
	cert := info.State.PeerCertificates[0]
	controlPeer, ok := peer.FromContext(current.Stream.Context())
	if !ok {
		return "", time.Time{}, status.Error(codes.Unauthenticated, "application control identity unavailable")
	}
	controlTLS, ok := controlPeer.AuthInfo.(credentials.TLSInfo)
	if !ok || len(controlTLS.State.PeerCertificates) == 0 || len(cert.Raw) == 0 || !bytes.Equal(cert.Raw, controlTLS.State.PeerCertificates[0].Raw) {
		return "", time.Time{}, status.Error(codes.Unauthenticated, "application certificate differs from active control identity")
	}
	return node, cert.NotAfter, nil
}

type applicationReceive struct {
	message *pb.ApplicationAgentMessage
	err     error
}

func (h *Handler) ApplicationProxy(stream pb.AgentService_ApplicationProxyServer) error {
	node, certExpiry, err := h.applicationNode(stream.Context())
	if err != nil {
		return err
	}
	t := h.applications
	if t == nil {
		return status.Error(codes.Unavailable, "application transport unavailable")
	}
	if !t.reserveRPC(node) {
		return status.Error(codes.ResourceExhausted, "application RPC capacity reached")
	}
	defer t.releaseRPC(node)
	firstCh := make(chan applicationReceive, 1)
	go func() { m, e := stream.Recv(); firstCh <- applicationReceive{m, e} }()
	timer := time.NewTimer(ApplicationOpenTimeout)
	defer timer.Stop()
	var first applicationReceive
	select {
	case first = <-firstCh:
	case <-timer.C:
		return status.Error(codes.DeadlineExceeded, "application attachment timed out")
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	if first.err != nil {
		return first.err
	}
	if first.message == nil || first.message.GetAttach() == nil {
		return status.Error(codes.InvalidArgument, "first application message must attach")
	}
	s, err := t.attach(node, first.message.GetAttach())
	if err != nil {
		return status.Error(codes.PermissionDenied, "application attachment refused")
	}
	defer s.cancel()
	if err := t.checkAdmission(s); err != nil {
		return status.Error(codes.PermissionDenied, "application admission expired")
	}
	if err := stream.Send(&pb.ApplicationHubMessage{Payload: &pb.ApplicationHubMessage_Attached{Attached: &pb.ApplicationAttached{Binding: proto.Clone(s.binding).(*pb.ApplicationBinding)}}}); err != nil {
		return err
	}
	conn := applicationproxy.NewConn(s.ctx, func(frame applicationproxy.Frame) error {
		message := &pb.ApplicationHubMessage{}
		if frame.EOF {
			message.Payload = &pb.ApplicationHubMessage_Eof{Eof: &pb.ApplicationEOF{Sequence: frame.Sequence}}
		} else {
			message.Payload = &pb.ApplicationHubMessage_Data{Data: &pb.ApplicationData{Sequence: frame.Sequence, Data: frame.Data}}
		}
		return stream.Send(message)
	}, s.cancel)
	defer conn.Close()
	t.mu.Lock()
	s.conn = conn
	t.mu.Unlock()
	received := make(chan error, 1)
	go func() { received <- t.receiveApplication(stream, s, conn) }()
	expiry := time.NewTimer(time.Until(certExpiry))
	defer expiry.Stop()
	select {
	case err := <-received:
		return err
	case <-conn.Done():
		return status.Error(codes.Canceled, "application connection closed")
	case <-expiry.C:
		return status.Error(codes.Unauthenticated, "application certificate expired")
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

func (t *ApplicationTunnels) attach(node string, attach *pb.ApplicationAttach) (*applicationTunnel, error) {
	if attach == nil || attach.Binding == nil || len(attach.Ticket) != 32 {
		return nil, ErrApplicationUnavailable
	}
	digest := sha256.Sum256(attach.Ticket)
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.nodes[attach.Binding.ConnectionId]
	if t.closed || s == nil || s.attached || s.target.NodeID != node || !proto.Equal(s.binding, attach.Binding) || s.ctx.Err() != nil || t.connections.GetConn(node) != s.control || !applicationControlOpen(s.control) || time.Now().UnixMilli() >= s.binding.ExpiresUnixMilli || subtle.ConstantTimeCompare(digest[:], s.ticket[:]) != 1 {
		return nil, ErrApplicationUnavailable
	}
	s.attached = true
	s.ticket = [32]byte{}
	return s, nil
}
func (t *ApplicationTunnels) receiveApplication(stream pb.AgentService_ApplicationProxyServer, s *applicationTunnel, conn *applicationproxy.Conn) error {
	opened := false
	for {
		message, err := stream.Recv()
		if err != nil {
			if err == io.EOF && !opened {
				s.reportReady(ErrApplicationUnavailable)
			}
			return err
		}
		if message == nil {
			return applicationproxy.ErrFrame
		}
		if !opened {
			if failed := message.GetOpenFailed(); failed != nil && proto.Equal(failed.Binding, s.binding) {
				s.reportReady(errors.New("application backend connection failed"))
				return status.Error(codes.Unavailable, "application backend connection failed")
			}
			ready := message.GetOpened()
			if ready == nil || !proto.Equal(ready.Binding, s.binding) || t.checkAdmission(s) != nil {
				s.reportReady(ErrApplicationUnavailable)
				return status.Error(codes.PermissionDenied, "application opening refused")
			}
			opened = true
			s.reportReady(nil)
			continue
		}
		var frame applicationproxy.Frame
		if data := message.GetData(); data != nil {
			frame = applicationproxy.Frame{Sequence: data.Sequence, Data: data.Data}
		} else if eof := message.GetEof(); eof != nil {
			frame = applicationproxy.Frame{Sequence: eof.Sequence, EOF: true}
		} else {
			return applicationproxy.ErrFrame
		}
		if err := conn.Deliver(frame); err != nil {
			return err
		}
	}
}
