package grpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"syscall"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Execution authenticates independently of Connect: enrollment permits an
// absent certificate on that listener, which can never authorize this RPC.
func (h *Handler) executionNode(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "execution requires an enrolled node certificate")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "execution requires a verified node certificate")
	}
	cert := tlsInfo.State.PeerCertificates[0]
	now := time.Now()
	if !cert.Equal(tlsInfo.State.VerifiedChains[0][0]) || cert.Subject.CommonName == "" || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return "", status.Error(codes.Unauthenticated, "execution certificate identity is invalid")
	}
	node := cert.Subject.CommonName
	srv, err := h.store.GetServerByID(node)
	if err != nil || srv.RegistrationToken != nil || srv.Status != "online" || !executionConnectionOpen(h.connMgr.GetConn(node)) {
		return "", status.Error(codes.PermissionDenied, "execution node is not currently enrolled and connected")
	}
	return node, nil
}

func (h *Handler) Execute(stream pb.AgentService_ExecuteServer) (returnErr error) {
	node, err := h.executionNode(stream.Context())
	if err != nil {
		return err
	}
	if h.executions == nil {
		return status.Error(codes.Unavailable, "execution service unavailable")
	}
	select {
	case h.executions.rpcSlots <- struct{}{}:
		defer func() { <-h.executions.rpcSlots }()
	default:
		return status.Error(codes.ResourceExhausted, "execution stream capacity reached")
	}
	firstCh := make(chan executionReceive, 1)
	go func() { msg, err := stream.Recv(); firstCh <- executionReceive{msg, err} }()
	timer := time.NewTimer(ExecutionAttachTimeout)
	defer timer.Stop()
	var first executionReceive
	select {
	case first = <-firstCh:
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-timer.C:
		return status.Error(codes.DeadlineExceeded, "execution attachment timed out")
	}
	if first.err != nil {
		return first.err
	}
	if first.msg == nil || first.msg.GetAttach() == nil {
		return status.Error(codes.InvalidArgument, "first execution message must be Attach")
	}
	s, err := h.executions.Attach(node, first.msg.GetAttach())
	if err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	defer func() {
		close(s.transportDone)
		if returnErr != nil {
			s.Cancel("execution transport lost")
		}
	}()
	sendErr := make(chan error, 1)
	go func() { sendErr <- sendExecution(stream, s) }()
	receiveErr := make(chan error, 1)
	go func() { receiveErr <- receiveExecution(stream, s) }()
	select {
	case err := <-receiveErr:
		return err
	case err := <-sendErr:
		return err
	case <-s.Done:
		return status.Error(codes.Canceled, s.Reason())
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

type executionReceive struct {
	msg *pb.ExecutionAgentMessage
	err error
}

// This goroutine is the sole stream sender. Start always precedes stdin.
func sendExecution(stream pb.AgentService_ExecuteServer, s *ExecutionSession) error {
	if err := stream.Send(&pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_Attached{Attached: &pb.ExecutionAttached{Binding: s.Binding()}}}); err != nil {
		return err
	}
	close(s.attached)
	var dispatch executionDispatch
	select {
	case dispatch = <-s.start:
	case <-s.Done:
		return nil
	case <-s.transportDone:
		return nil
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	// Dequeue can win a select against cancellation. Refuse stale authority
	// before transferring protected input, then check again before Start.
	s.mu.Lock()
	err := s.validateLaunchLocked(stream.Context())
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if dispatch.script != nil {
		if err := sendProtectedScript(stream, s, dispatch.script); err != nil {
			return err
		}
	}
	if dispatch.beforeStart != nil {
		if err := dispatch.beforeStart(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	err = s.validateLaunchLocked(stream.Context())
	if err == nil && (s.prepared.Binding.ExpiresUnixMilli <= time.Now().UnixMilli() || (dispatch.start.AdmissionExpiresUnixMilli != 0 && dispatch.start.AdmissionExpiresUnixMilli <= time.Now().UnixMilli())) {
		err = status.Error(codes.DeadlineExceeded, "execution authority expired before launch")
	}
	if err == nil {
		// Cancel closes Done under this mutex, so a withdrawn session cannot
		// become a Start attempt. Release it before any transport I/O.
		s.startAttempted = true
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := stream.Send(&pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_Start{Start: dispatch.start}}); err != nil {
		return err
	}
	for {
		select {
		case <-s.Done:
			return nil
		case <-s.transportDone:
			return nil
		default:
		}
		select {
		case <-s.Done:
			return nil
		case <-s.transportDone:
			return nil
		case <-stream.Context().Done():
			return stream.Context().Err()
		case msg := <-s.stdin:
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

func (s *ExecutionSession) validateLaunchLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.done:
		return status.Error(codes.Canceled, "execution cancelled before launch")
	case <-s.transportDone:
		return status.Error(codes.Canceled, "execution transport completed before launch")
	default:
	}
	if s.connection != s.registry.connections.GetConn(s.NodeID) || !executionConnectionOpen(s.connection) {
		return status.Error(codes.Canceled, "execution control connection changed before launch")
	}
	return nil
}

func sendProtectedScript(stream pb.AgentService_ExecuteServer, s *ExecutionSession, reader io.Reader) error {
	buffer := make([]byte, MaxExecutionFrameBytes)
	hash := sha256.New()
	var offset uint64
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if offset+uint64(n) > s.scriptLength {
				return status.Error(codes.DataLoss, "protected input length mismatch")
			}
			_, _ = hash.Write(buffer[:n])
			if sendErr := stream.Send(&pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_ScriptChunk{ScriptChunk: &pb.ExecutionScriptChunk{Offset: offset, Data: append([]byte(nil), buffer[:n]...)}}}); sendErr != nil {
				return sendErr
			}
			offset += uint64(n)
		}
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		select {
		case <-s.Done:
			return errors.New(s.Reason())
		case <-stream.Context().Done():
			return stream.Context().Err()
		default:
		}
		if s.Binding().ExpiresUnixMilli <= time.Now().UnixMilli() {
			return status.Error(codes.DeadlineExceeded, "protected transfer expired")
		}
	}
	if offset != s.scriptLength || !bytes.Equal(hash.Sum(nil), s.scriptHash) {
		return status.Error(codes.DataLoss, "protected input content mismatch")
	}
	return stream.Send(&pb.ExecutionHubMessage{Payload: &pb.ExecutionHubMessage_ScriptEof{ScriptEof: &pb.ExecutionScriptEOF{Length: offset, Sha256: append([]byte(nil), s.scriptHash...)}}})
}

func receiveExecution(stream pb.AgentService_ExecuteServer, s *ExecutionSession) error {
	var stdoutSeq, stderrSeq uint64
	var stdoutEOF, stderrEOF, started bool
	for {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return status.Error(codes.DataLoss, "execution ended without a final result")
			}
			return err
		}
		if msg == nil {
			return status.Error(codes.InvalidArgument, "empty execution message")
		}
		switch p := msg.Payload.(type) {
		case *pb.ExecutionAgentMessage_Started:
			if started || p.Started == nil || !proto.Equal(p.Started.Binding, s.Binding()) || !s.isDispatched() {
				return status.Error(codes.InvalidArgument, "invalid execution Started")
			}
			started = true
			close(s.started)
		case *pb.ExecutionAgentMessage_StartFailed:
			if started || p.StartFailed == nil || !proto.Equal(p.StartFailed.Binding, s.Binding()) || !s.isDispatched() {
				return status.Error(codes.InvalidArgument, "invalid execution StartFailed")
			}
			state := "outcome_unknown"
			if p.StartFailed.State == "launch_failed" || p.StartFailed.State == "cancelled" {
				state = p.StartFailed.State
			}
			s.result <- &pb.ExecutionResult{Binding: s.Binding(), State: state, ExitCode: 1, Reason: "agent reported " + state}
			close(s.stdout)
			close(s.stderr)
			return nil
		case *pb.ExecutionAgentMessage_Stdout:
			if !started || stdoutEOF || p.Stdout == nil || p.Stdout.Sequence != stdoutSeq {
				return status.Error(codes.DataLoss, "invalid stdout sequence")
			}
			if err := deliverExecutionOutput(stream.Context(), s, s.stdout, p.Stdout.Data); err != nil {
				return err
			}
			stdoutSeq++
		case *pb.ExecutionAgentMessage_Stderr:
			if !started || stderrEOF || p.Stderr == nil || p.Stderr.Sequence != stderrSeq {
				return status.Error(codes.DataLoss, "invalid stderr sequence")
			}
			if err := deliverExecutionOutput(stream.Context(), s, s.stderr, p.Stderr.Data); err != nil {
				return err
			}
			stderrSeq++
		case *pb.ExecutionAgentMessage_OutputEof:
			if !started || p.OutputEof == nil {
				return status.Error(codes.DataLoss, "unexpected execution output EOF")
			}
			switch p.OutputEof.Output {
			case pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT:
				if stdoutEOF || p.OutputEof.Sequence != stdoutSeq {
					return status.Error(codes.DataLoss, "invalid stdout EOF")
				}
				stdoutEOF = true
				close(s.stdout)
			case pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR:
				if stderrEOF || p.OutputEof.Sequence != stderrSeq {
					return status.Error(codes.DataLoss, "invalid stderr EOF")
				}
				stderrEOF = true
				close(s.stderr)
			default:
				return status.Error(codes.InvalidArgument, "unknown execution output")
			}
		case *pb.ExecutionAgentMessage_Result:
			r := p.Result
			if !started || !stdoutEOF || !stderrEOF || r == nil || !proto.Equal(r.Binding, s.Binding()) || (r.State == "exited" && (!r.StdoutComplete || !r.StderrComplete)) {
				return status.Error(codes.DataLoss, "execution result is incomplete or invalid")
			}
			if r.State != "exited" && r.State != "cancelled" && r.State != "transport_lost" && r.State != "outcome_unknown" {
				return status.Error(codes.InvalidArgument, "unknown execution result state")
			}
			if r.State == "exited" && !((r.ExitCode >= 0 && r.ExitCode <= 255 && r.Signal == "") || (r.ExitCode == -1 && redactedExecutionSignal(r.Signal) != "")) {
				return status.Error(codes.DataLoss, "invalid execution process exit")
			}
			// Reasons are supplied by a remote shell environment; retain only a
			// fixed classification in ordinary hub records and client diagnostics.
			result := proto.Clone(r).(*pb.ExecutionResult)
			result.Signal = redactedExecutionSignal(result.Signal)
			if result.Reason == "completion not durable" {
				result.Reason = "completion metadata unconfirmed"
			} else if result.Reason != "" {
				result.Reason = "agent reported " + result.State
			}
			s.result <- result
			return nil
		default:
			return status.Error(codes.InvalidArgument, "unexpected execution message")
		}
	}
}

func redactedExecutionSignal(value string) string {
	for number := 1; number <= 64; number++ {
		if syscall.Signal(number).String() == value {
			return value
		}
	}
	return ""
}

func (s *ExecutionSession) isDispatched() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.dispatch }

func deliverExecutionOutput(ctx context.Context, s *ExecutionSession, ch chan []byte, data []byte) error {
	if len(data) > MaxExecutionFrameBytes {
		return status.Error(codes.ResourceExhausted, "execution output frame too large")
	}
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	select {
	case ch <- append([]byte(nil), data...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.Done:
		return errors.New("execution cancelled")
	case <-timer.C:
		return status.Error(codes.DeadlineExceeded, "execution output consumer stalled")
	}
}
