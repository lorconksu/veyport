package sshgw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/crypto/ssh"
)

type execParams struct {
	bridgeParams
	user     *model.User
	metadata *model.Execution
	session  *grpcserver.ExecutionSession
}

func (s *Server) authorizeExec(conn *ssh.ServerConn) (execParams, error) {
	username, target := identityFrom(conn)
	user, err := s.cfg.Store.GetUserByUsername(username)
	if err != nil {
		return execParams{}, errors.New("account is not available for command execution")
	}
	node, err := s.resolveServer(target)
	if err != nil {
		return execParams{}, err
	}
	runAs, err := server.AuthorizeTerminalExecution(s.cfg.Store, user.ID, node.ID)
	if err != nil {
		return execParams{}, errors.New(authorizationMessage(err))
	}
	return execParams{bridgeParams: bridgeParams{serverID: node.ID, serverName: node.Name, userID: user.ID, username: username, executionUser: runAs, remoteIP: remoteHost(conn.RemoteAddr())}, user: user}, nil
}

// Request success means submission acceptance. No preparation, remote process
// or stdin read occurs before the reply, so OpenSSH can immediately send input.
func (s *Server) startExec(conn *ssh.ServerConn, ch ssh.Channel, req *ssh.Request, st *sessionState) {
	if st.started || st.pty {
		replyTo(req, false)
		return
	}
	var payload struct{ Command string }
	if len(req.Payload) > grpcserver.MaxExecutionCommandBytes+4 || ssh.Unmarshal(req.Payload, &payload) != nil || payload.Command == "" || !utf8.ValidString(payload.Command) || strings.ContainsRune(payload.Command, '\x00') {
		replyTo(req, false)
		return
	}
	st.started, st.exec = true, true
	p, err := s.authorizeExec(conn)
	if err == nil && (s.cfg.Executions == nil || !s.cfg.Executions.Supports(p.serverID)) {
		err = grpcserver.ErrExecutionUnsupported
	}
	if err != nil {
		replyTo(req, true)
		s.refuseShell(ch, p.userID, p.serverID, p.remoteIP, "reason=execution_submission_denied", err.Error())
		return
	}
	id := uuid.NewString()
	p.session, err = s.cfg.Executions.Register(p.serverID, id, p.userID, p.executionUser, []byte(payload.Command))
	if err != nil {
		replyTo(req, true)
		s.refuseShell(ch, p.userID, p.serverID, p.remoteIP, "reason=execution_capacity", err.Error())
		return
	}
	hash := sha256.Sum256([]byte(payload.Command))
	p.metadata = &model.Execution{ID: id, ActorID: p.userID, ActorName: p.username, ActorProvider: string(p.user.AuthProvider), NodeID: p.serverID, NodeName: p.serverName, RequestedUser: p.executionUser, CommandSHA256: hex.EncodeToString(hash[:]), CommandLength: len(payload.Command)}
	if err = s.cfg.Store.CreateExecution(p.metadata); err != nil {
		s.cfg.Executions.Remove(p.serverID, id)
		replyTo(req, true)
		s.refuseShell(ch, p.userID, p.serverID, p.remoteIP, "reason=execution_metadata_unavailable", "execution metadata could not be recorded")
		return
	}
	p.clientGone = st.clientGone
	replyTo(req, true)
	st.shellWG.Add(1)
	go func() { defer st.shellWG.Done(); s.runExec(ch, p, payload.Command) }()
}

func (s *Server) runExec(ch ssh.Channel, p execParams, command string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer s.cfg.Executions.Remove(p.serverID, p.session.ID)
	if err := s.auditExecution(p, model.AuditExecutionSubmitted, "submitted"); err != nil {
		s.finishExec(ch, p, "admission_failed", 1, nil, "", "ordinary audit metadata unavailable")
		return
	}
	var stdoutWrite, stderrWrite atomic.Int64
	var ioWG sync.WaitGroup
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); s.watchExecution(ctx, cancel, ch, p, &stdoutWrite, &stderrWrite) }()
	result, err := s.executeStandard(ctx, ch, p, command, &stdoutWrite, &stderrWrite, &ioWG)
	if err != nil {
		reason := p.session.Reason()
		if reason == "" {
			reason = "execution preparation or transport failed"
		}
		state := "admission_failed"
		if p.metadata.State == "dispatching" || p.metadata.State == "running" {
			state = "transport_lost"
		}
		if reason != "execution transport lost" && ctx.Err() != nil {
			state = "cancelled"
		}
		p.session.Cancel(reason)
		cancel()
		s.cancelPreparedExecution(p)
		// Closing the SSH channel unblocks both output writes and stdin reads.
		s.finishExec(ch, p, state, exitAborted, nil, "", reason)
	} else {
		code := uint32(result.ExitCode)
		if result.State != "exited" && result.State != "launch_failed" {
			code = exitAborted
		}
		if result.ExitCode < 0 {
			code = exitAborted
		}
		var observedExit *int32
		if result.State == "exited" && result.ExitCode >= 0 {
			observedExit = &result.ExitCode
		}
		s.finishExec(ch, p, result.State, code, observedExit, result.Signal, result.Reason)
	}
	cancel()
	ioWG.Wait()
	<-watchDone
}

func (s *Server) cancelPreparedExecution(p execParams) {
	binding := p.session.Binding()
	if binding.PreparationId == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.cfg.ConnMgr.SendToAgentContext(ctx, p.serverID, &pb.HubMessage{Payload: &pb.HubMessage_ExecutionCancel{ExecutionCancel: &pb.ExecutionCancel{Binding: binding, Reason: "hub cancelled execution"}}})
}

func (s *Server) executeStandard(ctx context.Context, ch ssh.Channel, p execParams, command string, stdoutWrite, stderrWrite *atomic.Int64, ioWG *sync.WaitGroup) (*pb.ExecutionResult, error) {
	prepareCtx, prepareCancel := context.WithTimeout(ctx, grpcserver.ExecutionAttachTimeout)
	defer prepareCancel()
	if err := s.cfg.ConnMgr.SendToAgentContext(prepareCtx, p.serverID, &pb.HubMessage{Payload: &pb.HubMessage_ExecutionPrepare{ExecutionPrepare: &pb.ExecutionPrepare{ExecutionId: p.session.ID, NodeId: p.serverID, RunAsUser: p.executionUser, Command: command, Limits: grpcserver.DefaultExecutionLimits()}}}); err != nil {
		return nil, err
	}
	prepared, err := p.session.WaitPrepared(prepareCtx)
	if err != nil {
		return nil, err
	}
	p.metadata.Preparation = executionPreparation(prepared)
	if err = s.cfg.Store.PrepareExecution(p.session.ID, p.metadata.Preparation); err != nil {
		return nil, err
	}
	if err = s.auditExecution(p, model.AuditExecutionPrepared, "prepared"); err != nil {
		return nil, err
	}
	attach, err := p.session.IssueAttach()
	if err != nil {
		return nil, err
	}
	if err = s.cfg.ConnMgr.SendToAgentContext(prepareCtx, p.serverID, &pb.HubMessage{Payload: &pb.HubMessage_ExecutionAttach{ExecutionAttach: attach}}); err != nil {
		return nil, err
	}
	select {
	case <-p.session.Attached:
	case <-prepareCtx.Done():
		return nil, prepareCtx.Err()
	case <-p.session.Done:
		return nil, errors.New(p.session.Reason())
	}
	if err = s.recheckExecution(p); err != nil {
		return nil, err
	}
	if err = s.cfg.Store.ClaimExecutionDispatch(p.session.ID, prepared.Binding.PreparationId); err != nil {
		return nil, err
	}
	p.metadata.State = "dispatching"
	if err = s.auditExecution(p, model.AuditExecutionDispatched, "dispatching"); err != nil {
		return nil, err
	}
	if err = p.session.Dispatch(); err != nil {
		return nil, err
	}
	ioWG.Add(3)
	outputDone := make(chan struct{}, 2)
	go func() { defer ioWG.Done(); s.forwardExecutionInput(ctx, ch, p) }()
	go func() {
		defer ioWG.Done()
		defer func() { outputDone <- struct{}{} }()
		relayExecutionOutput(ctx, cancelExecutionWriter(ch, p), ch, p.session.Stdout, stdoutWrite)
	}()
	go func() {
		defer ioWG.Done()
		defer func() { outputDone <- struct{}{} }()
		relayExecutionOutput(ctx, cancelExecutionWriter(ch, p), ch.Stderr(), p.session.Stderr, stderrWrite)
	}()
	var result *pb.ExecutionResult
	runtimeTimer := time.NewTimer(time.Duration(prepared.Limits.RuntimeSeconds) * time.Second)
	defer runtimeTimer.Stop()
	started := p.session.Started
	waiting := true
	for waiting {
		select {
		case result = <-p.session.Result:
			waiting = false
		case <-started:
			started = nil
			p.metadata.State = "running"
			if err = s.cfg.Store.MarkExecutionRunning(p.session.ID); err != nil {
				p.session.Cancel("execution state could not be recorded")
			}
		case <-p.session.Done:
			err = errors.New(p.session.Reason())
			waiting = false
		case <-ctx.Done():
			err = ctx.Err()
			waiting = false
		case <-runtimeTimer.C:
			p.session.Cancel("execution runtime limit reached")
			err = errors.New("execution runtime limit reached")
			waiting = false
		}
	}
	if result == nil {
		_ = ch.Close()
		return nil, err
	}
	// Output EOF precedes Result, but SSH writes may still be draining. Wait
	// for them before sending final status; input can remain half-open.
	for n := 0; n < 2; n++ {
		select {
		case <-outputDone:
		case <-ctx.Done():
			_ = ch.Close()
			return nil, ctx.Err()
		case <-p.session.Done:
			_ = ch.Close()
			return nil, errors.New(p.session.Reason())
		}
	}
	_ = ch.CloseWrite()
	// Stop stdin reads without cutting off the result request: input relay is
	// allowed to finish when finishExec closes the channel immediately below.
	return result, nil
}

func cancelExecutionWriter(ch ssh.Channel, p execParams) func() {
	return func() { p.session.Cancel("SSH output transport failed"); _ = ch.Close() }
}

func relayExecutionOutput(ctx context.Context, onError func(), writer io.Writer, frames <-chan []byte, active *atomic.Int64) {
	defer active.Store(-1)
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-frames:
			if !ok {
				return
			}
			active.Store(time.Now().UnixNano())
			_, err := writer.Write(data)
			active.Store(0)
			if err != nil {
				onError()
				return
			}
		}
	}
}

func (s *Server) forwardExecutionInput(ctx context.Context, ch ssh.Channel, p execParams) {
	buffer := make([]byte, grpcserver.MaxExecutionFrameBytes)
	for {
		n, err := ch.Read(buffer)
		if n > 0 {
			if sendErr := p.session.SendInput(ctx, buffer[:n]); sendErr != nil {
				if errors.Is(sendErr, grpcserver.ErrExecutionInputFinished) || ctx.Err() != nil {
					return
				}
				p.session.Cancel("execution stdin transport failed")
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				if eofErr := p.session.CloseInput(ctx); eofErr != nil {
					if errors.Is(eofErr, grpcserver.ErrExecutionInputFinished) || ctx.Err() != nil {
						return
					}
					p.session.Cancel("execution stdin EOF failed")
				}
			} else {
				p.session.Cancel("SSH input transport failed")
			}
			return
		}
	}
}

func (s *Server) watchExecution(ctx context.Context, cancel context.CancelFunc, ch ssh.Channel, p execParams, stdoutWrite, stderrWrite *atomic.Int64) {
	blocked := 60 * time.Second
	if s.cfg.ExecutionConsumerTimeout > 0 && s.cfg.ExecutionConsumerTimeout < blocked {
		blocked = s.cfg.ExecutionConsumerTimeout
	}
	interval := time.Second
	if blocked/4 < interval {
		interval = blocked / 4
	}
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		var reason string
		select {
		case <-ctx.Done():
			return
		case <-p.clientGone:
			reason = "SSH client disconnected"
		case event, ok := <-p.session.Revocations:
			if !ok || event.Type == grpcserver.TerminalEventExit {
				reason = "execution access revoked"
			}
		case <-p.session.Done:
			reason = p.session.Reason()
		case <-ticker.C:
			if err := s.recheckExecution(p); err != nil {
				reason = "execution access revoked"
			}
			for _, active := range []*atomic.Int64{stdoutWrite, stderrWrite} {
				if at := active.Load(); at > 0 && time.Since(time.Unix(0, at)) >= blocked {
					reason = "SSH output consumer stalled"
				}
			}
		}
		if reason != "" {
			p.session.Cancel(reason)
			cancel()
			_ = ch.Close()
			return
		}
	}
}

func (s *Server) recheckExecution(p execParams) error {
	current, err := s.cfg.Store.GetUserByID(p.userID)
	if err != nil || executionCredentialsChanged(p.user, current) {
		return errors.New("execution actor credential revoked")
	}
	runAs, err := server.AuthorizeTerminalExecution(s.cfg.Store, p.userID, p.serverID)
	if err != nil || runAs != p.executionUser {
		return errors.New("execution authorization changed")
	}
	node, err := s.cfg.Store.GetServerByID(p.serverID)
	if err != nil || node.RegistrationToken != nil || node.Status != "online" || !s.cfg.Executions.Supports(p.serverID) {
		return errors.New("execution node unavailable")
	}
	return nil
}

// Browser refresh rotates TokenGeneration without revoking independently issued
// SSH credentials. Compare the credential and identity snapshot instead; global
// revocation additionally closes the shared registry marker immediately.
func executionCredentialsChanged(original, current *model.User) bool {
	if original.PasswordHash != current.PasswordHash || original.TOTPEnabled != current.TOTPEnabled || original.Username != current.Username || original.AuthProvider != current.AuthProvider || original.ExternalID != current.ExternalID || original.LDAPDN != current.LDAPDN || original.LDAPUsername != current.LDAPUsername || original.Role != current.Role {
		return true
	}
	return (original.TOTPSecret == nil) != (current.TOTPSecret == nil) || (original.TOTPSecret != nil && current.TOTPSecret != nil && *original.TOTPSecret != *current.TOTPSecret)
}

func executionPreparation(p *pb.ExecutionPrepared) model.ExecutionPreparation {
	i := p.Identity
	return model.ExecutionPreparation{PreparationID: p.Binding.PreparationId, BootID: p.Binding.BootId, ExpiresUnixMilli: p.Binding.ExpiresUnixMilli, Identity: model.ExecutionIdentity{Username: i.Username, UID: i.Uid, GID: i.Gid, Groups: append([]uint32(nil), i.Groups...), GroupsSHA256: hex.EncodeToString(i.GroupsSha256), IdentitySHA256: hex.EncodeToString(i.IdentitySha256), Home: i.Home, Shell: i.Shell, Cwd: i.Cwd}}
}

func (s *Server) auditExecution(p execParams, action, state string) error {
	detail := fmt.Sprintf("execution_id=%s command_sha256=%s command_length=%d state=%s", p.metadata.ID, p.metadata.CommandSHA256, p.metadata.CommandLength, state)
	if identity := p.metadata.Preparation.Identity; identity.Username != "" {
		detail += fmt.Sprintf(" execution_user=%q execution_uid=%d execution_gid=%d shell=%q cwd=%q", identity.Username, identity.UID, identity.GID, identity.Shell, identity.Cwd)
	}
	resource := "execution"
	outcome := model.AuditOutcomeSuccess
	if action == model.AuditExecutionFinished && (state != "exited" || p.metadata.ExitCode == nil || *p.metadata.ExitCode != 0) {
		outcome = model.AuditOutcomeFailure
	}
	return s.cfg.Store.LogAudit(model.AuditEntry{ID: uuid.NewString(), UserID: &p.userID, Target: &p.serverID, Action: action, Detail: &detail, IPAddress: &p.remoteIP, ActorType: model.AuditActorTypeUser, ResourceType: &resource, CorrelationID: &p.metadata.ID, Outcome: outcome})
}

func (s *Server) finishExec(ch ssh.Channel, p execParams, state string, code uint32, observedExit *int32, signal, reason string) {
	p.metadata.ExitCode = observedExit
	p.metadata.Signal = signal
	storeErr := s.cfg.Store.FinishExecution(p.session.ID, state, observedExit, signal, reason)
	auditErr := s.auditExecution(p, model.AuditExecutionFinished, state)
	if storeErr != nil || auditErr != nil {
		_ = s.cfg.Store.MarkExecutionEvidenceIncomplete(p.session.ID)
		log.Printf("SSH execution %s: completion evidence unavailable", p.session.ID)
		writeClientMessage(ch, "execution completion evidence is incomplete")
	}
	if reason != "" {
		writeClientMessage(ch, reason)
	}
	sendExitStatus(ch, code)
	_ = ch.Close()
}
