package sshgw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/proto/protectedinput"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/crypto/ssh"
)

// ResolveArchive must construct the client/verifier from this exact immutable
// policy version, its credential reference, allowed destination and pinned keys.
// Readiness is evaluated from actual encrypted storage and configured clients;
// each command still requires an individual cryptographic external receipt.
type ProtectedExecutionConfig struct {
	Spool          protectedinput.Store
	ResolveArchive func(context.Context, model.PolicyVersion) (auditgate.Gate, error)
}

func (c *ProtectedExecutionConfig) Ready(ctx context.Context, p model.PolicyVersion) error {
	if c == nil || c.Spool == nil || c.ResolveArchive == nil || c.Spool.Ready() != nil {
		return authorization.ErrNotReady
	}
	g, err := c.ResolveArchive(ctx, p)
	if err != nil || g.Preserver == nil || g.Verifier == nil {
		return authorization.ErrNotReady
	}
	return nil
}

type protectedSubmission struct {
	file   protectedinput.File
	hash   []byte
	length uint64
}

func (s *Server) newExecutionMetadata(p execParams, id, command string) (*model.Execution, error) {
	hash := sha256.Sum256([]byte(command))
	e := &model.Execution{ID: id, ActorID: p.userID, ActorName: p.username, ActorProvider: string(p.user.AuthProvider), ActorSubject: p.user.ExternalID, NodeID: p.serverID, NodeName: p.serverName, RequestedUser: p.executionUser, CommandSHA256: hex.EncodeToString(hash[:]), CommandLength: len(command), Enhanced: p.policy.Enhanced, PolicyVersion: policyLabel(p.policy), PolicySHA256: p.policy.SHA256}
	var err error
	e.ActorPersonID, err = s.cfg.Store.PersonForUser(p.userID)
	return e, err
}

// This path runs only after SSH authentication, live node authorization and
// command syntax validation. It records no raw payload or prepared identity.
func (s *Server) recordProtectedReadinessDenial(p execParams, command string) error {
	var err error
	p.metadata, err = s.newExecutionMetadata(p, uuid.NewString(), command)
	if err != nil {
		return err
	}
	if err = s.cfg.Store.CreateExecution(p.metadata); err != nil {
		return err
	}
	if err = s.cfg.Store.FinishExecution(p.metadata.ID, "denied", nil, "", "protected execution unavailable"); err != nil {
		_ = s.cfg.Store.MarkExecutionEvidencePermanent(p.metadata.ID)
		return err
	}
	if err = s.queueExecutionLifecycle(p); err != nil {
		_ = s.cfg.Store.MarkExecutionEvidencePermanent(p.metadata.ID)
		return err
	}
	s.wakeEvidenceRecovery()
	return nil
}

func scriptInterpreter(command string) string {
	switch command {
	case "bash -s", "/bin/bash -s":
		return "/bin/bash"
	case "sh -s", "/bin/sh -s":
		return "/bin/sh"
	default:
		return ""
	}
}
func (s *Server) collectProtectedInput(ctx context.Context, ch ssh.Channel, p execParams, command string) (*protectedSubmission, error) {
	input := &protectedSubmission{}
	script := scriptInterpreter(command) != ""
	if script {
		var err error
		input.file, err = s.cfg.ProtectedExecution.Spool.Create()
		if err != nil {
			return nil, protectedinput.ErrUnavailable
		}
	}
	complete := false
	defer func() {
		if !complete && input.file != nil {
			_ = input.file.Close()
		}
	}()
	// ssh.Channel has no read deadline. Closing the channel on cancellation
	// bounds the sole reader, including clients that never send input EOF.
	readDone := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		timer := time.NewTimer(120 * time.Second)
		defer timer.Stop()
		select {
		case <-readDone:
		case <-ctx.Done():
			_ = ch.Close()
		case <-timer.C:
			p.session.Cancel("protected submission deadline exceeded")
			_ = ch.Close()
		}
	}()
	defer func() { close(readDone); <-watchDone }()
	buffer := make([]byte, 64<<10)
	hash := sha256.New()
	for {
		n, err := ch.Read(buffer)
		if n > 0 {
			if !script {
				return nil, errors.New("enhanced commands require empty stdin; use an exact bash -s or sh -s form for complete scripts")
			}
			if input.length+uint64(n) > protectedinput.MaxScriptBytes {
				return nil, protectedinput.ErrLimit
			}
			written, writeErr := input.file.Write(buffer[:n])
			if writeErr != nil || written != n {
				return nil, protectedinput.ErrUnavailable
			}
			_, _ = hash.Write(buffer[:n])
			input.length += uint64(n)
		}
		if err != nil {
			if err != io.EOF {
				return nil, errors.New("protected submission interrupted")
			}
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	select {
	case <-p.session.Done:
		return nil, errors.New(p.session.Reason())
	default:
	}
	if script {
		if err := input.file.Seal(); err != nil {
			return nil, protectedinput.ErrUnavailable
		}
		input.hash = hash.Sum(nil)
	}
	complete = true
	return input, nil
}

func (s *Server) recheckExecutionPolicy(p execParams) error {
	if err := s.recheckExecution(p); err != nil {
		return err
	}
	current, err := authorization.New(s.cfg.Store).PolicyForExecution(p.userID, p.serverID)
	if err != nil {
		return err
	}
	if current != p.policy {
		return errors.New("execution policy changed after submission")
	}
	person, err := s.cfg.Store.PersonForUser(p.userID)
	if err != nil || person != p.metadata.ActorPersonID {
		return errors.New("execution actor identity changed")
	}
	return nil
}

func protectedBinding(p execParams, prepared *pb.ExecutionPrepared, input *protectedSubmission) auditrecord.ExecutionBinding {
	i := p.metadata.Preparation.Identity
	l := prepared.Limits
	x := auditrecord.ExecutionBinding{ExecutionID: p.session.ID, PreparationID: prepared.Binding.PreparationId, BootID: prepared.Binding.BootId, NodeID: p.serverID, NodeName: p.serverName, CommandSHA256: p.metadata.CommandSHA256, CommandBytes: int64(p.metadata.CommandLength), PreparedUntil: time.UnixMilli(prepared.Binding.ExpiresUnixMilli).UTC(), Identity: auditrecord.Identity{Username: i.Username, UID: i.UID, GID: i.GID, Groups: i.Groups, GroupsSHA256: i.GroupsSHA256, IdentitySHA256: i.IdentitySHA256, Home: i.Home, Shell: i.Shell, CWD: i.Cwd}, Limits: auditrecord.Limits{MaxFrameBytes: l.MaxFrameBytes, MaxBufferBytes: l.MaxBufferBytes, RuntimeSeconds: l.RuntimeSeconds, TermGraceSeconds: l.TermGraceSeconds, BlockedConsumerSeconds: l.BlockedConsumerSeconds}}
	if len(input.hash) != 0 {
		x.ScriptSHA256 = hex.EncodeToString(input.hash)
		x.ScriptBytes = int64(input.length)
	}
	return x
}

type executionConsumer struct {
	server *Server
	params execParams
}

func (c executionConsumer) Claim(ctx context.Context, id, preparation, hash string) error {
	if id != c.params.session.ID {
		return auditgate.ErrReceipt
	}
	if err := c.server.recheckExecutionPolicy(c.params); err != nil {
		return err
	}
	return c.server.cfg.Store.Claim(ctx, id, preparation, hash)
}

func (s *Server) admitProtectedExecution(ctx context.Context, p execParams, command string, prepared *pb.ExecutionPrepared, input *protectedSubmission) (auditrecord.Receipt, int64, func() error, error) {
	version, err := s.cfg.Store.GetPolicyVersion(p.policy.Version)
	if err != nil || version.SHA256 != p.policy.SHA256 {
		return auditrecord.Receipt{}, 0, nil, authorization.ErrNotReady
	}
	gate, err := s.cfg.ProtectedExecution.ResolveArchive(ctx, version)
	if err != nil {
		return auditrecord.Receipt{}, 0, nil, err
	}
	binding := protectedBinding(p, prepared, input)
	p.metadata.ScriptSHA256 = binding.ScriptSHA256
	p.metadata.ScriptLength = binding.ScriptBytes
	p.metadata.AdmissionEventID = p.session.ID + ".admission"
	envelope := auditrecord.Envelope{SchemaVersion: 1, EventID: p.metadata.AdmissionEventID, EventType: auditrecord.ExecutionAdmission, Actor: auditrecord.Actor{UserID: p.userID, PersonID: p.metadata.ActorPersonID, Name: p.username, Provider: p.metadata.ActorProvider, Subject: p.metadata.ActorSubject}, Execution: &binding, PolicyVersion: p.policy.Version, PolicySHA256: p.policy.SHA256, OccurredAt: time.Now().UTC(), Command: []byte(command)}
	var attachments []auditgate.AttachmentInput
	if input.file != nil {
		envelope.Attachments = []auditrecord.Attachment{{ID: "script", SHA256: binding.ScriptSHA256, Bytes: binding.ScriptBytes}}
		reader, openErr := input.file.Open()
		if openErr != nil {
			return auditrecord.Receipt{}, 0, nil, openErr
		}
		defer reader.Close()
		attachments = []auditgate.AttachmentInput{{ID: "script", Reader: reader}}
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return auditrecord.Receipt{}, 0, nil, err
	}
	expected, _, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return auditrecord.Receipt{}, 0, nil, err
	}
	minimum := time.Now().UTC().Add(time.Duration(version.Policy.RetentionHours) * time.Hour)
	expected.MinRetainUntil = minimum
	p.metadata.AdmissionRecordSHA256 = expected.RecordSHA256
	if err = s.cfg.Store.SetExecutionSubmission(p.session.ID, binding.ScriptSHA256, binding.ScriptBytes, envelope.EventID, expected.RecordSHA256); err != nil {
		return auditrecord.Receipt{}, 0, nil, err
	}
	gate.Consumer = executionConsumer{server: s, params: p}
	admissionCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	receipt, err := gate.Admit(admissionCtx, raw, attachments, binding, minimum)
	if err != nil {
		if receipt.Token != "" {
			if claims, verifyErr := gate.Verifier.Verify(receipt.Token, expected, time.Now()); verifyErr == nil && auditrecord.Digest(claims.Manifest) == auditrecord.Digest(receipt.Manifest) {
				_ = s.cfg.Store.SaveUnusedExecutionReceipt(p.session.ID, receipt.Token)
			}
		}
		return receipt, 0, nil, err
	}
	claims, err := gate.Verifier.Verify(receipt.Token, expected, time.Now())
	if err != nil {
		return receipt, 0, nil, err
	}
	if err = s.cfg.Store.SaveExecutionReceipt(p.session.ID, receipt.Token); err != nil {
		return receipt, 0, nil, err
	}
	p.metadata.AdmissionReceipt = receipt.Token
	// This runs in the sole stream sender after the complete transfer and
	// immediately before Start. Policy changes never reinterpret old input.
	beforeStart := func() error {
		if err := s.recheckExecutionPolicy(p); err != nil {
			return err
		}
		_, err := gate.Verifier.Verify(receipt.Token, expected, time.Now())
		return err
	}
	return receipt, claims.ExpiresAt.Time.UnixMilli(), beforeStart, nil
}

func policyLabel(p model.ExecutionPolicy) string { return strconv.FormatUint(p.Version, 10) }
