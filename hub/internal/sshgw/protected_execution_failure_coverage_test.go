package sshgw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/proto/protectedinput"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// These dependencies exercise collection failures only. They are never passed
// to runtime wiring or described as encrypted filesystem qualification.
type submissionFaultStore struct {
	file                    *submissionFaultFile
	readyError, createError error
}

func (s submissionFaultStore) Ready() error { return s.readyError }
func (s submissionFaultStore) Create() (protectedinput.File, error) {
	return s.file, s.createError
}

type submissionFaultFile struct {
	mode   string
	closed atomic.Int32
	sealed atomic.Int32
}

func (f *submissionFaultFile) Write(p []byte) (int, error) {
	if f.mode == "write-error" {
		return 0, io.ErrClosedPipe
	}
	if f.mode == "short-write" {
		return len(p) - 1, nil
	}
	return len(p), nil
}
func (f *submissionFaultFile) Seal() error {
	f.sealed.Add(1)
	if f.mode == "seal-error" {
		return io.ErrClosedPipe
	}
	return nil
}
func (f *submissionFaultFile) Open() (io.ReadCloser, error) { return nil, io.ErrClosedPipe }
func (f *submissionFaultFile) Close() error                 { f.closed.Add(1); return nil }

type submissionChannel struct {
	reader io.Reader
	closed chan struct{}
	once   sync.Once
}

func (c *submissionChannel) Read(p []byte) (int, error) {
	if c.reader != nil {
		return c.reader.Read(p)
	}
	<-c.closed
	return 0, io.ErrClosedPipe
}
func (c *submissionChannel) Write(p []byte) (int, error)                    { return len(p), nil }
func (c *submissionChannel) Close() error                                   { c.once.Do(func() { close(c.closed) }); return nil }
func (c *submissionChannel) CloseWrite() error                              { return nil }
func (c *submissionChannel) SendRequest(string, bool, []byte) (bool, error) { return false, nil }
func (c *submissionChannel) Stderr() io.ReadWriter                          { return &bytes.Buffer{} }

type submissionReadFault struct{}

func (submissionReadFault) Read(p []byte) (int, error) {
	return copy(p, "partial private script"), io.ErrUnexpectedEOF
}

func TestProtectedSubmissionStorageFailuresAndInterruptedInputNeverSealAPrefix(t *testing.T) {
	for _, mode := range []string{"create-error", "write-error", "short-write", "seal-error", "read-error"} {
		t.Run(mode, func(t *testing.T) {
			file := &submissionFaultFile{mode: mode}
			spool := submissionFaultStore{file: file}
			if mode == "create-error" {
				spool.createError = protectedinput.ErrUnavailable
			}
			var reader io.Reader = bytes.NewBufferString("complete synthetic script\n")
			if mode == "read-error" {
				reader = submissionReadFault{}
			}
			channel := &submissionChannel{reader: reader, closed: make(chan struct{})}
			s := New(Config{ProtectedExecution: &ProtectedExecutionConfig{Spool: spool}})
			p := execParams{session: &grpcserver.ExecutionSession{Done: make(chan struct{})}}
			if input, err := s.collectProtectedInput(context.Background(), channel, p, "/bin/sh -s"); err == nil || input != nil {
				t.Fatal("partial/unsealed script became eligible for preparation")
			}
			if mode != "create-error" && file.closed.Load() != 1 {
				t.Fatal("failed complete-input collection did not close its private file")
			}
			if mode != "seal-error" && file.sealed.Load() != 0 {
				t.Fatal("a failed script prefix was sealed")
			}
		})
	}
}

func TestProtectedSubmissionCancellationClosesTheOnlyBlockedReaderAndPrivateFile(t *testing.T) {
	file := &submissionFaultFile{}
	channel := &submissionChannel{closed: make(chan struct{})}
	s := New(Config{ProtectedExecution: &ProtectedExecutionConfig{Spool: submissionFaultStore{file: file}}})
	p := execParams{session: &grpcserver.ExecutionSession{Done: make(chan struct{})}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.collectProtectedInput(ctx, channel, p, "/bin/sh -s"); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil || file.closed.Load() != 1 || file.sealed.Load() != 0 {
			t.Fatal("cancelled blocked input retained a file or reported complete input")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled input reader remained unbounded")
	}
	select {
	case <-channel.closed:
	default:
		t.Fatal("cancellation did not close the blocked SSH channel")
	}
	closed := make(chan struct{})
	close(closed)
	file = &submissionFaultFile{}
	s.cfg.ProtectedExecution.Spool = submissionFaultStore{file: file}
	p.session = &grpcserver.ExecutionSession{Done: closed}
	if _, err := s.collectProtectedInput(context.Background(), &submissionChannel{reader: bytes.NewBufferString("complete\n"), closed: make(chan struct{})}, p, "/bin/sh -s"); err == nil || file.closed.Load() != 1 || file.sealed.Load() != 0 {
		t.Fatal("revoked session completed and sealed a script")
	}
}

func TestProtectedReadinessChecksStorageAndExactArchiveDependencies(t *testing.T) {
	_, _, gate, _, policy := evidenceFailureFixture(t)
	resolve := func(context.Context, model.PolicyVersion) (auditgate.Gate, error) { return gate, nil }
	for _, c := range []*ProtectedExecutionConfig{nil, {}, {Spool: submissionFaultStore{}}, {Spool: submissionFaultStore{readyError: protectedinput.ErrUnavailable}, ResolveArchive: resolve}, {Spool: submissionFaultStore{}, ResolveArchive: func(context.Context, model.PolicyVersion) (auditgate.Gate, error) { return auditgate.Gate{}, nil }}} {
		if !errors.Is(c.Ready(context.Background(), policy), authorization.ErrNotReady) {
			t.Fatal("missing required protected storage/archive dependency reported ready")
		}
	}
	if err := (&ProtectedExecutionConfig{Spool: submissionFaultStore{}, ResolveArchive: resolve}).Ready(context.Background(), policy); err != nil {
		t.Fatal("complete collection dependencies were rejected:", err)
	}
}

func TestProtectedAdmissionArchiveReceiptCannotOverrideRevokedActor(t *testing.T) {
	s, archive, _, _, policy := evidenceFailureFixture(t)
	u := &model.User{ID: "admission-actor", Username: "admission-actor", Email: "admission@synthetic.invalid", Role: model.RoleAdmin, AuthProvider: model.AuthProviderLocal}
	if err := s.cfg.Store.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	command := "id"
	p := execParams{bridgeParams: bridgeParams{userID: u.ID, username: u.Username, serverID: "node", serverName: "synthetic-target"}, user: u, session: &grpcserver.ExecutionSession{ID: "revoked-admission"}, policy: model.ExecutionPolicy{Version: policy.Version, SHA256: policy.SHA256, Enhanced: true}}
	var err error
	p.metadata, err = s.newExecutionMetadata(p, p.session.ID, command)
	if err != nil {
		t.Fatal(err)
	}
	identity := &pb.ExecutionIdentity{Username: "root", Groups: []uint32{0}, GroupsSha256: make([]byte, sha256.Size), IdentitySha256: make([]byte, sha256.Size), Home: "/root", Shell: "/bin/sh", Cwd: "/root"}
	prepared := &pb.ExecutionPrepared{Binding: &pb.ExecutionBinding{ExecutionId: p.session.ID, PreparationId: "prepared-admission", BootId: "synthetic-boot", NodeId: "node", ExpiresUnixMilli: time.Now().Add(time.Minute).UnixMilli()}, Identity: identity, Limits: &pb.ExecutionLimits{MaxFrameBytes: 32768, MaxBufferBytes: 1 << 20, RuntimeSeconds: 60, TermGraceSeconds: 5, BlockedConsumerSeconds: 60}}
	p.metadata.Preparation = executionPreparation(prepared)
	if err := s.cfg.Store.CreateExecution(p.metadata); err != nil {
		t.Fatal(err)
	}
	if err := s.cfg.Store.PrepareExecution(p.session.ID, p.metadata.Preparation); err != nil {
		t.Fatal(err)
	}
	if err := s.cfg.Store.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	receipt, expiry, start, err := s.admitProtectedExecution(context.Background(), p, command, prepared, &protectedSubmission{})
	if err == nil || receipt.Token == "" || expiry != 0 || start != nil {
		t.Fatal("independently preserved receipt authorized a revoked actor")
	}
	stored, err := s.cfg.Store.GetExecution(p.session.ID)
	if err != nil || stored.AdmissionDisposition != "archived_unused" || stored.AdmissionReceipt != receipt.Token || stored.State != "prepared" {
		t.Fatal("revoked admission lost its exact unused receipt or claimed dispatch")
	}
	var claims int
	if err := s.cfg.Store.DB().QueryRow("SELECT COUNT(*) FROM execution_dispatches WHERE execution_id=?", p.session.ID).Scan(&claims); err != nil || claims != 0 {
		t.Fatal("revoked admission consumed a dispatch claim")
	}
	if events := archive.Originals.Envelopes(); len(events) != 1 || events[0].EventType != auditrecord.ExecutionAdmission {
		t.Fatal("fixture did not prove an actual independently archived exact admission")
	}
}

func TestProtectedReadinessDenialPersistenceFaultsKeepAnExplicitEvidenceGap(t *testing.T) {
	for _, fault := range []string{"create", "finish", "queue"} {
		t.Run(fault, func(t *testing.T) {
			s, archive, _, _, policy := evidenceFailureFixture(t)
			u := &model.User{ID: "denial-actor", Username: "denial-actor", Email: "denial@synthetic.invalid", Role: model.RoleAdmin, AuthProvider: model.AuthProviderLocal}
			if err := s.cfg.Store.CreateUser(u); err != nil {
				t.Fatal(err)
			}
			trigger := "CREATE TRIGGER submission_failure BEFORE INSERT ON executions BEGIN SELECT RAISE(ABORT,'synthetic create fault'); END"
			if fault == "finish" {
				trigger = "CREATE TRIGGER submission_failure BEFORE UPDATE OF finished_at ON executions BEGIN SELECT RAISE(ABORT,'synthetic finish fault'); END"
			} else if fault == "queue" {
				trigger = "CREATE TRIGGER submission_failure BEFORE INSERT ON execution_evidence_recovery BEGIN SELECT RAISE(ABORT,'synthetic queue fault'); END"
			}
			if _, err := s.cfg.Store.DB().Exec(trigger); err != nil {
				t.Fatal(err)
			}
			p := execParams{bridgeParams: bridgeParams{userID: u.ID, username: u.Username, serverID: "node", serverName: "synthetic-target"}, user: u, policy: model.ExecutionPolicy{Version: policy.Version, SHA256: policy.SHA256, Enhanced: true}}
			if err := s.recordProtectedReadinessDenial(p, "SYNTHETIC_PRIVATE_COMMAND_CANARY"); err == nil {
				t.Fatal("failed denial persistence reported durable evidence")
			}
			var count int
			if err := s.cfg.Store.DB().QueryRow("SELECT COUNT(*) FROM executions").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if fault == "create" {
				if count != 0 {
					t.Fatal("failed initial denial left partial metadata")
				}
			} else {
				var id string
				if err := s.cfg.Store.DB().QueryRow("SELECT id FROM executions").Scan(&id); err != nil {
					t.Fatal(err)
				}
				e, err := s.cfg.Store.GetExecution(id)
				if err != nil || e.EvidenceState != "permanently_incomplete" || e.Preparation.PreparationID != "" || e.CommandSHA256 != auditrecord.Hash([]byte("SYNTHETIC_PRIVATE_COMMAND_CANARY")) || e.AdmissionReceipt != "" {
					t.Fatal("failed denial fabricated preparation/receipt or hid its evidence gap")
				}
				if fault == "queue" && (e.State != "denied" || e.FinishedAt == nil) || fault == "finish" && e.FinishedAt != nil {
					t.Fatal("failed denial invented a persisted process outcome")
				}
			}
			if len(archive.Originals.Envelopes()) != 0 {
				t.Fatal("local failed denial claimed an independent archive record")
			}
		})
	}
}

func TestProtectedSubmissionOversizeAndOrdinaryStdinCannotBecomePreparedInput(t *testing.T) {
	for _, tc := range []struct{ command, data string }{
		{"id", "SYNTHETIC_UNAPPROVED_STDIN"},
		{"/bin/sh -s", strings.Repeat("x", protectedinput.MaxScriptBytes+1)},
	} {
		file := &submissionFaultFile{}
		s := New(Config{ProtectedExecution: &ProtectedExecutionConfig{Spool: submissionFaultStore{file: file}}})
		channel := &submissionChannel{reader: strings.NewReader(tc.data), closed: make(chan struct{})}
		p := execParams{session: &grpcserver.ExecutionSession{Done: make(chan struct{})}}
		if input, err := s.collectProtectedInput(context.Background(), channel, p, tc.command); err == nil || input != nil {
			t.Fatal("unapproved stdin or oversize script became eligible for preparation")
		}
		if file.sealed.Load() != 0 || tc.command == "/bin/sh -s" && file.closed.Load() != 1 {
			t.Fatal("bounded collection retained a sealed partial input")
		}
	}
}
