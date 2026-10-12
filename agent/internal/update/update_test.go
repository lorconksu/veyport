package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var fixtureOnce sync.Once
var fixtureErr error
var oldBytes, newBytes []byte
var oldMetadata, newMetadata Metadata

func artifacts(t *testing.T) {
	t.Helper()
	fixtureOnce.Do(func() {
		dir, err := os.MkdirTemp("", "veyport-update-build-")
		if err != nil {
			fixtureErr = err
			return
		}
		defer os.RemoveAll(dir)
		for i, item := range []struct {
			version, revision string
			bytes             *[]byte
			metadata          *Metadata
		}{{"0.2.0-prototype.3", strings.Repeat("b", 40), &oldBytes, &oldMetadata}, {"0.2.0-prototype.4", strings.Repeat("a", 40), &newBytes, &newMetadata}} {
			path := filepath.Join(dir, fmt.Sprintf("agent%d", i))
			cmd := exec.Command("go", "build", "-ldflags", "-X main.version="+item.version+" -X main.revision="+item.revision, "-o", path, "./cmd/veyport-agent")
			cmd.Dir = "../.."
			if output, err := cmd.CombinedOutput(); err != nil {
				fixtureErr = fmt.Errorf("build agent fixture: %w: %s", err, output)
				return
			}
			data, err := os.ReadFile(path)
			if err != nil {
				fixtureErr = err
				return
			}
			*item.bytes = data
			sum := sha256.Sum256(data)
			*item.metadata = Metadata{Version: item.version, Revision: item.revision, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data))}
		}
	})
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
}

func installation(t *testing.T) (paths, record) {
	t.Helper()
	artifacts(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	tls := filepath.Join(root, "tls")
	for _, dir := range []string{bin, tls} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	p := paths{binary: filepath.Join(bin, "veyport-agent"), journalDir: tls, root: root, uid: uint32(os.Getuid())}
	if err := os.WriteFile(p.binary, oldBytes, 0755); err != nil {
		t.Fatal(err)
	}
	r := record{Schema: 1, Operation: "12345678-update", Target: newMetadata, Original: oldMetadata, Expires: time.Now().Add(5 * time.Minute).UnixMilli(), State: "staged"}
	return p, r
}

func staged(t *testing.T) (paths, record) {
	t.Helper()
	p, r := installation(t)
	if err := os.Mkdir(p.stage(r.Operation), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.candidate(r.Operation), newBytes, 0700); err != nil {
		t.Fatal(err)
	}
	if err := p.write(r); err != nil {
		t.Fatal(err)
	}
	return p, r
}

func runtimeFor(p paths, metadata Metadata) *Runtime {
	return &Runtime{paths: p, budget: sessionlimit.New(8), launch: func(context.Context, string, ...string) error { return errors.New("fixture refuses real systemd") }, capabilities: &pb.UpdateCapabilities{ProtocolVersion: 1, Os: "linux", Arch: "amd64", Version: metadata.Version, Revision: metadata.Revision, Sha256: metadata.SHA256, BootId: "fresh-boot", Supported: true}}
}

func TestProtectedJournalAndExactConfirmation(t *testing.T) {
	p, entry := staged(t)
	entry.State = "reconnecting"
	if err := p.write(entry); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p.journal())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("journal mode=%v err=%v", info, err)
	}
	r := runtimeFor(p, newMetadata)
	r.budget.TryMaintenance()
	r.lease = true
	for _, confirm := range []*pb.UpdateConfirmation{{OperationId: "stale-operation", State: "succeeded"}, {OperationId: entry.Operation, State: "rolled_back"}} {
		if err := r.Confirm(confirm); err == nil {
			t.Fatal("accepted stale or wrong artifact confirmation")
		}
		if r.budget.Acquire() {
			t.Fatal("wrong confirmation released maintenance")
		}
	}
	if status := r.ResumeStatus(); status == nil || status.State != "reconnecting" || status.Sha256 != newMetadata.SHA256 {
		t.Fatalf("resume=%v", status)
	}
	if err := r.Confirm(&pb.UpdateConfirmation{OperationId: entry.Operation, State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	if !r.budget.Acquire() {
		t.Fatal("verified confirmation did not release maintenance")
	}
	journal, _ := p.read()
	if !journal.Confirmed || journal.State != "succeeded" {
		t.Fatalf("journal=%v", journal)
	}
	if status := r.ResumeStatus(); status == nil || status.State != "confirmed" || status.OperationId != entry.Operation {
		t.Fatal("lost final acknowledgement cannot recover after reconnect")
	}
	if err := r.Confirm(&pb.UpdateConfirmation{OperationId: entry.Operation, State: "succeeded"}); err != nil {
		t.Fatal("durable confirmation replay was not idempotent")
	}
}

func TestJournalSymlinksPermissionsMalformedAndLockFailClosed(t *testing.T) {
	for _, fault := range []string{"symlink", "hardlink", "permissions", "malformed", "directory_permissions", "lock"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := installation(t)
			switch fault {
			case "symlink":
				outside := filepath.Join(p.root, "outside")
				os.WriteFile(outside, []byte("identity"), 0600)
				os.Symlink(outside, p.journal())
			case "hardlink":
				outside := filepath.Join(p.root, "outside")
				os.WriteFile(outside, []byte("identity"), 0600)
				os.Link(outside, p.journal())
			case "permissions":
				p.write(entry)
				os.Chmod(p.journal(), 0644)
			case "malformed":
				os.WriteFile(p.journal(), []byte(`{"schema":1,"unknown":"value"}`), 0600)
			case "directory_permissions":
				os.Chmod(p.journalDir, 0755)
			case "lock":
				first, err := p.lock("agent-update.lock")
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				if second, err := p.lock("agent-update.lock"); err == nil {
					second.Close()
					t.Fatal("concurrent update lock accepted")
				}
				return
			}
			if _, err := p.read(); err == nil {
				t.Fatal("unsafe journal was accepted")
			}
		})
	}
}

type artifactStream struct {
	grpc.ClientStream
	chunks []*pb.UpdateArtifactChunk
	err    error
}

func (s *artifactStream) Recv() (*pb.UpdateArtifactChunk, error) {
	if len(s.chunks) == 0 {
		if s.err != nil {
			return nil, s.err
		}
		return nil, io.EOF
	}
	chunk := s.chunks[0]
	s.chunks = s.chunks[1:]
	return chunk, nil
}
func (s *artifactStream) Header() (metadata.MD, error) { return nil, nil }

type artifactService struct {
	pb.AgentServiceClient
	stream           *artifactStream
	called           bool
	bootstrapRequest *pb.AgentUpdateRequest
	bootstrapCaps    *pb.UpdateCapabilities
	bootstrapErr     error
}

func (s *artifactService) BootstrapUpdate(_ context.Context, request *pb.UpdateBootstrapRequest, _ ...grpc.CallOption) (*pb.AgentUpdateRequest, error) {
	s.bootstrapCaps = request.Capabilities
	return s.bootstrapRequest, s.bootstrapErr
}

func (s *artifactService) DownloadUpdate(context.Context, *pb.UpdateArtifactRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.UpdateArtifactChunk], error) {
	s.called = true
	return s.stream, nil
}

func chunks(data []byte) []*pb.UpdateArtifactChunk {
	var result []*pb.UpdateArtifactChunk
	for offset := 0; offset < len(data); {
		end := offset + (32 << 10)
		if end > len(data) {
			end = len(data)
		}
		result = append(result, &pb.UpdateArtifactChunk{Offset: int64(offset), Data: data[offset:end]})
		offset = end
	}
	return result
}

func TestDownloadRejectsTruncationHashOffsetAndPlatformIdentity(t *testing.T) {
	for _, fault := range []string{"valid", "truncated", "checksum", "offset", "interrupted", "build_version", "build_revision", "elf"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := installation(t)
			r := runtimeFor(p, oldMetadata)
			data := append([]byte(nil), newBytes...)
			switch fault {
			case "truncated":
				data = data[:len(data)-1]
			case "checksum":
				data[len(data)-1] ^= 1
			case "build_version":
				entry.Target.Version = "0.2.0-prototype.5"
			case "build_revision":
				entry.Target.Revision = strings.Repeat("c", 40)
			case "elf":
				data[0] = 'X'
				sum := sha256.Sum256(data)
				entry.Target.SHA256 = hex.EncodeToString(sum[:])
			}
			stream := &artifactStream{chunks: chunks(data)}
			if fault == "offset" {
				stream.chunks[0].Offset = 1
			}
			if fault == "interrupted" {
				stream.err = errors.New("connection lost")
			}
			err := r.download(context.Background(), &artifactService{stream: stream}, entry)
			if fault == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("invalid download accepted")
			}
			current, _ := os.ReadFile(p.binary)
			if string(current) != string(oldBytes) {
				t.Fatal("download mutated installed binary")
			}
		})
	}
}

func TestAdmissionAndStaleOperationDoNotDownloadOrReplaceIdentity(t *testing.T) {
	for _, fault := range []string{"busy", "stale", "expired", "downgrade", "bad_binding"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := installation(t)
			r := runtimeFor(p, oldMetadata)
			entry.State = "failed"
			if fault == "busy" {
				r.budget.Acquire()
			}
			if fault == "stale" {
				p.write(entry)
			}
			req := &pb.AgentUpdateRequest{OperationId: entry.Operation, Version: entry.Target.Version, Revision: entry.Target.Revision, Sha256: entry.Target.SHA256, Bytes: entry.Target.Bytes, ExpiresUnixMilli: entry.Expires}
			if fault == "expired" {
				req.ExpiresUnixMilli = time.Now().Add(-time.Second).UnixMilli()
			}
			if fault == "downgrade" {
				req.Version = "0.1.0"
			}
			if fault == "bad_binding" {
				req.OperationId = "../host"
			}
			identity := filepath.Join(p.journalDir, "node_transport.key")
			os.WriteFile(identity, []byte("private fixture identity"), 0600)
			service := &artifactService{stream: &artifactStream{chunks: chunks(newBytes)}}
			var status *pb.AgentUpdateStatus
			r.Begin(context.Background(), req, service, func(s *pb.AgentUpdateStatus) { status = s })
			if status == nil || status.State != "failed" || service.called {
				t.Fatalf("status=%v downloaded=%v", status, service.called)
			}
			bytes, _ := os.ReadFile(identity)
			if string(bytes) != "private fixture identity" {
				t.Fatal("identity changed")
			}
			current, _ := os.ReadFile(p.binary)
			if string(current) != string(oldBytes) {
				t.Fatal("binary changed")
			}
		})
	}
}

func TestSupervisorSuccessAndFailuresRestoreVerifiedOriginal(t *testing.T) {
	for _, fault := range []string{"success", "candidate_start", "confirmation_timeout", "cancellation", "tampered_candidate", "authorization", "original_changed"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := staged(t)
			var commands []string
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "tampered_candidate" {
				data := append([]byte(nil), newBytes...)
				data[len(data)-1] ^= 1
				os.WriteFile(p.candidate(entry.Operation), data, 0700)
			}
			if fault == "original_changed" {
				os.WriteFile(p.binary, []byte("changed"), 0755)
			}
			s := supervisor{paths: p, wait: time.Millisecond, rollbackWait: time.Millisecond, authorize: func(context.Context, string) (*pb.UpdateAuthorization, error) {
				if fault == "authorization" {
					return nil, errors.New("governance changed")
				}
				return &pb.UpdateAuthorization{OperationId: entry.Operation, ExpiresUnixMilli: entry.Expires}, nil
			}}
			s.run = func(commandCtx context.Context, program string, args ...string) error {
				if program != "/usr/bin/systemctl" || len(args) != 2 || args[1] != Service {
					t.Fatalf("arbitrary service command %s %v", program, args)
				}
				if commandCtx.Err() != nil {
					t.Fatalf("recovery inherited forward cancellation: %v", commandCtx.Err())
				}
				commands = append(commands, args[0])
				current, _ := os.ReadFile(p.binary)
				if args[0] == "start" && string(current) == string(newBytes) {
					if fault == "candidate_start" {
						return errors.New("candidate failed")
					}
					if fault == "cancellation" {
						cancel()
						return context.Canceled
					}
					if fault == "confirmation_timeout" {
						return nil
					}
					journal, _ := p.read()
					journal.State = "succeeded"
					journal.Confirmed = true
					return p.write(*journal)
				}
				if args[0] == "start" && string(current) == string(oldBytes) {
					journal, _ := p.read()
					journal.State = "rolled_back"
					journal.Confirmed = true
					return p.write(*journal)
				}
				return nil
			}
			err := s.runOperation(ctx, entry.Operation)
			if fault == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("failure reported success")
			}
			current, _ := os.ReadFile(p.binary)
			if fault == "success" {
				if string(current) != string(newBytes) {
					t.Fatal("candidate not installed")
				}
			} else if fault != "original_changed" && string(current) != string(oldBytes) {
				t.Fatal("original binary not restored")
			}
			if fault == "tampered_candidate" || fault == "authorization" || fault == "original_changed" {
				if len(commands) != 0 {
					t.Fatal("service changed before full verification/live authorization")
				}
			} else {
				backup, _ := os.ReadFile(p.backup(entry.Operation))
				if string(backup) != string(oldBytes) {
					t.Fatal("rollback backup differs")
				}
			}
		})
	}
}

func TestLegacyRecoveryRequiresCooldownAndExactOriginal(t *testing.T) {
	_, entry := installation(t)
	entry.State = "rolled_back"
	entry.Expires = time.Now().Add(-191 * time.Second).UnixMilli()
	if !canSupersede(&entry, entry.Original, "fresh-operation") {
		t.Fatal("fresh authorized recovery cannot retire old rollback")
	}
	for _, fault := range []string{"same_op", "cooldown", "wrong_hash", "active_install", "confirmed"} {
		t.Run(fault, func(t *testing.T) {
			copy := entry
			metadata := entry.Original
			op := "fresh-operation"
			switch fault {
			case "same_op":
				op = entry.Operation
			case "cooldown":
				copy.Expires = time.Now().UnixMilli()
			case "wrong_hash":
				metadata.SHA256 = newMetadata.SHA256
			case "active_install":
				copy.State = "reconnecting"
			case "confirmed":
				copy.Confirmed = true
			}
			if canSupersede(&copy, metadata, op) {
				t.Fatal("unsafe recovery superseded journal")
			}
		})
	}
}

func TestUnprivilegedHelpersAndCapabilities(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged permission regression")
	}
	if err := ValidateHelperFiles(); err == nil {
		t.Fatal("helper accepted unprivileged invocation")
	}
	if err := Supervise(context.Background(), "valid-operation", nil); err == nil {
		t.Fatal("supervisor accepted unprivileged invocation")
	}
	if err := Bootstrap(context.Background(), strings.Repeat("x", 32), "1.0.0", "rev", nil); err == nil {
		t.Fatal("bootstrap accepted unprivileged invocation")
	}
	r := New("1.0.0", "rev", ConfigPath, CertDir, false, sessionlimit.New(8))
	caps := r.Capabilities()
	if caps.Supported || caps.Reason == "" || caps.Sha256 == "" || caps.BootId == "" {
		t.Fatalf("unsupported runtime capability=%v", caps)
	}
}

func TestBeginFailureReleasesAdmissionAndTracksOnlyBoundedSupervisor(t *testing.T) {
	for _, fault := range []string{"download", "launch", "supervisor_refuses", "journal_malformed", "staging_symlink"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := installation(t)
			r := runtimeFor(p, oldMetadata)
			if fault == "journal_malformed" {
				os.WriteFile(p.journal(), []byte("bad JSON"), 0600)
			}
			if fault == "staging_symlink" {
				outside := filepath.Join(p.root, "outside")
				os.Mkdir(outside, 0700)
				os.WriteFile(filepath.Join(outside, "candidate"), []byte("preserve"), 0600)
				os.Symlink(outside, p.stage(entry.Operation))
			}
			stream := &artifactStream{chunks: chunks(newBytes)}
			if fault == "download" {
				stream.err = errors.New("partition")
			}
			service := &artifactService{stream: stream}
			launched := false
			r.launch = func(ctx context.Context, program string, args ...string) error {
				launched = true
				if caps := r.Capabilities(); caps.BootId == "" {
					t.Fatal("capabilities unavailable while updating")
				}
				joined := strings.Join(args, " ")
				if program != "/usr/bin/systemd-run" || !strings.Contains(joined, "--collect") || !strings.Contains(joined, "RuntimeMaxSec=180") || !strings.Contains(joined, "TimeoutStopSec=5") || !strings.Contains(joined, "KillMode=control-group") || !strings.Contains(joined, "SendSIGKILL=yes") || !strings.Contains(joined, p.candidate(entry.Operation)+" --update-supervisor "+entry.Operation) {
					t.Fatalf("untracked supervisor %s %v", program, args)
				}
				if fault == "launch" {
					return errors.New("systemd unavailable")
				}
				journal, err := p.read()
				if err != nil {
					t.Fatal(err)
				}
				journal.State = "failed"
				return p.write(*journal)
			}
			request := &pb.AgentUpdateRequest{OperationId: entry.Operation, Version: entry.Target.Version, Revision: entry.Target.Revision, Sha256: entry.Target.SHA256, Bytes: entry.Target.Bytes, ExpiresUnixMilli: entry.Expires}
			var final *pb.AgentUpdateStatus
			r.Begin(context.Background(), request, service, func(status *pb.AgentUpdateStatus) { final = status })
			if final == nil || final.State != "failed" {
				t.Fatalf("status=%v", final)
			}
			if !r.budget.Acquire() {
				t.Fatal("failed update left normal admission locked")
			}
			if (fault == "launch" || fault == "supervisor_refuses") != launched {
				t.Fatalf("launched=%v fault=%s", launched, fault)
			}
			current, _ := os.ReadFile(p.binary)
			if string(current) != string(oldBytes) {
				t.Fatal("pre-install failure replaced binary")
			}
			if fault == "staging_symlink" {
				bytes, _ := os.ReadFile(filepath.Join(p.root, "outside", "candidate"))
				if string(bytes) != "preserve" {
					t.Fatal("failed cleanup followed staging symlink")
				}
			}
		})
	}
}

func TestPreservingBootstrapBoundToOldIdentityAndNewApprovedArtifact(t *testing.T) {
	for _, fault := range []string{"success", "rpc_refused", "wrong_version", "wrong_revision", "candidate_changed", "wrong_stage", "launch_failure", "pending_operation", "recovered_legacy"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := installation(t)
			stage := filepath.Join(filepath.Dir(p.binary), ".veyport-agent-bootstrap-fixture")
			os.Mkdir(stage, 0700)
			executable := filepath.Join(stage, "candidate")
			os.WriteFile(executable, newBytes, 0700)
			identity := filepath.Join(p.journalDir, "client.key")
			os.WriteFile(identity, []byte("enrolled private identity"), 0600)
			request := &pb.AgentUpdateRequest{OperationId: entry.Operation, Version: newMetadata.Version, Revision: newMetadata.Revision, Sha256: newMetadata.SHA256, Bytes: newMetadata.Bytes, ExpiresUnixMilli: entry.Expires}
			service := &artifactService{bootstrapRequest: request}
			if fault == "rpc_refused" {
				service.bootstrapErr = errors.New("ticket consumed")
			}
			if fault == "candidate_changed" {
				os.WriteFile(executable, oldBytes, 0700)
			}
			if fault == "wrong_stage" {
				executable = p.binary
			}
			if fault == "pending_operation" || fault == "recovered_legacy" {
				previous := entry
				previous.Operation = "older-operation"
				previous.State = "rolled_back"
				if fault == "recovered_legacy" {
					previous.Expires = time.Now().Add(-191 * time.Second).UnixMilli()
				}
				p.write(previous)
			}
			version, revision := newMetadata.Version, newMetadata.Revision
			if fault == "wrong_version" {
				version = "1.0.0"
			}
			if fault == "wrong_revision" {
				revision = "unknown"
			}
			launched := false
			err := bootstrap(context.Background(), p, strings.Repeat("x", 64), version, revision, service, executable, func(_ context.Context, program string, args ...string) error {
				launched = true
				if program != "/usr/bin/systemd-run" {
					t.Fatal("arbitrary bootstrap process")
				}
				if err := p.verify(p.candidate(entry.Operation), newMetadata, true); err != nil {
					t.Fatal(err)
				}
				if fault == "launch_failure" {
					return errors.New("systemd refused")
				}
				return nil
			})
			if fault == "success" || fault == "recovered_legacy" {
				if err != nil || !launched {
					t.Fatalf("bootstrap err=%v launched=%v", err, launched)
				}
			} else if err == nil {
				t.Fatal("unsafe bootstrap accepted")
			}
			if service.bootstrapCaps == nil || service.bootstrapCaps.Sha256 != oldMetadata.SHA256 || service.bootstrapCaps.Version != oldMetadata.Version || service.bootstrapCaps.Revision != oldMetadata.Revision {
				t.Fatal("bootstrap attested candidate instead of installed identity")
			}
			key, _ := os.ReadFile(identity)
			if string(key) != "enrolled private identity" {
				t.Fatal("bootstrap mutated identity")
			}
			current, _ := os.ReadFile(p.binary)
			if string(current) != string(oldBytes) {
				t.Fatal("bootstrap directly replaced running binary")
			}
			if fault == "launch_failure" {
				journal, _ := p.read()
				if journal.State != "failed" {
					t.Fatal("failed bootstrap remained active")
				}
			}
		})
	}
}
