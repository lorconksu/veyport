package update

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestRollbackFailuresStayUnconfirmedAndRetainExactBackup(t *testing.T) {
	for _, fault := range []string{"backup_changed", "stop_failed", "start_failed", "no_confirmation", "journal_unavailable", "destination_symlink"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := staged(t)
			if err := p.copyVerified(p.binary, p.backup(entry.Operation), entry.Original, false); err != nil {
				t.Fatal(err)
			}
			if err := p.copyVerified(p.candidate(entry.Operation), p.binary, entry.Target, true); err != nil {
				t.Fatal(err)
			}
			if fault == "backup_changed" {
				os.WriteFile(p.backup(entry.Operation), []byte("wrong bytes"), 0755)
			}
			if fault == "journal_unavailable" {
				os.Remove(p.journal())
				os.Symlink(p.binary, p.journal())
			}
			if fault == "destination_symlink" {
				os.Remove(p.binary)
				os.Symlink(p.candidate(entry.Operation), p.binary)
			}
			starts := 0
			s := supervisor{paths: p, rollbackWait: time.Millisecond, run: func(_ context.Context, _ string, args ...string) error {
				if args[0] == "stop" && fault == "stop_failed" {
					return errors.New("stop failed")
				}
				if args[0] == "start" {
					starts++
					if fault == "start_failed" {
						return errors.New("start failed")
					}
				}
				return nil
			}}
			if err := s.rollback(context.Background(), entry, errors.New("candidate failure")); err == nil {
				t.Fatal("failed/unconfirmed rollback claimed success")
			}
			if journal, err := p.read(); err == nil && journal.Confirmed {
				t.Fatal("rollback self-confirmed without enrolled reconnect")
			}
			if fault == "start_failed" || fault == "no_confirmation" {
				current, _ := os.ReadFile(p.binary)
				if string(current) != string(oldBytes) || starts != 1 {
					t.Fatal("restoration/start was not attempted")
				}
			}
			if fault != "backup_changed" {
				backup, _ := os.ReadFile(p.backup(entry.Operation))
				if string(backup) != string(oldBytes) {
					t.Fatal("rollback destroyed the preserved original")
				}
			}
		})
	}
}

func TestFreshRecoveryCannotOverlapLiveSupervisor(t *testing.T) {
	for _, state := range []string{"downloading", "staged", "rolled_back"} {
		t.Run(state, func(t *testing.T) {
			p, entry := installation(t)
			entry.State = state
			entry.Expires = time.Now().Add(-191 * time.Second).UnixMilli()
			p.write(entry)
			owner, err := p.lock("agent-update-supervisor.lock")
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			r := runtimeFor(p, oldMetadata)
			r.budget.TryMaintenance()
			r.lease = true
			request := &pb.AgentUpdateRequest{OperationId: "fresh-operation", Version: newMetadata.Version, Revision: newMetadata.Revision, Sha256: newMetadata.SHA256, Bytes: newMetadata.Bytes, ExpiresUnixMilli: time.Now().Add(time.Minute).UnixMilli()}
			service := &artifactService{stream: &artifactStream{chunks: chunks(newBytes)}}
			var final *pb.AgentUpdateStatus
			r.Begin(context.Background(), request, service, func(status *pb.AgentUpdateStatus) { final = status })
			if final == nil || final.State != "failed" || service.called {
				t.Fatal("recovery overlapped a live supervisor")
			}
			journal, _ := p.read()
			if journal.Operation != entry.Operation {
				t.Fatal("live operation journal overwritten")
			}
			if r.budget.Acquire() {
				t.Fatal("failed recovery released old maintenance lease")
			}
		})
	}
}

func TestBootstrapSourceAndIdentityProtection(t *testing.T) {
	for _, url := range []string{"https://hub.test", "https://hub.test:8443/"} {
		if err := validateBootstrapSource(url, "hub.test:9090"); err != nil {
			t.Fatal(err)
		}
	}
	for _, url := range []string{"http://hub.test", "https://other.test", "https://user@hub.test", "https://hub.test/path", "https://hub.test?url=other", "https://hub.test#other", "://bad"} {
		if err := validateBootstrapSource(url, "hub.test:9090"); err == nil {
			t.Fatalf("unsafe source %s accepted", url)
		}
	}
	if err := validateBootstrapSource("https://hub.test", "invalid enrolled address"); err == nil {
		t.Fatal("invalid enrolled address accepted")
	}
	for _, fault := range []string{"valid", "nonroot", "tls_permissions", "config_symlink", "key_permissions"} {
		t.Run(fault, func(t *testing.T) {
			p, _ := installation(t)
			p.config = filepath.Join(p.root, "agent.conf")
			os.WriteFile(p.config, []byte("identity fixture"), 0600)
			for _, name := range []string{"client.key", "client.crt", "ca.crt"} {
				os.WriteFile(filepath.Join(p.journalDir, name), []byte("private fixture"), 0600)
			}
			uid := 0
			switch fault {
			case "nonroot":
				uid = 1000
			case "tls_permissions":
				os.Chmod(p.journalDir, 0755)
			case "config_symlink":
				os.Remove(p.config)
				os.Symlink(p.binary, p.config)
			case "key_permissions":
				os.Chmod(filepath.Join(p.journalDir, "client.key"), 0644)
			}
			err := validateHelperFiles(p, uid)
			if (err == nil) != (fault == "valid") {
				t.Fatalf("fault=%s error=%v", fault, err)
			}
		})
	}
}

func TestFirstEnrollmentRecheckKeepsProcessIdentity(t *testing.T) {
	p, _ := installation(t)
	p.config = filepath.Join(p.root, "agent.conf")
	p.systemdDir = filepath.Join(p.root, "systemd")
	p.systemdRun = filepath.Join(p.root, "systemd-run")
	p.systemctl = filepath.Join(p.root, "systemctl")
	os.Mkdir(p.systemdDir, 0700)
	for _, tool := range []string{p.systemdRun, p.systemctl} {
		os.WriteFile(tool, []byte("fixture"), 0755)
	}
	r := newRuntime(oldMetadata.Version, oldMetadata.Revision, p.config, p.journalDir, false, sessionlimit.New(8), hostEnvironment{paths: p, executable: p.binary, uid: 0, os: "linux", arch: runtime.GOARCH})
	before := r.Capabilities()
	if before.Supported {
		t.Fatal("missing enrollment configuration supported")
	}
	os.WriteFile(p.config, []byte("newly saved existing identity"), 0600)
	r.Recheck()
	after := r.Capabilities()
	if !after.Supported || after.BootId != before.BootId || after.Sha256 != before.Sha256 {
		t.Fatalf("recheck changed process identity or failed support: %v", after)
	}
	r.Recheck()
	if r.Capabilities().BootId != before.BootId {
		t.Fatal("reconnect rotated process identity")
	}
}

func TestServiceCommandsUsePrivateFixedEnvironmentAndBoundedCancellation(t *testing.T) {
	t.Setenv("UPDATE_TEST_SECRET", "fixture private value")
	root := t.TempDir()
	script := filepath.Join(root, "command")
	os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s|%s|%s|%s' \"$PATH\" \"$LANG\" \"$HOME\" \"${UPDATE_TEST_SECRET-unset}\" > \"$1\"\n"), 0700)
	out := filepath.Join(root, "output")
	if err := runCommand(context.Background(), script, out); err != nil {
		t.Fatal(err)
	}
	bytes, _ := os.ReadFile(out)
	if string(bytes) != "/usr/sbin:/usr/bin:/sbin:/bin|C|/root|unset" {
		t.Fatal("service command inherited caller environment")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runCommand(ctx, script, out); err == nil {
		t.Fatal("cancelled service command ran")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), "fixture private value") {
		t.Fatal("private input leaked into command environment")
	}
}

func TestRollbackAckReplayAndFailedPersistenceKeepTruthfulState(t *testing.T) {
	for _, fault := range []string{"confirmed_rollback", "unsafe_journal"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := installation(t)
			entry.State = "rolled_back"
			if err := p.write(entry); err != nil {
				t.Fatal(err)
			}
			r := runtimeFor(p, oldMetadata)
			r.budget.TryMaintenance()
			r.lease = true
			if fault == "unsafe_journal" {
				os.Chmod(p.journal(), 0644)
			}
			err := r.Confirm(&pb.UpdateConfirmation{OperationId: entry.Operation, State: "rolled_back"})
			if fault == "unsafe_journal" {
				if err == nil || r.budget.Acquire() {
					t.Fatal("failed persistence certified outcome/released maintenance")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			status := r.ResumeStatus()
			if status == nil || status.State != "rollback_confirmed" || status.Sha256 != entry.Original.SHA256 {
				t.Fatal("rollback acknowledgement cannot recover after lost reply")
			}
			if err := r.Confirm(&pb.UpdateConfirmation{OperationId: entry.Operation, State: "rolled_back"}); err != nil {
				t.Fatal("matching rollback replay refused")
			}
			if !r.budget.Acquire() {
				t.Fatal("durable rollback confirmation retained maintenance")
			}
		})
	}
}

func TestDurableConfirmationWinsRollbackDeadlineRace(t *testing.T) {
	p, entry := staged(t)
	if err := p.copyVerified(p.binary, p.backup(entry.Operation), entry.Original, false); err != nil {
		t.Fatal(err)
	}
	if err := p.copyVerified(p.candidate(entry.Operation), p.binary, entry.Target, true); err != nil {
		t.Fatal(err)
	}
	entry.State = "reconnecting"
	p.write(entry)
	r := runtimeFor(p, newMetadata)
	r.budget.TryMaintenance()
	r.lease = true
	if err := r.Confirm(&pb.UpdateConfirmation{OperationId: entry.Operation, State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	s := supervisor{paths: p, run: func(context.Context, string, ...string) error {
		t.Fatal("late timeout stopped durably confirmed candidate")
		return nil
	}}
	if err := s.rollback(context.Background(), entry, context.DeadlineExceeded); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(p.binary)
	journal, _ := p.read()
	if string(current) != string(newBytes) || journal.State != "succeeded" || !journal.Confirmed {
		t.Fatal("late rollback undid a committed update")
	}
	if err := s.transition(entry.Operation, "rolling_back"); err == nil {
		t.Fatal("generic transition overwrote a durable terminal state")
	}
}

func TestRollbackDecisionRejectsLateSuccessAcknowledgement(t *testing.T) {
	p, entry := staged(t)
	entry.State = "reconnecting"
	p.write(entry)
	s := supervisor{paths: p}
	committed, err := s.beginRollback(entry.Operation)
	if err != nil || committed {
		t.Fatalf("rollback decision committed=%v err=%v", committed, err)
	}
	r := runtimeFor(p, newMetadata)
	r.budget.TryMaintenance()
	r.lease = true
	if err := r.Confirm(&pb.UpdateConfirmation{OperationId: entry.Operation, State: "succeeded"}); err == nil {
		t.Fatal("late success was certified after rollback decision")
	}
	if r.budget.Acquire() {
		t.Fatal("late success released admission")
	}
	journal, _ := p.read()
	if journal.Confirmed || journal.State != "rolling_back" {
		t.Fatal("late success corrupted rollback journal")
	}
}

func TestReconnectObservesPreinstallFailureAfterWorkerCancellation(t *testing.T) {
	p, entry := installation(t)
	r := runtimeFor(p, oldMetadata)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.launch = func(context.Context, string, ...string) error { cancel(); return nil }
	request := &pb.AgentUpdateRequest{OperationId: entry.Operation, Version: entry.Target.Version, Revision: entry.Target.Revision, Sha256: entry.Target.SHA256, Bytes: entry.Target.Bytes, ExpiresUnixMilli: entry.Expires}
	r.Begin(ctx, request, &artifactService{stream: &artifactStream{chunks: chunks(newBytes)}}, func(*pb.AgentUpdateStatus) {})
	if r.budget.Acquire() {
		t.Fatal("unobserved supervisor released maintenance")
	}
	journal, _ := p.read()
	journal.State = "failed"
	p.write(*journal)
	status := r.ResumeStatus()
	if status == nil || status.State != "failed" || status.Sha256 != entry.Original.SHA256 {
		t.Fatal("reconnect lost the truthful preinstall failure")
	}
	if !r.budget.Acquire() {
		t.Fatal("terminal preinstall failure left admission permanently locked")
	}
}

func TestSupervisorPreinstallRefusalsAndLostStopReply(t *testing.T) {
	for _, fault := range []string{"expired", "existing_backup", "lost_stop_reply", "candidate_changed_after_stop", "live_supervisor", "stale_operation"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := staged(t)
			operation := entry.Operation
			identity := filepath.Join(p.journalDir, "node_key.enc")
			if err := os.WriteFile(identity, []byte("preserved fixture identity"), 0600); err != nil {
				t.Fatal(err)
			}
			if fault == "expired" {
				entry.Expires = time.Now().Add(-time.Second).UnixMilli()
				if err := p.write(entry); err != nil {
					t.Fatal(err)
				}
			}
			priorBackup := []byte("existing recovery backup must not be overwritten")
			if fault == "existing_backup" {
				if err := os.WriteFile(p.backup(operation), priorBackup, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "live_supervisor" {
				owner, err := p.lock("agent-update-supervisor.lock")
				if err != nil {
					t.Fatal(err)
				}
				defer owner.Close()
			}
			if fault == "stale_operation" {
				operation = "stale-operation"
			}
			authorized := false
			var commands []string
			s := supervisor{paths: p, wait: time.Millisecond, rollbackWait: time.Millisecond, authorize: func(context.Context, string) (*pb.UpdateAuthorization, error) {
				authorized = true
				return &pb.UpdateAuthorization{OperationId: entry.Operation, ExpiresUnixMilli: entry.Expires}, nil
			}}
			s.run = func(_ context.Context, program string, args ...string) error {
				if program != "/usr/bin/systemctl" || len(args) != 2 || args[1] != Service {
					t.Fatalf("unexpected service command: %s %v", program, args)
				}
				commands = append(commands, args[0])
				if len(commands) == 1 && fault == "lost_stop_reply" {
					return errors.New("service stop reply lost after dispatch")
				}
				if len(commands) == 1 && fault == "candidate_changed_after_stop" {
					data := append([]byte(nil), newBytes...)
					data[len(data)-1] ^= 1
					return os.WriteFile(p.candidate(entry.Operation), data, 0700)
				}
				if args[0] == "start" {
					current, err := os.ReadFile(p.binary)
					if err != nil || string(current) != string(oldBytes) {
						t.Fatal("recovery started an unverified replacement")
					}
				}
				return nil
			}
			if err := s.runOperation(context.Background(), operation); err == nil {
				t.Fatal("refused or unconfirmed update claimed success")
			}
			current, err := os.ReadFile(p.binary)
			if err != nil || string(current) != string(oldBytes) {
				t.Fatal("refusal/recovery did not preserve original binary")
			}
			key, err := os.ReadFile(identity)
			if err != nil || string(key) != "preserved fixture identity" {
				t.Fatal("refusal/recovery changed enrolled identity")
			}
			journal, err := p.read()
			if err != nil || journal.Confirmed {
				t.Fatal("unobserved recovery durably certified an outcome")
			}
			if fault == "lost_stop_reply" || fault == "candidate_changed_after_stop" {
				if strings.Join(commands, ",") != "stop,stop,start" || journal.State != "rolled_back" {
					t.Fatalf("recovery commands=%v state=%s", commands, journal.State)
				}
				backup, err := os.ReadFile(p.backup(entry.Operation))
				if err != nil || string(backup) != string(oldBytes) {
					t.Fatal("recovery lost the original backup")
				}
			} else if len(commands) != 0 {
				t.Fatal("preinstall refusal changed the service")
			}
			if (fault == "expired" || fault == "live_supervisor" || fault == "stale_operation") && authorized {
				t.Fatal("invalid staged operation attempted fresh authorization")
			}
			if fault == "existing_backup" {
				backup, err := os.ReadFile(p.backup(entry.Operation))
				if err != nil || string(backup) != string(priorBackup) {
					t.Fatal("existing recovery backup was overwritten")
				}
			}
		})
	}
}
