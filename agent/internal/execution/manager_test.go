package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/executionidentity"
	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	j, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(Config{NodeID: "node", Journal: j, Budget: sessionlimit.New(8), TermGrace: 20 * time.Millisecond, BlockedConsumer: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}
func prepare(t *testing.T, m *Manager, id, command string) *pb.ExecutionPrepared {
	t.Helper()
	p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: id, NodeId: "node", Command: command})
	if p.Error != "" {
		t.Fatal(p.Error)
	}
	return p
}
func start(t *testing.T, m *Manager, p *pb.ExecutionPrepared) *Run {
	t.Helper()
	r, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits, PolicyVersion: "standard"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func collect(t *testing.T, r *Run) ([]byte, []byte, *pb.ExecutionResult) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	var outSeq, errSeq uint64
	var outEOF, errEOF bool
	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg, ok := <-r.Messages():
			if !ok {
				t.Fatal("closed without result")
			}
			if d := msg.GetStdout(); d != nil {
				if d.Sequence != outSeq {
					t.Fatal("stdout sequence")
				}
				outSeq++
				stdout.Write(d.Data)
			}
			if d := msg.GetStderr(); d != nil {
				if d.Sequence != errSeq {
					t.Fatal("stderr sequence")
				}
				errSeq++
				stderr.Write(d.Data)
			}
			if eof := msg.GetOutputEof(); eof != nil {
				switch eof.Output {
				case pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT:
					outEOF = eof.Sequence == outSeq
				case pb.ExecutionOutput_EXECUTION_OUTPUT_STDERR:
					errEOF = eof.Sequence == errSeq
				}
			}
			if result := msg.GetResult(); result != nil {
				if !outEOF || !errEOF {
					t.Fatal("result before output EOF")
				}
				return stdout.Bytes(), stderr.Bytes(), result
			}
		case <-deadline:
			t.Fatal("execution timed out")
		}
	}
}
func TestPrepareResolvesActualIdentityWithoutLaunching(t *testing.T) {
	m := testManager(t)
	marker := filepath.Join(t.TempDir(), "marker")
	p := prepare(t, m, "prepared", "touch "+marker)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("prepare launched")
	}
	if p.Identity.Username == "" || p.Identity.Uid != uint32(os.Geteuid()) || p.Identity.Gid != uint32(os.Getegid()) || p.Identity.Home == "" || p.Identity.Shell == "" || p.Identity.Cwd == "" || len(p.Identity.GroupsSha256) != sha256.Size || p.Binding.BootId == "" {
		t.Fatalf("incomplete actual identity: %+v", p)
	}
}
func TestBinaryOutputExitAndDrain(t *testing.T) {
	for _, code := range []int32{0, 42, 255} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			m := testManager(t)
			p := prepare(t, m, "binary", fmt.Sprintf("printf '\\000\\377foo'; printf error >&2; exit %d", code))
			r := start(t, m, p)
			out, stderr, result := collect(t, r)
			if !bytes.Equal(out, []byte{0, 255, 'f', 'o', 'o'}) || string(stderr) != "error" || result.ExitCode != code {
				t.Fatalf("output=%q stderr=%q result=%+v", out, stderr, result)
			}
		})
	}
}
func TestStreamsEOFAndExit42(t *testing.T) {
	m := testManager(t)
	p := prepare(t, m, "streams", "cat; printf '\\000\\377final'; printf problem >&2; exit 42")
	r := start(t, m, p)
	if err := r.Input(&pb.ExecutionData{Sequence: 0, Data: []byte("input")}); err != nil {
		t.Fatal(err)
	}
	if err := r.InputEOF(&pb.ExecutionInputEOF{Sequence: 1}); err != nil {
		t.Fatal(err)
	}
	if err := r.Input(&pb.ExecutionData{Sequence: 1, Data: []byte("late")}); err == nil {
		t.Fatal("input after EOF accepted")
	}
	out, stderr, result := collect(t, r)
	if !bytes.Equal(out, []byte{'i', 'n', 'p', 'u', 't', 0, 255, 'f', 'i', 'n', 'a', 'l'}) || string(stderr) != "problem" || result.ExitCode != 42 || !result.StdoutComplete || !result.StderrComplete {
		t.Fatalf("output=%q stderr=%q result=%+v", out, stderr, result)
	}
}
func TestDuplicateStartDoesNotRepeatSideEffect(t *testing.T) {
	m := testManager(t)
	marker := filepath.Join(t.TempDir(), "once")
	p := prepare(t, m, "once", "printf x >> "+marker)
	r := start(t, m, p)
	collect(t, r)
	_, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits})
	if !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("duplicate: %v", err)
	}
	data, _ := os.ReadFile(marker)
	if string(data) != "x" {
		t.Fatalf("duplicate side effect: %q", data)
	}
}
func TestBindingAndHashRejectBeforeLaunch(t *testing.T) {
	m := testManager(t)
	p := prepare(t, m, "binding", "exit 0")
	_, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: []byte("wrong"), IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits})
	if err == nil {
		t.Fatal("wrong hash accepted")
	}
	if _, ok := m.journal.Status("binding"); ok {
		t.Fatal("invalid start claimed")
	}
}
func TestCancelTerminatesGroupAndQuietCommandsAreAllowed(t *testing.T) {
	m := testManager(t)
	p := prepare(t, m, "quiet", "sleep 30 & wait")
	r := start(t, m, p)
	select {
	case <-r.Done():
		t.Fatal("quiet command timed out")
	case <-time.After(150 * time.Millisecond):
	}
	if err := m.Cancel(&pb.ExecutionCancel{Binding: p.Binding, Reason: "client_lost"}); err != nil {
		t.Fatal(err)
	}
	_, _, result := collect(t, r)
	if result.State != "cancelled" || result.Reason != "client_lost" {
		t.Fatalf("cancel: %+v", result)
	}
}
func TestPrepareRejectsEnhancedMalformedAndSharedBudget(t *testing.T) {
	m := testManager(t)
	for _, command := range []string{"", "bad\x00command", strings.Repeat("x", MaxCommandBytes+1), string([]byte{255})} {
		if p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "bad", NodeId: "node", Command: command}); p.Error == "" {
			t.Fatal("bad command accepted")
		}
	}
	if p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "enhanced", NodeId: "node", Command: "sh -s", Enhanced: true}); p.Error == "" {
		t.Fatal("unsupported enhanced accepted")
	}
	for i := 0; i < 8; i++ {
		prepare(t, m, string(rune('a'+i)), "exit 0")
	}
	if p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "ninth", NodeId: "node", Command: "exit 0"}); p.Error == "" {
		t.Fatal("node budget exceeded")
	}
}

func TestNormalExitCleansBackgroundGroupBeforeResult(t *testing.T) {
	m := testManager(t)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	p := prepare(t, m, "background", "sleep 30 >/dev/null 2>&1 & printf '%s' $! > "+pidFile)
	r := start(t, m, p)
	_, _, result := collect(t, r)
	if result.State != "exited" || result.ExitCode != 0 || result.Reason != "background_descendants_terminated" {
		t.Fatalf("background cleanup: %+v", result)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	// A terminated orphan can briefly remain a zombie until PID1 reaps it.
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil {
		end := strings.LastIndexByte(string(stat), ')')
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) == 0 || (fields[0] != "Z" && fields[0] != "X") {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("ordinary descendant survived final result: %s", stat)
		}
	}
}
func TestClaimFailureRefusesCommandAndRunningFsyncFailureIsUnknown(t *testing.T) {
	for _, failureAt := range []int{1, 3} {
		t.Run(fmt.Sprint(failureAt), func(t *testing.T) {
			m := testManager(t)
			marker := filepath.Join(t.TempDir(), "side-effect")
			p := prepare(t, m, "disk-failure", "touch "+marker+"; sleep 30")
			syncCount := 0
			m.journal.syncFile = func(f *os.File) error {
				syncCount++
				if syncCount == failureAt {
					return errors.New("disk full")
				}
				return f.Sync()
			}
			_, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits})
			if err == nil {
				t.Fatal("journal failure accepted")
			}
			if m.Status(p.ExecutionId).State != "outcome_unknown" {
				t.Fatalf("uncertainty lost: %+v", m.Status(p.ExecutionId))
			}
			if failureAt == 1 {
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("non-durable claim launched")
				}
			}
			if _, err = m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding}); !errors.Is(err, ErrAlreadyClaimed) {
				t.Fatalf("ambiguous launch retried: %v", err)
			}
		})
	}
}
func TestPreparationExpiryBootAndAttachAreSingleUse(t *testing.T) {
	m := testManager(t)
	m.ttl = 15 * time.Millisecond
	p := prepare(t, m, "expiry", "exit 0")
	if err := m.Attach(p.Binding); err != nil {
		t.Fatal(err)
	}
	if err := m.Attach(p.Binding); err == nil {
		t.Fatal("duplicate transport accepted")
	}
	expiry := time.NewTimer(30 * time.Millisecond)
	<-expiry.C
	if _, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits}); err == nil {
		t.Fatal("expired preparation started")
	}
	p = prepare(t, m, "boot", "exit 0")
	p.Binding.BootId = "old-boot"
	if err := m.Attach(p.Binding); err == nil {
		t.Fatal("previous boot attached")
	}
}
func TestLargeSlowOutputPreservesBytesAndBlockedConsumerCancels(t *testing.T) {
	t.Run("slow", func(t *testing.T) {
		m := testManager(t)
		p := prepare(t, m, "large", "head -c 3145728 /dev/zero")
		r := start(t, m, p)
		var count int
		var stdoutEOF, stderrEOF bool
		for msg := range r.Messages() {
			if d := msg.GetStdout(); d != nil {
				count += len(d.Data)
				time.Sleep(time.Millisecond)
			}
			if e := msg.GetOutputEof(); e != nil {
				if e.Output == pb.ExecutionOutput_EXECUTION_OUTPUT_STDOUT {
					stdoutEOF = true
				} else {
					stderrEOF = true
				}
			}
			if result := msg.GetResult(); result != nil {
				if count != 3145728 || !stdoutEOF || !stderrEOF || !result.StdoutComplete || !result.StderrComplete || result.State != "exited" {
					t.Fatalf("loss: count=%d result=%+v", count, result)
				}
			}
		}
	})
	t.Run("blocked", func(t *testing.T) {
		m := testManager(t)
		p := prepare(t, m, "blocked", "yes output")
		r := start(t, m, p)
		select {
		case <-r.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("blocked consumer failed to cancel")
		}
		status := m.Status(p.ExecutionId)
		if status.State != "cancelled" || status.Result.Reason != "blocked_output_consumer" {
			t.Fatalf("blocked result: %+v", status)
		}
	})
}
func TestInputRejectsOversizeSequenceAndInvalidEOF(t *testing.T) {
	m := testManager(t)
	p := prepare(t, m, "input-validation", "cat")
	r := start(t, m, p)
	if err := r.Input(&pb.ExecutionData{Sequence: 1}); err == nil {
		t.Fatal("out-of-order input accepted")
	}
	if err := r.Input(&pb.ExecutionData{Data: make([]byte, MaxFrameBytes+1)}); err == nil {
		t.Fatal("oversized input accepted")
	}
	if err := r.InputEOF(&pb.ExecutionInputEOF{Sequence: 1}); err == nil {
		t.Fatal("wrong EOF accepted")
	}
	if err := r.InputEOF(&pb.ExecutionInputEOF{}); err != nil {
		t.Fatal(err)
	}
	collect(t, r)
}

func TestFastExitIgnoresLargeValidStdinWithoutChangingResult(t *testing.T) {
	m := testManager(t)
	p := prepare(t, m, "fast-exit", "exit 0")
	r := start(t, m, p)
	inputDone := make(chan error, 1)
	go func() {
		for seq := uint64(0); seq < 128; seq++ {
			if err := r.Input(&pb.ExecutionData{Sequence: seq, Data: make([]byte, MaxFrameBytes)}); err != nil {
				inputDone <- err
				return
			}
		}
		inputDone <- r.InputEOF(&pb.ExecutionInputEOF{Sequence: 128})
	}()
	_, _, result := collect(t, r)
	if result.State != "exited" || result.ExitCode != 0 {
		t.Fatalf("late stdin changed result: %+v", result)
	}
	select {
	case err := <-inputDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("late stdin stalled after process exit")
	}
	if err := r.Input(&pb.ExecutionData{Sequence: 128, Data: []byte("after EOF")}); err == nil {
		t.Fatal("bytes after EOF accepted")
	}
}
func TestChangedIdentityAndLaunchFailureNeverRetry(t *testing.T) {
	t.Run("changed", func(t *testing.T) {
		m := testManager(t)
		originalResolve := m.resolve
		calls := 0
		m.resolve = func(user, cwd string) (*executionidentity.Identity, error) {
			identity, err := originalResolve(user, cwd)
			calls++
			if identity != nil && calls > 1 {
				identity.UID++
			}
			return identity, err
		}
		p := prepare(t, m, "identity-change", "exit 0")
		if _, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits}); err == nil {
			t.Fatal("changed identity launched")
		}
		if _, ok := m.journal.Status(p.ExecutionId); ok {
			t.Fatal("identity denial durably claimed")
		}
	})
	t.Run("launch", func(t *testing.T) {
		m := testManager(t)
		originalResolve := m.resolve
		m.resolve = func(user, cwd string) (*executionidentity.Identity, error) {
			identity, err := originalResolve(user, cwd)
			if identity != nil {
				identity.Shell = "/veyport-definitely-missing-shell"
			}
			return identity, err
		}
		p := prepare(t, m, "launch-failure", "exit 0")
		if _, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits}); err == nil {
			t.Fatal("missing shell launched")
		}
		if m.Status(p.ExecutionId).State != "launch_failed" {
			t.Fatalf("launch status: %+v", m.Status(p.ExecutionId))
		}
		if _, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding}); !errors.Is(err, ErrAlreadyClaimed) {
			t.Fatalf("failed launch retried: %v", err)
		}
	})
}

func TestControlLossAndRuntimeExpiryCleanOwnedWork(t *testing.T) {
	t.Run("control", func(t *testing.T) {
		m := testManager(t)
		p := prepare(t, m, "control-loss", "sleep 30 & wait")
		r := start(t, m, p)
		m.Close()
		select {
		case <-r.Done():
		default:
			t.Fatal("control cleanup returned with process active")
		}
		status := m.Status(p.ExecutionId)
		if status.State != "cancelled" || status.Result.Reason != "control_transport_lost" {
			t.Fatalf("control loss: %+v", status)
		}
		if prepared := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "closed", NodeId: "node", Command: "exit 0"}); prepared.Error == "" {
			t.Fatal("closed manager accepted prepare")
		}
		if _, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding}); err == nil {
			t.Fatal("closed manager accepted start")
		}
		if err := m.Attach(p.Binding); err == nil {
			t.Fatal("closed manager accepted attach")
		}
		m.Close()
	})
	t.Run("runtime", func(t *testing.T) {
		m := testManager(t)
		p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "runtime", NodeId: "node", Command: "sleep 30 & wait", Limits: &pb.ExecutionLimits{RuntimeSeconds: 1}})
		if p.Error != "" {
			t.Fatal(p.Error)
		}
		r := start(t, m, p)
		_, _, result := collect(t, r)
		if result.State != "cancelled" || result.Reason != "runtime_or_transport_expired" {
			t.Fatalf("runtime expiry: %+v", result)
		}
	})
}
func TestOutputReadFailureCannotReportSuccessfulExecution(t *testing.T) {
	m := testManager(t)
	p := prepare(t, m, "output-fault", "read token; printf payload")
	r := start(t, m, p)
	if err := r.stdout.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.InputEOF(&pb.ExecutionInputEOF{}); err != nil {
		t.Fatal(err)
	}
	_, _, result := collect(t, r)
	if result.State != "transport_lost" || result.StdoutComplete {
		t.Fatalf("output failure became success: %+v", result)
	}
}
func TestOwnershipLimitsAndLifecycleDenials(t *testing.T) {
	m := testManager(t)
	if _, err := NewManager(Config{}); err == nil {
		t.Fatal("missing journal accepted")
	}
	for _, request := range []*pb.ExecutionPrepare{nil, {ExecutionId: "wrong-node", NodeId: "other", Command: "exit 0"}, {ExecutionId: strings.Repeat("x", 129), NodeId: "node", Command: "exit 0"}, {ExecutionId: "limits", NodeId: "node", Command: "exit 0", Limits: &pb.ExecutionLimits{RuntimeSeconds: 3601}}, {ExecutionId: "limits", NodeId: "node", Command: "exit 0", Limits: &pb.ExecutionLimits{MaxFrameBytes: 1}}} {
		if prepared := m.Prepare(request); prepared.Error == "" {
			t.Fatal("invalid preparation accepted")
		}
	}
	if _, err := m.Start(context.Background(), nil); err == nil {
		t.Fatal("nil start accepted")
	}
	if err := m.Cancel(nil); err == nil {
		t.Fatal("nil cancel accepted")
	}
	if err := m.Cancel(&pb.ExecutionCancel{Binding: &pb.ExecutionBinding{ExecutionId: "missing"}}); err == nil {
		t.Fatal("unknown cancel accepted")
	}
	if m.Status("missing").State != "not_found" {
		t.Fatal("unknown status")
	}
	p := prepare(t, m, "ownership", "exit 0")
	wrong := proto.Clone(p.Binding).(*pb.ExecutionBinding)
	wrong.NodeId = "other"
	if err := m.Cancel(&pb.ExecutionCancel{Binding: wrong}); err == nil {
		t.Fatal("wrong-node cancellation accepted")
	}
	if duplicate := m.Prepare(&pb.ExecutionPrepare{ExecutionId: p.ExecutionId, NodeId: "node", Command: "exit 0"}); duplicate.Error == "" {
		t.Fatal("duplicate preparation accepted")
	}
	r := start(t, m, p)
	collect(t, r)
	if err := m.Cancel(&pb.ExecutionCancel{Binding: p.Binding}); err != nil {
		t.Fatalf("completed cancel not idempotent: %v", err)
	}
	if _, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: wrong}); err == nil || errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("wrong ownership accepted: %v", err)
	}
	if prepared := m.Prepare(&pb.ExecutionPrepare{ExecutionId: p.ExecutionId, NodeId: "node", Command: "exit 0"}); prepared.Error == "" {
		t.Fatal("completed execution prepared again")
	}
}
