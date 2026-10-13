package execution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/executionidentity"
	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	"github.com/wyiu/veyport/proto/protectedinput"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func failureStartRequest(p *pb.ExecutionPrepared) *pb.ExecutionStart {
	return &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits, PolicyVersion: "standard"}
}

func requireExecutionBudgetReleased(t *testing.T, budget *sessionlimit.Budget) {
	t.Helper()
	if !budget.Acquire() {
		t.Fatal("failed work retained the shared execution budget")
	}
	budget.Release()
}

func TestPreparationLookupFailureAndConcurrentShutdownReleaseReservation(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprint(shutdown), func(t *testing.T) {
			journal, err := OpenJournal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			releaseLookup := sync.OnceFunc(func() { close(release) })
			budget := sessionlimit.New(1)
			m, err := NewManager(Config{NodeID: "node", Journal: journal, Budget: budget, Resolve: func(user, cwd string) (*executionidentity.Identity, error) {
				close(entered)
				<-release
				if !shutdown {
					return nil, errors.New("identity lookup unavailable")
				}
				return executionidentity.Resolve(user, cwd)
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(m.Close)
			t.Cleanup(releaseLookup)
			result := make(chan *pb.ExecutionPrepared, 1)
			go func() {
				result <- m.Prepare(&pb.ExecutionPrepare{ExecutionId: "lookup", NodeId: "node", Command: "exit 0"})
			}()
			<-entered
			if duplicate := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "lookup", NodeId: "node", Command: "exit 0"}); duplicate.Error == "" {
				t.Fatal("duplicate preparation entered an active identity lookup")
			}
			if budget.Acquire() {
				budget.Release()
				t.Fatal("pending identity lookup did not reserve capacity")
			}
			if shutdown {
				m.Close()
			}
			releaseLookup()
			select {
			case response := <-result:
				if response.Error == "" {
					t.Fatal("failed or closed identity lookup installed a preparation")
				}
			case <-time.After(time.Second):
				t.Fatal("preparation did not leave the failed lookup")
			}
			if m.Status("lookup").State != "not_found" {
				t.Fatal("failed preparation acquired durable or reusable authority")
			}
			requireExecutionBudgetReleased(t, budget)
		})
	}
}

func TestLaunchLookupCancellationAndShutdownCannotCreateProcess(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprint(shutdown), func(t *testing.T) {
			m := testManager(t)
			budget := sessionlimit.New(1)
			m.budget = budget
			marker := filepath.Join(t.TempDir(), "never-launched")
			p := prepare(t, m, "launch-lookup", fmt.Sprintf("printf effect > %q", marker))
			entered, release := make(chan struct{}), make(chan struct{})
			releaseLookup := sync.OnceFunc(func() { close(release) })
			t.Cleanup(releaseLookup)
			m.resolve = func(user, cwd string) (*executionidentity.Identity, error) {
				close(entered)
				<-release
				return executionidentity.Resolve(user, cwd)
			}
			startDone := make(chan error, 1)
			go func() { _, err := m.Start(context.Background(), failureStartRequest(p)); startDone <- err }()
			<-entered
			wrong := proto.Clone(p.Binding).(*pb.ExecutionBinding)
			wrong.BootId = "foreign-boot"
			if err := m.Cancel(&pb.ExecutionCancel{Binding: wrong}); err == nil {
				t.Fatal("foreign cancellation changed a launch lookup")
			}
			var closeDone chan struct{}
			if shutdown {
				closeDone = make(chan struct{})
				go func() { m.Close(); close(closeDone) }()
				// Observe shutdown's authority invalidation before releasing lookup.
				deadline := time.Now().Add(time.Second)
				for {
					m.mu.Lock()
					closed := m.closed
					m.mu.Unlock()
					if closed {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("shutdown did not invalidate launch authority")
					}
					time.Sleep(time.Millisecond)
				}
				select {
				case <-closeDone:
					t.Fatal("shutdown returned with an unresolved launch")
				default:
				}
			} else if err := m.Cancel(&pb.ExecutionCancel{Binding: p.Binding, Reason: "operator_cancelled"}); err != nil {
				t.Fatal(err)
			}
			releaseLookup()
			select {
			case err := <-startDone:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled lookup became launchable: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled launch lookup leaked")
			}
			if closeDone != nil {
				select {
				case <-closeDone:
				case <-time.After(time.Second):
					t.Fatal("shutdown did not wait for cancelled launch cleanup")
				}
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) || m.Status(p.ExecutionId).State != "not_found" {
				t.Fatal("cancelled preclaim lookup launched or retained authority")
			}
			requireExecutionBudgetReleased(t, budget)
		})
	}
}

func TestForeignRunningCancellationCannotReplaceActualExit(t *testing.T) {
	m := testManager(t)
	p := prepare(t, m, "foreign-cancel", `printf ready; read value; printf '%s' "$value"; exit 37`)
	r := start(t, m, p)
	wrong := proto.Clone(p.Binding).(*pb.ExecutionBinding)
	wrong.PreparationId = "other-preparation"
	if err := m.Cancel(&pb.ExecutionCancel{Binding: wrong, Reason: "foreign"}); err == nil {
		t.Fatal("foreign cancellation accepted for a running command")
	}
	if err := r.Input(&pb.ExecutionData{Data: []byte("literal\n")}); err != nil {
		t.Fatal(err)
	}
	if err := r.InputEOF(&pb.ExecutionInputEOF{Sequence: 1}); err != nil {
		t.Fatal(err)
	}
	out, _, result := collect(t, r)
	if string(out) != "readyliteral" || result.State != "exited" || result.ExitCode != 37 {
		t.Fatalf("foreign cancellation altered owned work: %q %+v", out, result)
	}
}

func TestRejectedStartMetadataDoesNotConsumeValidPreparation(t *testing.T) {
	m := testManager(t)
	marker := filepath.Join(t.TempDir(), "only-once")
	p := prepare(t, m, "start-metadata", fmt.Sprintf("printf x >> %q", marker))
	for _, policy := range []string{strings.Repeat("x", 129), "bad\x00policy", string([]byte{0xff})} {
		request := failureStartRequest(p)
		request.PolicyVersion = policy
		if _, err := m.Start(context.Background(), request); err == nil {
			t.Fatal("malformed policy label acquired launch authority")
		}
	}
	for _, expiration := range []int64{0, time.Now().Add(time.Minute).UnixMilli()} {
		request := failureStartRequest(p)
		request.AdmissionReceipt = []byte("foreign-enhanced-receipt")
		request.AdmissionExpiresUnixMilli = expiration
		if _, err := m.Start(context.Background(), request); err == nil {
			t.Fatal("protected admission was accepted by an ordinary preparation")
		}
	}
	if m.Status(p.ExecutionId).State != "prepared" {
		t.Fatal("rejected start consumed its valid preparation")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("rejected start produced an effect")
	}
	r := start(t, m, p)
	_, _, result := collect(t, r)
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "x" || result.State != "exited" || result.ExitCode != 0 {
		t.Fatalf("valid preparation no longer launched exactly once: %q %+v %v", data, result, err)
	}
}

func TestCancellationNormalizesReasonAndKillsTERMResistantProcess(t *testing.T) {
	for _, reason := range []string{"", strings.Repeat("x", 129), "bad\x00reason", string([]byte{0xff})} {
		t.Run(fmt.Sprintf("%x", []byte(reason)), func(t *testing.T) {
			m := testManager(t)
			marker := filepath.Join(t.TempDir(), "trap-installed")
			p := prepare(t, m, "resistant", fmt.Sprintf("trap '' TERM; printf ready > %q; sleep 30", marker))
			r := start(t, m, p)
			deadline := time.Now().Add(time.Second)
			for {
				if _, err := os.Stat(marker); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("process did not install its TERM handler")
				}
				time.Sleep(time.Millisecond)
			}
			r.Cancel(reason)
			r.Cancel("must_not_replace_first_reason")
			_, _, result := collect(t, r)
			if result.State != "cancelled" || result.Reason != "cancelled" || result.Signal != "killed" {
				t.Fatalf("TERM-resistant cancellation: %+v", result)
			}
			if durable := m.Status(p.ExecutionId); durable.Result == nil || !proto.Equal(durable.Result, result) {
				t.Fatal("normalized cancellation was not durably retained")
			}
		})
	}
}

func TestCompletionDurabilityFailurePreservesRealExitAndPreventsReplay(t *testing.T) {
	m := testManager(t)
	var failCompletion atomic.Bool
	m.journal.syncFile = func(f *os.File) error {
		if failCompletion.Load() {
			return io.ErrUnexpectedEOF
		}
		return f.Sync()
	}
	p := prepare(t, m, "completion-fsync", "printf actual; read value; exit 42")
	r := start(t, m, p)
	// Start has durably recorded running; its real command now waits for stdin.
	failCompletion.Store(true)
	if err := r.InputEOF(&pb.ExecutionInputEOF{}); err != nil {
		t.Fatal(err)
	}
	out, _, result := collect(t, r)
	if string(out) != "actual" || result.State != "exited" || result.ExitCode != 42 || result.Reason != "completion not durable" || !result.StdoutComplete || !result.StderrComplete {
		t.Fatalf("durability failure fabricated process outcome: %q %+v", out, result)
	}
	if _, err := m.Start(context.Background(), failureStartRequest(p)); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("lost durable completion permitted replay: %v", err)
	}
	reopened, err := OpenJournal(m.journal.dir)
	if err != nil {
		t.Fatal(err)
	}
	if record, ok := reopened.Status(p.ExecutionId); !ok || record.State != "outcome_unknown" || record.Result != nil {
		t.Fatalf("restart claimed a durable completion that failed: %+v", record)
	}
}

type unavailablePreparationSpool struct{}

func (unavailablePreparationSpool) Ready() error { return nil }
func (unavailablePreparationSpool) Create() (protectedinput.File, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestProtectedPreparationStorageFailureAndExpiryReleaseCapacity(t *testing.T) {
	m, spool := protectedManager(t)
	budget := sessionlimit.New(1)
	m.budget = budget
	for _, req := range []*pb.ExecutionPrepare{
		{ExecutionId: "ordinary", NodeId: "node", Command: "exit 0", ScriptLength: 1},
		{ExecutionId: "length", NodeId: "node", Command: "sh -s", Enhanced: true, ScriptLength: protectedinput.MaxScriptBytes + 1, ScriptSha256: make([]byte, 32)},
		{ExecutionId: "hash", NodeId: "node", Command: "sh -s", Enhanced: true, ScriptSha256: []byte("short")},
	} {
		if got := m.Prepare(req); got.Error == "" || m.Status(req.ExecutionId).State != "not_found" {
			t.Fatal("invalid script binding reserved authority")
		}
	}
	m.spool = unavailablePreparationSpool{}
	if got := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "storage-failure", NodeId: "node", Command: "sh -s", Enhanced: true, ScriptSha256: make([]byte, 32)}); got.Error == "" {
		t.Fatal("failed spool creation installed a preparation")
	}
	requireExecutionBudgetReleased(t, budget)
	m.spool = spool
	m.ttl = 20 * time.Millisecond
	p := protectedPrepare(t, m, "sh -s", nil)
	deadline := time.Now().Add(time.Second)
	for m.Status(p.ExecutionId).State != "not_found" {
		if time.Now().After(deadline) {
			t.Fatal("protected preparation did not expire")
		}
		time.Sleep(time.Millisecond)
	}
	if len(spool.files) != 1 || !spool.files[0].closed {
		t.Fatal("expired protected preparation retained its raw spool")
	}
	requireExecutionBudgetReleased(t, budget)
}

func TestProtectedSpoolOpenFailureConsumesClaimWithoutProcessEffect(t *testing.T) {
	m, spool := protectedManager(t)
	marker := filepath.Join(t.TempDir(), "never-launched")
	script := []byte(fmt.Sprintf("printf effect > %q", marker))
	p := protectedPrepare(t, m, "sh -s", script)
	uploadScript(t, m, p, script)
	// The sealed fixture becomes unavailable after admission, before process start.
	spool.files[0].closed = true
	if _, err := protectedStart(m, p, "authenticated-fixture"); err == nil || !strings.Contains(err.Error(), "protected input unavailable before launch") {
		t.Fatalf("unreadable spool launched: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unreadable admitted source produced a process effect")
	}
	if _, err := protectedStart(m, p, "another-receipt"); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("consumed claim became retryable: %v", err)
	}
}
