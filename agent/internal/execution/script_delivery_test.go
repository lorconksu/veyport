package execution

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wyiu/veyport/proto/protectedinput"
)

type deliverySpoolStore struct {
	file *deliverySpool
	open func([]byte) io.ReadCloser
}

func (*deliverySpoolStore) Ready() error { return nil }
func (s *deliverySpoolStore) Create() (protectedinput.File, error) {
	s.file = &deliverySpool{memorySpool: &memorySpool{store: &memorySpoolStore{}}, open: s.open}
	return s.file, nil
}

type deliverySpool struct {
	*memorySpool
	open func([]byte) io.ReadCloser
}

func (f *deliverySpool) Open() (io.ReadCloser, error) {
	return f.open(append([]byte(nil), f.Bytes()...)), nil
}

// Return an intact prefix first and wait for its real effect before producing
// the backing-file fault. The assertion concerns truthful outcome and stopping
// owned work; it never assumes that previous effects can be rolled back.
type failingDeliveryReader struct {
	prefix []byte
	marker string
	fault  error
}

func (r *failingDeliveryReader) Read(p []byte) (int, error) {
	if len(r.prefix) != 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(r.marker); err == nil && string(data) == "prefix" {
			return 0, r.fault
		}
		time.Sleep(time.Millisecond)
	}
	return 0, r.fault
}
func (*failingDeliveryReader) Close() error { return nil }

func TestProtectedScriptDeliveryFaultCancelsWithDurableIncompleteOutcome(t *testing.T) {
	for _, fault := range []error{syscall.EIO, io.EOF} {
		t.Run(fault.Error(), func(t *testing.T) {
			m := testManager(t)
			marker := filepath.Join(t.TempDir(), "prefix-effect")
			prefix := "printf prefix > '" + marker + "'\nsleep 30\n"
			script := []byte(prefix + "exit 42\n")
			spool := &deliverySpoolStore{open: func([]byte) io.ReadCloser {
				return &failingDeliveryReader{prefix: []byte(prefix), marker: marker, fault: fault}
			}}
			m.spool = spool
			p := protectedPrepare(t, m, "sh -s", script)
			uploadScript(t, m, p, script)
			run, err := protectedStart(m, p, "hub-verified-receipt")
			if err != nil {
				t.Fatal(err)
			}
			_, _, result := collect(t, run)
			<-run.Done()
			if result.State != "cancelled" || result.Reason != "protected_input_incomplete" {
				t.Fatalf("source fault reported as complete: %+v", result)
			}
			if data, err := os.ReadFile(marker); err != nil || string(data) != "prefix" {
				t.Fatal("fixture did not demonstrate the existing prefix effect")
			}
			status := m.Status(p.ExecutionId)
			if status.Result == nil || status.Result.Reason != result.Reason || !spool.file.closed {
				t.Fatal("incomplete result or encrypted spool cleanup was lost")
			}
			if _, err := protectedStart(m, p, "another-receipt"); !errors.Is(err, ErrAlreadyClaimed) {
				t.Fatal("partially effected execution became retryable")
			}
		})
	}
}

func TestProtectedScriptDeliveryDetectsBackingContentChange(t *testing.T) {
	m := testManager(t)
	spool := &deliverySpoolStore{open: func(data []byte) io.ReadCloser {
		data[0] = '#'
		return io.NopCloser(bytes.NewReader(data))
	}}
	m.spool = spool
	script := []byte("printf unchanged\n")
	p := protectedPrepare(t, m, "sh -s", script)
	uploadScript(t, m, p, script)
	run, err := protectedStart(m, p, "hub-verified-receipt")
	if err != nil {
		t.Fatal(err)
	}
	_, _, result := collect(t, run)
	if result.State != "cancelled" || result.Reason != "protected_input_incomplete" {
		t.Fatalf("changed backing input reported complete: %+v", result)
	}
}

func TestProtectedScriptIntentionalEarlyExitPreservesActualOutcome(t *testing.T) {
	m, _ := protectedManager(t)
	marker := filepath.Join(t.TempDir(), "unread-must-not-run")
	// More than pipe capacity guarantees that the shell exits while the agent
	// still has unread admitted input, exercising a real EPIPE rather than EOF.
	script := []byte("exit 42\n" + strings.Repeat("# unused admitted comment\n", 16384) + "touch '" + marker + "'\n")
	p := protectedPrepare(t, m, "sh -s", script)
	uploadScript(t, m, p, script)
	run, err := protectedStart(m, p, "hub-verified-receipt")
	if err != nil {
		t.Fatal(err)
	}
	_, _, result := collect(t, run)
	if result.State != "exited" || result.ExitCode != 42 || result.Reason != "" {
		t.Fatalf("intentional unread stdin changed actual exit: %+v", result)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unread tail had an effect")
	}
}

type blockedDeliveryReader struct {
	reading, closed     chan struct{}
	readOnce, closeOnce sync.Once
}

func (r *blockedDeliveryReader) Read([]byte) (int, error) {
	r.readOnce.Do(func() { close(r.reading) })
	<-r.closed
	return 0, os.ErrClosed
}
func (r *blockedDeliveryReader) Close() error {
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}

func TestProtectedScriptCancellationClosesBlockedSourceBeforeFinalization(t *testing.T) {
	m := testManager(t)
	reader := &blockedDeliveryReader{reading: make(chan struct{}), closed: make(chan struct{})}
	spool := &deliverySpoolStore{open: func([]byte) io.ReadCloser { return reader }}
	m.spool = spool
	script := []byte("printf must-not-be-delivered\n")
	p := protectedPrepare(t, m, "sh -s", script)
	uploadScript(t, m, p, script)
	run, err := protectedStart(m, p, "hub-verified-receipt")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-reader.reading:
	case <-time.After(time.Second):
		t.Fatal("source read did not block")
	}
	run.Cancel("control_transport_lost")
	_, _, result := collect(t, run)
	<-run.Done()
	if result.State != "cancelled" || result.Reason != "control_transport_lost" || !spool.file.closed {
		t.Fatalf("cancelled source retained resources or fabricated source fault: %+v", result)
	}
}
