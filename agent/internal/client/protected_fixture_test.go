package client

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/wyiu/veyport/proto/protectedinput"
)

// This executable test fixture exercises the real enrollment, Client transport,
// preparation, Manager process launch and cancellation through mTLS. Its memory
// storage dependency exists only in the Go test executable. Normal agent builds
// have no configuration flag or environment variable enabling fake encryption.
func TestProtectedExecutionEnrolledFixture(t *testing.T) {
	hub := os.Getenv("VEYPORT_TEST_PROTECTED_HUB")
	if hub == "" {
		t.Skip("subprocess fixture only")
	}
	dir := os.Getenv("VEYPORT_TEST_PROTECTED_DIR")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	c := New(Config{HubAddr: hub, Token: os.Getenv("VEYPORT_TEST_PROTECTED_TOKEN"), HubCAPin: os.Getenv("VEYPORT_TEST_PROTECTED_CAPIN"), Hostname: "protected-test-agent", CertDir: filepath.Join(dir, "tls"), DropzoneDir: filepath.Join(dir, "dropzone"), AgentVersion: "protected-test"})
	c.executionSpool = &fixtureSpools{}
	_ = c.Run(ctx)
}

type fixtureSpools struct {
	mu   sync.Mutex
	used int64
}

func (s *fixtureSpools) Ready() error                         { return nil }
func (s *fixtureSpools) Create() (protectedinput.File, error) { return &fixtureSpool{owner: s}, nil }

type fixtureSpool struct {
	mu             sync.Mutex
	owner          *fixtureSpools
	buffer         bytes.Buffer
	sealed, closed bool
}

func (f *fixtureSpool) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owner.mu.Lock()
	defer f.owner.mu.Unlock()
	if f.closed || f.sealed {
		return 0, io.ErrClosedPipe
	}
	if f.buffer.Len()+len(p) > protectedinput.MaxScriptBytes || f.owner.used+int64(len(p)) > protectedinput.MaxAggregateBytes {
		return 0, protectedinput.ErrLimit
	}
	n, err := f.buffer.Write(p)
	f.owner.used += int64(n)
	return n, err
}
func (f *fixtureSpool) Seal() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.sealed {
		return io.ErrClosedPipe
	}
	f.sealed = true
	return nil
}
func (f *fixtureSpool) Open() (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || !f.sealed {
		return nil, io.ErrClosedPipe
	}
	return io.NopCloser(bytes.NewReader(f.buffer.Bytes())), nil
}
func (f *fixtureSpool) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	f.owner.mu.Lock()
	f.owner.used -= int64(f.buffer.Len())
	f.owner.mu.Unlock()
	return nil
}
