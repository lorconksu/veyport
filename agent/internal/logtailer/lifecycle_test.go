package logtailer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func logDescriptorCount(t *testing.T, path string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		target, _ := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if target == path {
			count++
		}
	}
	return count
}

func TestTailCancellationUnderOutputBackpressureClosesFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux descriptor lifetime fixture")
	}
	for _, cancelKind := range []string{"context", "stop"} {
		t.Run(cancelKind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tail.log")
			os.WriteFile(path, []byte("initial data\n"), 0600)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := make(chan struct{})
			done := make(chan error, 1)
			go func() { done <- Tail(ctx, path, "", 1, make(chan *pb.AgentMessage), "tail", stop) }()
			deadline := time.Now().Add(time.Second)
			for logDescriptorCount(t, path) != 1 {
				if time.Now().After(deadline) {
					t.Fatal("tail did not open file")
				}
				time.Sleep(time.Millisecond)
			}
			// The next poll has output but no consumer. Cancellation must not need
			// a successful send to release the open descriptor.
			time.Sleep(pollInterval + 20*time.Millisecond)
			if cancelKind == "context" {
				cancel()
			} else {
				close(stop)
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) && !(cancelKind == "stop" && err == nil) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("blocked output stranded tail")
			}
			if logDescriptorCount(t, path) != 0 {
				t.Fatal("tail returned before closing descriptor")
			}
		})
	}
}

func TestReadFailuresAndCanceledRotationCloseResources(t *testing.T) {
	for _, fault := range []string{"missing", "closed", "directory", "rotation_read", "rotation_send"} {
		t.Run(fault, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "log")
			os.WriteFile(path, []byte("new bytes"), 0600)
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			offset := int64(0)
			switch fault {
			case "missing":
				os.Remove(path)
			case "closed":
				f.Close()
			case "directory", "rotation_read":
				os.Remove(path)
				os.Mkdir(path, 0700)
				if fault == "rotation_read" {
					offset = 1 << 20
				} else {
					f.Close()
					f, err = os.Open(path)
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
				}
			case "rotation_send":
				offset = 1 << 20
				cancel()
			}
			newF, _, err := readNewDataContext(ctx, f, path, offset, "", make(chan *pb.AgentMessage), "tail", nil)
			if err == nil || newF != nil {
				if newF != nil {
					newF.Close()
				}
				t.Fatal("read fault not terminal", fault, err)
			}
			if fault == "rotation_send" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if runtime.GOOS == "linux" && fault == "rotation_send" && logDescriptorCount(t, path) != 1 {
				t.Fatal("canceled rotation leaked replacement descriptor")
			}
		})
	}
}

func TestTailReadFailureIsTerminalAfterFileClose(t *testing.T) {
	path := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Tail(ctx, path, "", 1, make(chan *pb.AgentMessage, 1), "directory", nil); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("read error ignored", err)
	}
}

func TestTailPermissionDenialIsTerminal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged permission fixture")
	}
	path := filepath.Join(t.TempDir(), "unreadable")
	os.WriteFile(path, []byte("private"), 0000)
	if err := Tail(context.Background(), path, "", 0, make(chan *pb.AgentMessage, 1), "denied", nil); err == nil {
		t.Fatal("open failure ignored")
	}
}
