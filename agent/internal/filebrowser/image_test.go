package filebrowser

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStreamImageRejectsFileChangedInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mutating.png")
	if err := os.WriteFile(path, make([]byte, 256<<10), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = StreamImage(context.Background(), path, func(offset, _ int64, _ []byte) error {
		if offset != 0 {
			return nil
		}
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		if _, err := f.WriteAt([]byte("changed"), 128<<10); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return os.Chtimes(path, info.ModTime(), info.ModTime())
	})
	if !errors.Is(err, errImageRead) {
		t.Fatalf("same-size, restored-mtime change was treated as a complete image: %v", err)
	}
}

func TestStreamImageRejectsNonRegularFilesWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "stream.png")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := StreamImage(context.Background(), path, func(_ int64, _ int64, _ []byte) error {
			t.Error("non-regular file supplied bytes")
			return nil
		})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errImageRead) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("preview blocked opening a FIFO")
	}
}
