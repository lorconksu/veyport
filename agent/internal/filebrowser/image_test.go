package filebrowser

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/proto/fileview"
	"golang.org/x/sys/unix"
)

func TestStreamImagePathErrors(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "file.png")
	if err := os.WriteFile(regular, []byte("image"), 0600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		want error
	}{
		{name: "relative path", path: "file.png", want: ErrImageAccess},
		{name: "missing file", path: filepath.Join(dir, "missing.png"), want: errImageRead},
		{name: "regular file as directory", path: filepath.Join(regular, "child.png"), want: ErrImageAccess},
		{name: "directory", path: dir, want: errImageRead},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			size, err := StreamImage(context.Background(), test.path, func(_ int64, _ int64, _ []byte) error {
				t.Fatal("invalid image path emitted data")
				return nil
			})
			if size != 0 || !errors.Is(err, test.want) {
				t.Fatalf("StreamImage = (%d, %v), want (0, %v)", size, err, test.want)
			}
		})
	}
}

func TestStreamImageUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unreadable.png")
	if err := os.WriteFile(path, []byte("image"), 0000); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(path); err == nil {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		t.Skip("test process can read files without read permission")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}

	size, err := StreamImage(context.Background(), path, func(_ int64, _ int64, _ []byte) error {
		t.Fatal("unreadable image emitted data")
		return nil
	})
	if size != 0 || !errors.Is(err, ErrImageAccess) {
		t.Fatalf("StreamImage = (%d, %v), want (0, %v)", size, err, ErrImageAccess)
	}
}

func TestStreamImageChunkMetadataAndBytes(t *testing.T) {
	first := bytes.Repeat([]byte("a"), fileview.MaxChunkSize)
	last := []byte("tail")
	path := filepath.Join(t.TempDir(), "image.png")
	if err := os.WriteFile(path, append(first, last...), 0600); err != nil {
		t.Fatal(err)
	}
	chunks := []struct {
		offset int64
		data   []byte
	}{
		{offset: 0, data: first},
		{offset: fileview.MaxChunkSize, data: last},
	}
	wantSize := int64(len(first) + len(last))
	calls := 0
	size, err := StreamImage(context.Background(), path, func(offset, total int64, data []byte) error {
		if calls >= len(chunks) {
			t.Fatalf("unexpected chunk at offset %d", offset)
		}
		want := chunks[calls]
		calls++
		if offset != want.offset || total != wantSize || len(data) != len(want.data) {
			t.Fatalf("chunk %d metadata = (%d, %d, %d), want (%d, %d, %d)", calls,
				offset, total, len(data), want.offset, wantSize, len(want.data))
		}
		if !bytes.Equal(data, want.data) {
			t.Fatalf("chunk %d contains unexpected bytes", calls)
		}
		return nil
	})
	if size != wantSize || err != nil || calls != len(chunks) {
		t.Fatalf("StreamImage = (%d, %v) with %d chunks, want (%d, nil) with %d chunks",
			size, err, calls, wantSize, len(chunks))
	}
}

func TestStreamImageSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.png")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		size int64
		want error
	}{
		{name: "empty file", size: 0},
		{name: "at limit", size: fileview.MaxFileSize},
		{name: "one byte over limit", size: fileview.MaxFileSize + 1, want: ErrImageTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Truncate(path, test.size); err != nil {
				t.Fatal(err)
			}
			var emitted int64
			size, err := StreamImage(context.Background(), path, func(offset, total int64, data []byte) error {
				if test.want != nil {
					t.Fatal("oversized image emitted data")
				}
				if offset != emitted || total != test.size || len(data) == 0 || len(data) > fileview.MaxChunkSize {
					t.Fatalf("chunk metadata = (%d, %d, %d) after %d emitted bytes for file of size %d",
						offset, total, len(data), emitted, test.size)
				}
				emitted += int64(len(data))
				return nil
			})
			wantSize := test.size
			if test.want != nil {
				wantSize = 0
			}
			if size != wantSize || !errors.Is(err, test.want) || emitted != wantSize {
				t.Fatalf("StreamImage = (%d, %v) after emitting %d bytes, want (%d, %v) after emitting %d bytes",
					size, err, emitted, wantSize, test.want, wantSize)
			}
		})
	}
}

func TestStreamImageCancellation(t *testing.T) {
	for _, test := range []struct {
		name      string
		fileSize  int
		preCancel bool
		wantCalls int
	}{
		{name: "before opening", fileSize: 1, preCancel: true},
		{name: "between chunks", fileSize: fileview.MaxChunkSize + 1, wantCalls: 1},
		{name: "after final chunk", fileSize: 1, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "image.png")
			if err := os.WriteFile(path, make([]byte, test.fileSize), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.preCancel {
				cancel()
			}
			calls := 0
			size, err := StreamImage(ctx, path, func(_ int64, _ int64, _ []byte) error {
				calls++
				cancel()
				return nil
			})
			if size != 0 || !errors.Is(err, context.Canceled) || calls != test.wantCalls {
				t.Fatalf("StreamImage = (%d, %v) with %d chunks, want (0, %v) with %d chunks",
					size, err, calls, context.Canceled, test.wantCalls)
			}
		})
	}
}

func TestStreamImagePropagatesEmitError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.png")
	if err := os.WriteFile(path, make([]byte, fileview.MaxChunkSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("cannot accept image chunk")
	calls := 0
	size, err := StreamImage(context.Background(), path, func(_ int64, _ int64, _ []byte) error {
		calls++
		return want
	})
	if size != 0 || !errors.Is(err, want) || calls != 1 {
		t.Fatalf("StreamImage = (%d, %v) with %d chunks, want (0, %v) with one chunk", size, err, calls, want)
	}
}

func TestStreamImageStopsOnShortRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.png")
	if err := os.WriteFile(path, make([]byte, fileview.MaxChunkSize+2), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	size, err := StreamImage(context.Background(), path, func(_ int64, _ int64, _ []byte) error {
		calls++
		if calls == 1 {
			if err := os.Truncate(path, fileview.MaxChunkSize+1); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	if size != 0 || !errors.Is(err, errImageRead) || calls != 1 {
		t.Fatalf("StreamImage = (%d, %v) with %d chunks, want (0, %v) with one chunk",
			size, err, calls, errImageRead)
	}
}

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
