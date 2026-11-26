package filebrowser

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wyiu/veyport/proto/fileview"
	"golang.org/x/sys/unix"
)

var (
	ErrImageAccess   = errors.New("access denied")
	ErrImageTooLarge = errors.New("image exceeds the 10 MiB preview limit")
	errImageRead     = errors.New("cannot read complete image")
)

// StreamImage reads exactly the initial size from a single regular-file
// descriptor. Only the caller's success record makes provisional bytes usable.
func StreamImage(ctx context.Context, path string, emit func(offset, size int64, data []byte) error) (int64, error) {
	if err := validatePath(path); err != nil {
		return 0, ErrImageAccess
	}
	f, err := openImage(ctx, filepath.Clean(path))
	if err != nil {
		return 0, imageOpenError(err)
	}
	defer f.Close()

	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var initial unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &initial); err != nil {
		return 0, errImageRead
	}

	size := initial.Size
	if size > fileview.MaxFileSize {
		return 0, ErrImageTooLarge
	}
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		data := make([]byte, min(fileview.MaxChunkSize, size-offset))
		if _, err := io.ReadFull(f, data); err != nil {
			return 0, errImageRead
		}
		if err := emit(offset, size, data); err != nil {
			return 0, err
		}
		offset += int64(len(data))
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var final unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &final); err != nil || final.Size != size || final.Mtim != initial.Mtim || final.Ctim != initial.Ctim {
		return 0, errImageRead
	}
	return size, nil
}

// The file browser disallows symlink traversal. Walk using pinned directory
// descriptors and O_NOFOLLOW so a path swap cannot undo the access checks.
// Pin the final inode and check its type before opening it for reading.
func openImage(ctx context.Context, path string) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, component := range parts {
		if err := ctx.Err(); err != nil {
			_ = unix.Close(dir)
			return nil, err
		}
		flags := unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(dir, component, flags, 0)
		_ = unix.Close(dir)
		if err != nil {
			return nil, err
		}
		dir = next
	}
	defer unix.Close(dir)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var info unix.Stat_t
	if err := unix.Fstat(dir, &info); err != nil {
		return nil, err
	}
	switch info.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return nil, unix.ELOOP
	case unix.S_IFREG:
		// Reopen the pinned regular inode, never the original path. The
		// descriptor belongs to this process and remains open through Open.
	default:
		return nil, errImageRead
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(dir), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func imageOpenError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, os.ErrPermission) {
		return ErrImageAccess
	}
	return errImageRead
}
