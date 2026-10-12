package logtailer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const pollInterval = 500 * time.Millisecond

const errPathRestricted = "access to this path is restricted"

// blockedPaths are sensitive system paths that the log tailer must never read.
var blockedPaths = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/veyport",
	"/root/.ssh",
	"/proc/self",
	"/proc/kcore",
	"/sys/firmware",
}

var blockedPrefixes = []string{
	"/proc/",
	"/sys/kernel/",
}

// isBlockedPath checks whether the given path matches any entry in the
// blocklist or starts with a blocked prefix.
func isBlockedPath(path string) bool {
	for _, blocked := range blockedPaths {
		if path == blocked || strings.HasPrefix(path, blocked+"/") {
			return true
		}
	}
	for _, prefix := range blockedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func validateLogPath(path string) (string, error) {
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("path traversal not allowed")
	}
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("path must be absolute")
	}
	if isBlockedPath(cleaned) {
		return "", fmt.Errorf(errPathRestricted)
	}
	// Resolve symlinks to prevent reading sensitive files via symlink
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path")
	}
	if isBlockedPath(resolved) {
		return "", fmt.Errorf(errPathRestricted)
	}
	if resolved != cleaned && !strings.HasPrefix(resolved, cleaned+"/") {
		return "", fmt.Errorf("path resolves outside requested directory")
	}
	return resolved, nil
}

// StartTail opens a file, seeks to offset (0 = end of file), and polls for new data.
// Matching lines (if grep is non-empty) are sent as LogStreamChunk messages.
// Stops when the stop channel is closed.
func StartTail(path string, grep string, offset int64, sendCh chan<- *pb.AgentMessage, requestID string, stop <-chan struct{}) {
	if err := Tail(context.Background(), path, grep, offset, sendCh, requestID, stop); err != nil {
		_ = sendChunk(context.Background(), sendCh, requestID, []byte("error: "+err.Error()), 0, stop)
	}
}

// Tail returns only after closing its file; every output send is cancellable.
func Tail(ctx context.Context, path string, grep string, offset int64, sendCh chan<- *pb.AgentMessage, requestID string, stop <-chan struct{}) error {
	resolved, err := validateLogPath(path)
	if err != nil {
		return err
	}

	f, err := os.Open(resolved)
	if err != nil {
		log.Printf("logtailer: cannot open %s: %v", path, err)
		return fmt.Errorf("cannot open log file")
	}
	defer func() { f.Close() }()

	// Seek to position
	if offset <= 0 {
		// Seek to end
		pos, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			log.Printf("logtailer: seek error: %v", err)
			return fmt.Errorf("cannot seek log file")
		}
		offset = pos
	} else {
		_, err := f.Seek(offset, io.SeekStart)
		if err != nil {
			log.Printf("logtailer: seek error: %v", err)
			return fmt.Errorf("cannot seek log file")
		}
	}

	grepLower := strings.ToLower(grep)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stop:
			return nil
		case <-ticker.C:
			var newF *os.File
			newF, offset, err = readNewDataContext(ctx, f, resolved, offset, grepLower, sendCh, requestID, stop)
			if newF != nil {
				f.Close()
				f = newF
			}
			if err != nil {
				return err
			}
		}
	}
}

// readNewData checks for new data in the file and sends it through sendCh.
// Returns a new *os.File (non-nil) when file rotation is detected so the caller
// can replace the old handle, plus the updated offset.
func readNewData(f *os.File, path string, lastOffset int64, grepLower string, sendCh chan<- *pb.AgentMessage, requestID string) (*os.File, int64) {
	newF, offset, _ := readNewDataContext(context.Background(), f, path, lastOffset, grepLower, sendCh, requestID, nil)
	return newF, offset
}

func readNewDataContext(ctx context.Context, f *os.File, path string, lastOffset int64, grepLower string, sendCh chan<- *pb.AgentMessage, requestID string, stop <-chan struct{}) (*os.File, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, lastOffset, fmt.Errorf("cannot stat log file")
	}

	currentSize := info.Size()

	// File rotation detection: file got smaller
	if currentSize < lastOffset {
		// Reopen file (it may have been replaced)
		newF, err := os.Open(path)
		if err != nil {
			return nil, lastOffset, fmt.Errorf("cannot reopen log file")
		}
		// Read from beginning of new file, capped to 1MB to prevent memory exhaustion.
		data, err := io.ReadAll(io.LimitReader(newF, 1<<20))
		if err != nil {
			newF.Close()
			return nil, lastOffset, fmt.Errorf("cannot read log file")
		}
		if err := sendFilteredContext(ctx, data, currentSize, grepLower, sendCh, requestID, stop); err != nil {
			newF.Close()
			return nil, lastOffset, err
		}
		// Return new file handle to the caller so it replaces the old one
		return newF, currentSize, nil
	}

	if currentSize == lastOffset {
		return nil, lastOffset, nil // No new data
	}

	// Seek to last position and read new data (cap at 1MB per poll)
	if _, err := f.Seek(lastOffset, io.SeekStart); err != nil {
		return nil, lastOffset, fmt.Errorf("cannot seek log file")
	}
	readSize := currentSize - lastOffset
	if readSize > 1<<20 {
		readSize = 1 << 20
	}
	data := make([]byte, readSize)
	n, err := f.Read(data)
	if err != nil && err != io.EOF {
		return nil, lastOffset, fmt.Errorf("cannot read log file")
	}
	if n == 0 {
		return nil, lastOffset, nil
	}

	data = data[:n]
	newOffset := lastOffset + int64(n)

	err = sendFilteredContext(ctx, data, newOffset, grepLower, sendCh, requestID, stop)
	return nil, newOffset, err
}

func sendFiltered(data []byte, offset int64, grepLower string, sendCh chan<- *pb.AgentMessage, requestID string) {
	_ = sendFilteredContext(context.Background(), data, offset, grepLower, sendCh, requestID, nil)
}

func sendFilteredContext(ctx context.Context, data []byte, offset int64, grepLower string, sendCh chan<- *pb.AgentMessage, requestID string, stop <-chan struct{}) error {
	var outData []byte

	if grepLower == "" {
		outData = data
	} else {
		// Filter lines using bytes.NewReader to avoid string conversions
		scanner := bufio.NewScanner(bytes.NewReader(data))
		var buf bytes.Buffer
		for scanner.Scan() {
			line := scanner.Bytes()
			if strings.Contains(strings.ToLower(string(line)), grepLower) {
				buf.Write(line)
				buf.WriteByte('\n')
			}
		}
		if buf.Len() == 0 {
			return nil
		}
		outData = buf.Bytes()
	}

	if len(outData) == 0 {
		return nil
	}
	return sendChunk(ctx, sendCh, requestID, outData, offset, stop)
}

func sendChunk(ctx context.Context, sendCh chan<- *pb.AgentMessage, requestID string, data []byte, offset int64, stop <-chan struct{}) error {
	message := &pb.AgentMessage{
		Payload: &pb.AgentMessage_LogStreamChunk{
			LogStreamChunk: &pb.LogStreamChunk{
				RequestId: requestID,
				Data:      data,
				Offset:    offset,
			},
		},
	}
	select {
	case sendCh <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-stop:
		return context.Canceled
	}
}
