package logtailer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	testExpectedLogStreamChunk = "expected LogStreamChunk"
	testExpectedMsgOnSendCh    = "expected message on sendCh"
)

// TestTailWithOffset verifies that starting at a positive offset skips earlier content.
func TestTailWithOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testLogFile)

	// Write initial content
	content := "old line\n"
	os.WriteFile(path, []byte(content), 0644)

	sendCh := make(chan *pb.AgentMessage, 10)
	stop := make(chan struct{})

	// Start from the END of file (offset = len(content)), then append
	go StartTail(path, "", int64(len(content)), sendCh, "req-offset", stop)

	time.Sleep(100 * time.Millisecond)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString("new line\n")
	f.Close()

	time.Sleep(700 * time.Millisecond)
	close(stop)

	found := false
	for len(sendCh) > 0 {
		msg := <-sendCh
		chunk := msg.GetLogStreamChunk()
		if chunk != nil && strings.Contains(string(chunk.Data), "new line") {
			found = true
		}
		// Should NOT contain "old line"
		if chunk != nil && strings.Contains(string(chunk.Data), "old line") {
			t.Error("should not have received old content after offset start")
		}
	}
	if !found {
		t.Fatal("expected to receive 'new line' chunk")
	}
}

// TestSendFiltered_NoGrepWithData verifies sendFiltered without grep sends all data.
func TestSendFiltered_NoGrepWithData(t *testing.T) {
	sendCh := make(chan *pb.AgentMessage, 5)
	data := []byte("line1\nline2\nline3\n")

	sendFiltered(data, int64(len(data)), "", sendCh, "req-1")

	select {
	case msg := <-sendCh:
		chunk := msg.GetLogStreamChunk()
		if chunk == nil {
			t.Fatal(testExpectedLogStreamChunk)
		}
		if string(chunk.Data) != string(data) {
			t.Fatalf("expected all data, got %q", string(chunk.Data))
		}
		if chunk.RequestId != "req-1" {
			t.Fatalf("expected request_id 'req-1', got %q", chunk.RequestId)
		}
	default:
		t.Fatal(testExpectedMsgOnSendCh)
	}
}

// TestSendFiltered_WithGrepNoMatches verifies sendFiltered with grep + no matches sends nothing.
func TestSendFiltered_WithGrepNoMatches(t *testing.T) {
	sendCh := make(chan *pb.AgentMessage, 5)
	data := []byte("info: all good\nwarn: maybe\n")

	sendFiltered(data, 27, "error", sendCh, "req-2")

	select {
	case msg := <-sendCh:
		t.Fatalf("expected no message when no grep matches, got: %v", msg)
	default:
		// Expected: no message
	}
}

// TestSendFiltered_EmptyData verifies sendFiltered with empty data sends nothing.
func TestSendFiltered_EmptyData(t *testing.T) {
	sendCh := make(chan *pb.AgentMessage, 5)

	sendFiltered([]byte{}, 0, "", sendCh, "req-3")

	select {
	case msg := <-sendCh:
		t.Fatalf("expected no message for empty data, got: %v", msg)
	default:
		// Expected: no message
	}
}

// TestSendFiltered_WithGrepMatches verifies sendFiltered filters correctly.
func TestSendFiltered_WithGrepMatches(t *testing.T) {
	sendCh := make(chan *pb.AgentMessage, 5)
	data := []byte("info: ok\nERROR: something bad\nwarn: hmm\nError: another\n")

	sendFiltered(data, int64(len(data)), "error", sendCh, "req-4")

	select {
	case msg := <-sendCh:
		chunk := msg.GetLogStreamChunk()
		if chunk == nil {
			t.Fatal(testExpectedLogStreamChunk)
		}
		result := string(chunk.Data)
		if !strings.Contains(result, "ERROR: something bad") {
			t.Fatalf("expected ERROR line, got: %q", result)
		}
		if !strings.Contains(result, "Error: another") {
			t.Fatalf("expected Error line, got: %q", result)
		}
		if strings.Contains(result, "info: ok") {
			t.Fatal("should not have included info line")
		}
	default:
		t.Fatal(testExpectedMsgOnSendCh)
	}
}

// TestReadNewData_NoChange verifies readNewData returns same offset when file unchanged.
func TestReadNewData_NoChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testLogFile)
	content := []byte("existing content\n")
	os.WriteFile(path, content, 0644)

	f, _ := os.Open(path)
	defer f.Close()

	// Start at end — no new data
	sendCh := make(chan *pb.AgentMessage, 5)
	_, newOffset := readNewData(f, path, int64(len(content)), "", sendCh, "req-1")

	if newOffset != int64(len(content)) {
		t.Fatalf("expected offset %d (unchanged), got %d", len(content), newOffset)
	}

	select {
	case msg := <-sendCh:
		t.Fatalf("expected no message when no new data, got: %v", msg)
	default:
		// Expected
	}
}

// TestReadNewData_NewContent verifies readNewData detects and sends new content.
func TestReadNewData_NewContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testLogFile)
	initial := []byte("first line\n")
	os.WriteFile(path, initial, 0644)

	f, _ := os.Open(path)
	defer f.Close()

	sendCh := make(chan *pb.AgentMessage, 5)

	// Append new data
	fAppend, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	fAppend.WriteString("second line\n")
	fAppend.Close()

	_, newOffset := readNewData(f, path, int64(len(initial)), "", sendCh, "req-1")

	if newOffset <= int64(len(initial)) {
		t.Fatalf("expected offset to advance past %d, got %d", len(initial), newOffset)
	}

	select {
	case msg := <-sendCh:
		chunk := msg.GetLogStreamChunk()
		if chunk == nil {
			t.Fatal(testExpectedLogStreamChunk)
		}
		if !strings.Contains(string(chunk.Data), "second line") {
			t.Fatalf("expected 'second line', got: %q", string(chunk.Data))
		}
	default:
		t.Fatal(testExpectedMsgOnSendCh)
	}
}

// TestIsBlockedPath verifies the isBlockedPath helper for various paths.
func TestIsBlockedPath(t *testing.T) {
	tests := []struct {
		path    string
		blocked bool
	}{
		{"/etc/shadow", true},
		{"/etc/shadow/subdir", true},
		{"/etc/gshadow", true},
		{"/etc/sudoers", true},
		{"/etc/sudoers.d/myconfig", true},
		{"/etc/veyport", true},
		{"/etc/veyport/config.yaml", true},
		{"/root/.ssh", true},
		{"/root/.ssh/authorized_keys", true},
		{"/proc/self", true},
		{"/proc/self/environ", true},
		{"/proc/kcore", true},
		{"/sys/firmware", true},
		{"/sys/firmware/efi", true},
		// Blocked prefixes
		{"/proc/1/cmdline", true},
		{"/proc/123/status", true},
		{"/sys/kernel/security", true},
		{"/sys/kernel/debug", true},
		// Allowed paths
		{"/var/log/syslog", false},
		{"/var/log/auth.log", false},
		{"/tmp/test.log", false},
		{"/etc/hostname", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isBlockedPath(tt.path)
			if got != tt.blocked {
				t.Errorf("isBlockedPath(%q) = %v, want %v", tt.path, got, tt.blocked)
			}
		})
	}
}

// TestReadNewData_MissingFile verifies readNewData handles a missing file gracefully.
func TestReadNewData_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.log")

	// Create and then delete the file
	os.WriteFile(path, []byte("content\n"), 0644)
	f, _ := os.Open(path)
	defer f.Close()
	os.Remove(path)

	sendCh := make(chan *pb.AgentMessage, 5)
	_, newOffset := readNewData(f, path, 100, "", sendCh, "req-1")

	// Should return same offset or handle gracefully
	_ = newOffset
}
