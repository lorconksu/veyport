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
	testLogFile = "test.log"
)

func TestTailNewLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testLogFile)
	os.WriteFile(path, []byte("line1\n"), 0644)

	sendCh := make(chan *pb.AgentMessage, 10)
	stop := make(chan struct{})

	go StartTail(path, "", 0, sendCh, "req-1", stop)

	// Wait for initial position, then append
	time.Sleep(100 * time.Millisecond)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString("line2\nline3\n")
	f.Close()

	// Wait for poll
	time.Sleep(700 * time.Millisecond)
	close(stop)

	// Should have received at least one chunk with new data
	found := false
	for len(sendCh) > 0 {
		msg := <-sendCh
		chunk := msg.GetLogStreamChunk()
		if chunk != nil && strings.Contains(string(chunk.Data), "line2") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected to receive chunk with 'line2'")
	}
}

func TestTailWithGrep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testLogFile)
	os.WriteFile(path, []byte(""), 0644)

	sendCh := make(chan *pb.AgentMessage, 10)
	stop := make(chan struct{})

	go StartTail(path, "error", 0, sendCh, "req-1", stop)

	time.Sleep(100 * time.Millisecond)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString("info: all good\nerror: something broke\nwarn: hmm\n")
	f.Close()

	time.Sleep(700 * time.Millisecond)
	close(stop)

	found := false
	for len(sendCh) > 0 {
		msg := <-sendCh
		chunk := msg.GetLogStreamChunk()
		if chunk != nil {
			data := string(chunk.Data)
			if strings.Contains(data, "error") && !strings.Contains(data, "info: all good") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected grep to filter to only error lines")
	}
}

func TestTailFileRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testLogFile)
	os.WriteFile(path, []byte("old content that is quite long\n"), 0644)

	sendCh := make(chan *pb.AgentMessage, 10)
	stop := make(chan struct{})

	go StartTail(path, "", 0, sendCh, "req-1", stop)

	time.Sleep(100 * time.Millisecond)

	// Simulate rotation: truncate and write new content
	os.WriteFile(path, []byte("new\n"), 0644)

	time.Sleep(700 * time.Millisecond)
	close(stop)

	found := false
	for len(sendCh) > 0 {
		msg := <-sendCh
		chunk := msg.GetLogStreamChunk()
		if chunk != nil && strings.Contains(string(chunk.Data), "new") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected to detect rotation and read new content")
	}
}

func TestTailStop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testLogFile)
	os.WriteFile(path, []byte("line1\n"), 0644)

	sendCh := make(chan *pb.AgentMessage, 10)
	stop := make(chan struct{})

	go StartTail(path, "", 0, sendCh, "req-1", stop)
	time.Sleep(100 * time.Millisecond)
	close(stop)
	time.Sleep(200 * time.Millisecond)

	// After stop, no more messages should be sent
	initialLen := len(sendCh)
	time.Sleep(700 * time.Millisecond)
	if len(sendCh) != initialLen {
		t.Fatal("expected no new messages after stop")
	}
}

func TestTailFileNotFound(t *testing.T) {
	sendCh := make(chan *pb.AgentMessage, 10)
	stop := make(chan struct{})

	go StartTail("/nonexistent/file.log", "", 0, sendCh, "req-1", stop)
	time.Sleep(200 * time.Millisecond)
	close(stop)

	// Should not panic, may send error chunk or nothing
}

func TestStartTail_InvalidPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"path traversal with ..", "/var/log/../../../etc/shadow"},
		{"relative path", "relative/path/file.log"},
		{"dot-dot only", ".."},
		{"hidden traversal", "/var/log/..hidden/../etc/passwd"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sendCh := make(chan *pb.AgentMessage, 10)
			stop := make(chan struct{})

			go StartTail(tc.path, "", 0, sendCh, "req-invalid", stop)

			// Wait for the validation to trigger
			time.Sleep(200 * time.Millisecond)
			close(stop)

			if len(sendCh) == 0 {
				t.Fatal("expected error message on sendCh for invalid path")
			}

			msg := <-sendCh
			chunk := msg.GetLogStreamChunk()
			if chunk == nil {
				t.Fatal("expected LogStreamChunk payload")
			}
			if chunk.RequestId != "req-invalid" {
				t.Fatalf("expected requestID 'req-invalid', got %q", chunk.RequestId)
			}
			if !strings.HasPrefix(string(chunk.Data), "error: ") {
				t.Fatalf("expected error message in data, got %q", string(chunk.Data))
			}
		})
	}
}

func TestValidateLogPath_BlockedPaths(t *testing.T) {
	tests := []struct {
		path      string
		shouldErr bool
	}{
		{"/etc/shadow", true},
		{"/etc/gshadow", true},
		{"/root/.ssh/authorized_keys", true},
		{"/proc/1/cmdline", true},
		{"/proc/kcore", true},
		{"/sys/kernel/security", true},
		{"/var/log/syslog", false},
		{"/var/log/auth.log", false},
	}
	for _, tt := range tests {
		_, err := validateLogPath(tt.path)
		if tt.shouldErr && err == nil {
			t.Errorf("validateLogPath(%q) should have returned error", tt.path)
		}
		if !tt.shouldErr && err != nil {
			t.Errorf("validateLogPath(%q) unexpected error: %v", tt.path, err)
		}
	}
}

func TestValidateLogPath_RejectsSymlinkEscape(t *testing.T) {
	allowedDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.log")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	linkPath := filepath.Join(allowedDir, "escape.log")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err := validateLogPath(linkPath)
	if err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
	if !strings.Contains(err.Error(), "outside requested directory") {
		t.Fatalf("expected symlink escape error, got %v", err)
	}
}
