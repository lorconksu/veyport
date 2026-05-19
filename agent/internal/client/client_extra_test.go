package client

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	testLogReqMsg = "log-req-msg"
)

// TestHandleFileListRequest_InvalidPath verifies file list for invalid path returns error response.
func TestHandleFileListRequest_InvalidPath(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{})}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage_FileListRequest{
		FileListRequest: &pb.FileListRequest{
			RequestId: "req-invalid",
			Path:      "/nonexistent/path/xyz123",
		},
	}
	c.handleFileListRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		listResp := resp.GetFileListResponse()
		if listResp == nil {
			t.Fatal("expected FileListResponse")
		}
		if listResp.RequestId != "req-invalid" {
			t.Fatalf("expected 'req-invalid', got '%s'", listResp.RequestId)
		}
		// Error should be set for nonexistent path
		if listResp.Error == "" {
			t.Fatal("expected error in response for nonexistent path")
		}
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

// TestHandleFileReadRequest_InvalidPath verifies file read for invalid path returns error response.
func TestHandleFileReadRequest_InvalidPath(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{})}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage_FileReadRequest{
		FileReadRequest: &pb.FileReadRequest{
			RequestId: "req-invalid-read",
			Path:      "/nonexistent/file.txt",
			Offset:    0,
			Limit:     100,
		},
	}
	c.handleFileReadRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		readResp := resp.GetFileReadResponse()
		if readResp == nil {
			t.Fatal("expected FileReadResponse")
		}
		if readResp.Error == "" {
			t.Fatal("expected error in response for nonexistent file")
		}
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

// TestHandleFileUploadRequest_MultipleChunks verifies multi-chunk upload works.
func TestHandleFileUploadRequest_MultipleChunks(t *testing.T) {
	dir := t.TempDir()
	c := &Client{
		tailSessions: make(map[string]chan struct{}),
		dropzone:     newTestDropzone(dir),
	}
	sendCh := make(chan *pb.AgentMessage, 5)

	// Send first chunk (not done)
	msg1 := &pb.HubMessage_FileUploadRequest{
		FileUploadRequest: &pb.FileUploadRequest{
			RequestId: "req-multi",
			Filename:  "multi.txt",
			Chunk:     []byte("hello "),
			Done:      false,
		},
	}
	c.handleFileUploadRequest(msg1, sendCh)

	// No ack yet — not done
	select {
	case msg := <-sendCh:
		t.Fatalf("should not get ack until done=true, got: %v", msg)
	default:
		// Expected: no ack yet
	}

	// Send second (final) chunk
	msg2 := &pb.HubMessage_FileUploadRequest{
		FileUploadRequest: &pb.FileUploadRequest{
			RequestId: "req-multi",
			Filename:  "",
			Chunk:     []byte("world"),
			Done:      true,
		},
	}
	c.handleFileUploadRequest(msg2, sendCh)

	select {
	case resp := <-sendCh:
		ack := resp.GetFileUploadAck()
		if ack == nil {
			t.Fatal("expected FileUploadAck")
		}
		if !ack.Success {
			t.Fatalf("expected success, got error: %s", ack.Error)
		}
	default:
		t.Fatal("expected ack on sendCh after done=true")
	}
}

// TestHandleFileDeleteRequest_PathTraversal verifies path traversal is blocked.
func TestHandleFileDeleteRequest_PathTraversal(t *testing.T) {
	dropzoneDir := t.TempDir()
	c := &Client{tailSessions: make(map[string]chan struct{}), dropzone: newTestDropzone(dropzoneDir)}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage_FileDeleteRequest{
		FileDeleteRequest: &pb.FileDeleteRequest{
			RequestId: "req-traversal",
			Path:      filepath.Join(dropzoneDir, "..", "..", "etc", "passwd"),
		},
	}
	c.handleFileDeleteRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		ack := resp.GetFileDeleteResponse()
		if ack == nil {
			t.Fatal("expected FileDeleteResponse")
		}
		// After path.Clean, this resolves to /etc/passwd which is NOT in dropzone
		if ack.Success {
			t.Fatal("expected failure for path traversal")
		}
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

// TestHandleMessage_FileRead verifies handleMessage dispatches file read requests.
func TestHandleMessage_FileRead(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-read-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("content")
	tmpFile.Close()

	c := &Client{tailSessions: make(map[string]chan struct{})}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage{
		Payload: &pb.HubMessage_FileReadRequest{
			FileReadRequest: &pb.FileReadRequest{
				RequestId: "req-read",
				Path:      tmpFile.Name(),
				Offset:    0,
				Limit:     100,
			},
		},
	}
	c.handleMessage(msg, sendCh)

	select {
	case <-sendCh:
		// ok
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

// TestHandleMessage_FileUpload verifies handleMessage dispatches upload requests.
func TestHandleMessage_FileUpload(t *testing.T) {
	dir := t.TempDir()
	c := &Client{
		tailSessions: make(map[string]chan struct{}),
		dropzone:     newTestDropzone(dir),
	}
	sendCh := make(chan *pb.AgentMessage, 2)

	msg := &pb.HubMessage{
		Payload: &pb.HubMessage_FileUploadRequest{
			FileUploadRequest: &pb.FileUploadRequest{
				RequestId: "req-upload-msg",
				Filename:  "msg-test.txt",
				Chunk:     []byte("data"),
				Done:      true,
			},
		},
	}
	c.handleMessage(msg, sendCh)

	select {
	case resp := <-sendCh:
		ack := resp.GetFileUploadAck()
		if ack == nil {
			t.Fatal("expected FileUploadAck")
		}
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

// TestHandleMessage_LogStreamRequest verifies handleMessage dispatches log stream requests.
func TestHandleMessage_LogStreamRequest(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-log-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("log content\n")
	tmpFile.Close()

	c := &Client{tailSessions: make(map[string]chan struct{})}
	sendCh := make(chan *pb.AgentMessage, 10)

	msg := &pb.HubMessage{
		Payload: &pb.HubMessage_LogStreamRequest{
			LogStreamRequest: &pb.LogStreamRequest{
				RequestId: testLogReqMsg,
				Path:      tmpFile.Name(),
				Grep:      "",
				Offset:    0,
			},
		},
	}
	c.handleMessage(msg, sendCh)

	// Verify session was registered
	if _, ok := c.tailSessions[testLogReqMsg]; !ok {
		t.Fatal("expected tail session to be registered")
	}

	// Cleanup
	close(c.tailSessions[testLogReqMsg])
	delete(c.tailSessions, testLogReqMsg)
}

func TestIsPathAllowed_RejectsSymlinkEscape(t *testing.T) {
	allowedRoot := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.log")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	linkPath := filepath.Join(allowedRoot, "escape.log")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if isPathAllowed(linkPath, []string{allowedRoot}) {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestIsPathAllowed_AllowsSymlinkWithinRoot(t *testing.T) {
	allowedRoot := t.TempDir()
	target := filepath.Join(allowedRoot, "app.log")
	if err := os.WriteFile(target, []byte("inside"), 0644); err != nil {
		t.Fatalf("write target file: %v", err)
	}

	linkPath := filepath.Join(allowedRoot, "current.log")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if !isPathAllowed(linkPath, []string{allowedRoot}) {
		t.Fatal("expected in-root symlink to be allowed")
	}
}

// TestNewClient_DefaultValues verifies client is initialized with sensible defaults.
func TestNewClient_DefaultValues(t *testing.T) {
	c := New(Config{
		HubAddr:      "hub.example.com:443",
		ServerID:     "srv-abc",
		Token:        "some-token",
		Hostname:     "web-prod-1",
		IPAddress:    "10.0.0.100",
		OS:           "Ubuntu 24.04",
		AgentVersion: "0.1.0",
	})

	if c.hubAddr != "hub.example.com:443" {
		t.Fatalf("expected hubAddr 'hub.example.com:443', got '%s'", c.hubAddr)
	}
	if c.serverID != "srv-abc" {
		t.Fatalf("expected serverID 'srv-abc', got '%s'", c.serverID)
	}
	if c.token != "some-token" {
		t.Fatalf("expected token 'some-token', got '%s'", c.token)
	}
	if c.backoff == 0 {
		t.Fatal("expected non-zero initial backoff")
	}
	if c.maxBackoff == 0 {
		t.Fatal("expected non-zero max backoff")
	}
}

// TestHandleFileListRequest_RootDir verifies listing a directory.
func TestHandleFileListRequest_RootDir(t *testing.T) {
	c := &Client{tailSessions: make(map[string]chan struct{})}
	sendCh := make(chan *pb.AgentMessage, 1)

	// Use t.TempDir() to avoid listing /tmp which can hang in CI
	dir := t.TempDir()
	os.WriteFile(dir+"/testfile.txt", []byte("hello"), 0644)

	msg := &pb.HubMessage_FileListRequest{
		FileListRequest: &pb.FileListRequest{
			RequestId: "req-root",
			Path:      dir,
		},
	}
	c.handleFileListRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		listResp := resp.GetFileListResponse()
		if listResp == nil {
			t.Fatal("expected FileListResponse")
		}
		if listResp.RequestId != "req-root" {
			t.Fatalf("expected 'req-root', got '%s'", listResp.RequestId)
		}
		if len(listResp.Files) == 0 {
			t.Fatal("expected at least one file in listing")
		}
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}

// TestHandleFileDeleteRequest_InDropzone_WithActualFile creates a real dropzone file and deletes it.
func TestHandleFileDeleteRequest_InDropzone_WithActualFile(t *testing.T) {
	dropzoneDir := t.TempDir()
	testFile := filepath.Join(dropzoneDir, "client-test-delete.txt")
	if err := os.WriteFile(testFile, []byte("delete me"), 0644); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	c := &Client{tailSessions: make(map[string]chan struct{}), dropzone: newTestDropzone(dropzoneDir)}
	sendCh := make(chan *pb.AgentMessage, 1)

	msg := &pb.HubMessage_FileDeleteRequest{
		FileDeleteRequest: &pb.FileDeleteRequest{
			RequestId: "req-del-real",
			Path:      testFile,
		},
	}
	c.handleFileDeleteRequest(msg, sendCh)

	select {
	case resp := <-sendCh:
		ack := resp.GetFileDeleteResponse()
		if ack == nil {
			t.Fatal("expected FileDeleteResponse")
		}
		if !ack.Success {
			t.Fatalf("expected success, got error: %s", ack.Error)
		}
	default:
		t.Fatal(testExpectedRespOnSendCh)
	}
}
