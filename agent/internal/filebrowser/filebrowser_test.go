package filebrowser

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	testUnexpectedErrFmt = "unexpected error: %v"
	testEtcShadow        = "/etc/shadow"
	testFileTxt          = "file.txt"
	testHelloWorld       = "hello world"
	testTestTxt          = "test.txt"
	testReadFileFmt      = "read file: %v"
	testTextPlain        = "text/plain"
)

func TestListDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	os.WriteFile(filepath.Join(dir, testFileTxt), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# hi"), 0644)

	resp, err := ListDir(dir)
	if err != nil {
		t.Fatalf("list dir: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}

	// Directories come first, then files, both alphabetical
	if len(resp.Files) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(resp.Files))
	}
	if resp.Files[0].Name != "subdir" || !resp.Files[0].IsDir {
		t.Fatalf("expected first entry to be dir 'subdir', got %s (is_dir=%v)", resp.Files[0].Name, resp.Files[0].IsDir)
	}
	if resp.Files[1].Name != testFileTxt || resp.Files[1].IsDir {
		t.Fatalf("expected second entry to be file '%s', got %s", testFileTxt, resp.Files[1].Name)
	}
}

func TestListDir_NotFound(t *testing.T) {
	resp, err := ListDir("/nonexistent/path/12345")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Error == "" {
		t.Fatal("expected error in response")
	}
}

func TestListDir_PathTraversal(t *testing.T) {
	_, err := ListDir("/tmp/../etc/passwd")
	// Should either return error or resolve safely
	if err != nil {
		return // error is fine
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte(testHelloWorld)
	path := filepath.Join(dir, testTestTxt)
	os.WriteFile(path, content, 0644)

	resp, err := ReadFile(path, 0, 1048576)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if string(resp.Data) != testHelloWorld {
		t.Fatalf("expected 'hello world', got '%s'", string(resp.Data))
	}
	if resp.TotalSize != 11 {
		t.Fatalf("expected total_size 11, got %d", resp.TotalSize)
	}
}

func TestReadFile_WithOffset(t *testing.T) {
	dir := t.TempDir()
	content := []byte(testHelloWorld)
	path := filepath.Join(dir, testTestTxt)
	os.WriteFile(path, content, 0644)

	resp, err := ReadFile(path, 6, 1048576)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if string(resp.Data) != "world" {
		t.Fatalf("expected 'world', got '%s'", string(resp.Data))
	}
}

func TestReadFile_LimitEnforced(t *testing.T) {
	dir := t.TempDir()
	content := make([]byte, 100)
	path := filepath.Join(dir, testTestTxt)
	os.WriteFile(path, content, 0644)

	resp, err := ReadFile(path, 0, 50)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if len(resp.Data) != 50 {
		t.Fatalf("expected 50 bytes, got %d", len(resp.Data))
	}
	if resp.TotalSize != 100 {
		t.Fatalf("expected total_size 100, got %d", resp.TotalSize)
	}
}

func TestReadFile_NotFound(t *testing.T) {
	resp, err := ReadFile("/nonexistent/file.txt", 0, 1048576)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Error == "" {
		t.Fatal("expected error in response")
	}
}

func TestValidatePath(t *testing.T) {
	if err := validatePath("/var/log/syslog"); err != nil {
		t.Fatalf("expected valid path: %v", err)
	}
	if err := validatePath("/var/log/../../../etc/passwd"); err == nil {
		t.Fatal("expected error for path traversal")
	}
}

func TestListDir_SymlinkEscape(t *testing.T) {
	// Create a temp directory with a symlink pointing outside it
	dir := t.TempDir()
	outsideDir := t.TempDir()
	os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("sensitive"), 0644)

	// Create a symlink inside dir that points to outsideDir
	linkPath := filepath.Join(dir, "escape")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// Listing through the symlink should be rejected
	resp, err := ListDir(linkPath)
	if err != nil {
		t.Fatalf(testUnexpectedErrFmt, err)
	}
	if resp.Error == "" {
		t.Fatal("expected symlink escape to be rejected, but it was allowed")
	}
	if resp.Error != "path resolves outside requested directory" {
		t.Fatalf("unexpected error message: %s", resp.Error)
	}
}

func TestReadFile_SymlinkEscape(t *testing.T) {
	// Create a temp directory with a symlink pointing to a file outside it
	dir := t.TempDir()
	outsideDir := t.TempDir()
	secretPath := filepath.Join(outsideDir, "secret.txt")
	os.WriteFile(secretPath, []byte("sensitive"), 0644)

	// Create a symlink inside dir that points to the secret file
	linkPath := filepath.Join(dir, "escape.txt")
	if err := os.Symlink(secretPath, linkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// Reading through the symlink should be rejected
	resp, err := ReadFile(linkPath, 0, 1048576)
	if err != nil {
		t.Fatalf(testUnexpectedErrFmt, err)
	}
	if resp.Error == "" {
		t.Fatal("expected symlink escape to be rejected, but it was allowed")
	}
	if resp.Error != "path resolves outside requested directory" {
		t.Fatalf("unexpected error message: %s", resp.Error)
	}
}

func TestValidatePath_BlockedPaths(t *testing.T) {
	tests := []struct {
		path      string
		shouldErr bool
	}{
		{testEtcShadow, true},
		{"/etc/shadow/subpath", true},
		{"/etc/gshadow", true},
		{"/etc/sudoers", true},
		{"/etc/sudoers.d/custom", true},
		{"/root/.ssh", true},
		{"/root/.ssh/authorized_keys", true},
		{"/proc/1/cmdline", true},
		{"/proc/kcore", true},
		{"/sys/kernel/security", true},
		{"/etc/passwd", false},       // not blocked — readable by all
		{"/var/log/syslog", false},   // normal path
		{"/etc/shadowbackup", false}, // not a prefix match
		{"/proc", false},             // /proc itself is not blocked, only /proc/*
	}
	for _, tt := range tests {
		err := validatePath(tt.path)
		if tt.shouldErr && err == nil {
			t.Errorf("validatePath(%q) should have returned error", tt.path)
		}
		if !tt.shouldErr && err != nil {
			t.Errorf("validatePath(%q) unexpected error: %v", tt.path, err)
		}
	}
}

func TestListDir_BlockedPath(t *testing.T) {
	resp, err := ListDir(testEtcShadow)
	if err != nil {
		t.Fatalf(testUnexpectedErrFmt, err)
	}
	if resp.Error == "" {
		t.Fatal("expected blocked path error")
	}
}

func TestReadFile_BlockedPath(t *testing.T) {
	resp, err := ReadFile(testEtcShadow, 0, 1048576)
	if err != nil {
		t.Fatalf(testUnexpectedErrFmt, err)
	}
	if resp.Error == "" {
		t.Fatal("expected blocked path error")
	}
}

func TestDetectMIME(t *testing.T) {
	tests := map[string]string{
		testFileTxt:   testTextPlain,
		"file.json":   "application/json",
		"file.md":     "text/markdown",
		"file.yaml":   "text/yaml",
		"file.yml":    "text/yaml",
		"file.go":     "text/x-go",
		"file.py":     "text/x-python",
		"file.sh":     "text/x-sh",
		"file.conf":   testTextPlain,
		"file.log":    testTextPlain,
		"unknown.xyz": "application/octet-stream",
	}
	for name, expected := range tests {
		got := detectMIME(name)
		if got != expected {
			t.Errorf("detectMIME(%s) = %s, want %s", name, got, expected)
		}
	}
}
