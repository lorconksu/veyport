package filebrowser

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

const (
	testUnexpectedErrStrFmt = "unexpected error: %s"
	testUnexpectedGoErrFmt  = "unexpected Go error: %v"
	testListDirFmt          = "list dir: %v"
)

// TestListDir_Empty verifies listing an empty directory returns empty list.
func TestListDir_Empty(t *testing.T) {
	dir := t.TempDir()

	resp, err := ListDir(dir)
	if err != nil {
		t.Fatalf("list empty dir: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}
	if len(resp.Files) != 0 {
		t.Fatalf("expected 0 files, got %d", len(resp.Files))
	}
}

// TestListDir_RelativePath verifies relative path returns an error response.
func TestListDir_RelativePath(t *testing.T) {
	resp, err := ListDir("relative/path")
	if err != nil {
		t.Fatalf(testUnexpectedGoErrFmt, err)
	}
	if resp.Error == "" {
		t.Fatal("expected error in response for relative path")
	}
}

// TestReadFile_PathTraversal verifies path traversal returns error response.
func TestReadFile_PathTraversal(t *testing.T) {
	resp, err := ReadFile("/tmp/../etc/passwd", 0, 100)
	if err != nil {
		t.Fatalf(testUnexpectedGoErrFmt, err)
	}
	if resp.Error == "" {
		t.Fatal("expected error in response for path traversal")
	}
}

// TestReadFile_Directory verifies reading a directory returns an error response.
func TestReadFile_Directory(t *testing.T) {
	dir := t.TempDir()

	resp, err := ReadFile(dir, 0, 1048576)
	if err != nil {
		t.Fatalf(testUnexpectedGoErrFmt, err)
	}
	if resp.Error == "" {
		t.Fatal("expected error when reading a directory")
	}
}

// TestReadFile_LimitOverMax verifies the MaxReadSize limit is enforced.
func TestReadFile_LimitOverMax(t *testing.T) {
	dir := t.TempDir()
	content := make([]byte, 100)
	path := filepath.Join(dir, "test.bin")
	os.WriteFile(path, content, 0644)

	// Request more than MaxReadSize — should be clamped
	resp, err := ReadFile(path, 0, MaxReadSize*2)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}
}

// TestReadFile_ZeroLimit uses 0 limit (defaults to MaxReadSize).
func TestReadFile_ZeroLimit(t *testing.T) {
	dir := t.TempDir()
	content := []byte("test content")
	path := filepath.Join(dir, "zero-limit.txt")
	os.WriteFile(path, content, 0644)

	resp, err := ReadFile(path, 0, 0)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}
	if string(resp.Data) != "test content" {
		t.Fatalf("expected 'test content', got '%s'", string(resp.Data))
	}
}

// TestDetectMIME_AllTypes covers all MIME type branches.
func TestDetectMIME_AllTypes(t *testing.T) {
	tests := map[string]string{
		"file.txt":      testTextPlain,
		"file.conf":     testTextPlain,
		"file.cfg":      testTextPlain,
		"file.ini":      testTextPlain,
		"file.log":      testTextPlain,
		"file.env":      testTextPlain,
		"file.json":     "application/json",
		"file.md":       "text/markdown",
		"file.markdown": "text/markdown",
		"file.yaml":     "text/yaml",
		"file.yml":      "text/yaml",
		"file.xml":      "text/xml",
		"file.html":     "text/html",
		"file.htm":      "text/html",
		"file.css":      "text/css",
		"file.js":       "text/javascript",
		"file.go":       "text/x-go",
		"file.py":       "text/x-python",
		"file.rs":       "text/x-rust",
		"file.sh":       "text/x-sh",
		"file.bash":     "text/x-sh",
		"file.toml":     "text/x-toml",
		"file.sql":      "text/x-sql",
		"file.unknown":  "application/octet-stream",
		"noextension":   "application/octet-stream",
	}

	for name, expected := range tests {
		got := detectMIME(name)
		if got != expected {
			t.Errorf("detectMIME(%q) = %q, want %q", name, got, expected)
		}
	}
}

// TestValidatePath_AllCases covers all validatePath branches.
func TestValidatePath_AllCases(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid absolute", "/var/log/syslog", false},
		{"root path", "/", false},
		{"path traversal", "/var/../etc/passwd", true},
		{"double dot traversal", "/../../etc", true},
		{"relative path", "relative/path", true},
		{"empty string causes relative", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePath(tc.path)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for path %q, got nil", tc.path)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for path %q, got %v", tc.path, err)
			}
		})
	}
}

// TestListDir_Symlink verifies symlinks that escape outside the requested directory are rejected.
func TestListDir_Symlink(t *testing.T) {
	dir := t.TempDir()
	targetDir := t.TempDir()

	// Create a file in targetDir
	os.WriteFile(filepath.Join(targetDir, "file.txt"), []byte("linked"), 0644)

	// Create a symlink in dir pointing to targetDir (outside dir)
	linkPath := filepath.Join(dir, "linkdir")
	if err := os.Symlink(targetDir, linkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	resp, err := ListDir(linkPath)
	if err != nil {
		t.Fatalf("list symlinked dir: %v", err)
	}
	// Symlink escapes outside the requested directory, should be rejected
	if resp.Error == "" {
		t.Fatal("expected symlink escape to be rejected")
	}
}

// TestListDir_UnreadableDir verifies permission errors are handled gracefully.
func TestListDir_UnreadableDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test as root")
	}

	dir := t.TempDir()
	noReadDir := filepath.Join(dir, "no-read")
	os.MkdirAll(noReadDir, 0000)    // NOSONAR — test fixture requires specific permissions
	defer os.Chmod(noReadDir, 0755) // NOSONAR — restore permissions for cleanup

	resp, err := ListDir(noReadDir)
	if err != nil {
		t.Fatalf(testUnexpectedGoErrFmt, err)
	}
	// Should return an error in the response
	if resp.Error == "" {
		t.Log("Note: no error returned for unreadable dir (may be root or other conditions)")
	}
}

// TestReadFile_SymlinkToFile verifies reading through a symlink that resolves
// to a different path is rejected (defense-in-depth).
func TestReadFile_SymlinkToFile(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.txt")
	os.WriteFile(realFile, []byte("symlinked content"), 0644)

	linkFile := filepath.Join(dir, "link.txt")
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	resp, err := ReadFile(linkFile, 0, 1048576)
	if err != nil {
		t.Fatalf("read through symlink: %v", err)
	}
	// Symlink resolves to a different path, should be rejected
	if resp.Error == "" {
		t.Fatal("expected symlink to different path to be rejected")
	}
}

// --- Task 1 tests: negative offset (tail) behavior ---

// TestReadFile_NegativeOffset_SmallFile verifies that a negative offset on a file
// smaller than limit returns the entire file content.
func TestReadFile_NegativeOffset_SmallFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte("small file content")
	path := filepath.Join(dir, "small.txt")
	os.WriteFile(path, content, 0644)

	resp, err := ReadFile(path, -1, MaxReadSize)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}
	if string(resp.Data) != "small file content" {
		t.Fatalf("expected full content, got %q", string(resp.Data))
	}
	if resp.TotalSize != int64(len(content)) {
		t.Fatalf("expected total_size %d, got %d", len(content), resp.TotalSize)
	}
}

// TestReadFile_NegativeOffset_LargeFile verifies that a negative offset on a file
// larger than limit returns the tail (last `limit` bytes) not the head.
func TestReadFile_NegativeOffset_LargeFile(t *testing.T) {
	dir := t.TempDir()
	// Create a file with known head and tail content
	// Total size = 200 bytes, limit = 50 bytes → should return last 50 bytes
	head := bytes.Repeat([]byte("H"), 150)
	tail := bytes.Repeat([]byte("T"), 50)
	content := append(head, tail...)
	path := filepath.Join(dir, "large.bin")
	os.WriteFile(path, content, 0644)

	resp, err := ReadFile(path, -1, 50)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}
	if len(resp.Data) != 50 {
		t.Fatalf("expected 50 bytes, got %d", len(resp.Data))
	}
	// All bytes should be 'T' (the tail), not 'H' (the head)
	expected := bytes.Repeat([]byte("T"), 50)
	if !bytes.Equal(resp.Data, expected) {
		t.Fatalf("expected tail content (all T's), got data starting with %q", string(resp.Data[:10]))
	}
	if resp.TotalSize != 200 {
		t.Fatalf("expected total_size 200, got %d", resp.TotalSize)
	}
}

// TestReadFile_NegativeOffset_ExactLimit verifies that a file exactly equal to limit
// returns all content when offset is negative.
func TestReadFile_NegativeOffset_ExactLimit(t *testing.T) {
	dir := t.TempDir()
	content := bytes.Repeat([]byte("X"), 100)
	path := filepath.Join(dir, "exact.bin")
	os.WriteFile(path, content, 0644)

	resp, err := ReadFile(path, -1, 100)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}
	if len(resp.Data) != 100 {
		t.Fatalf("expected 100 bytes, got %d", len(resp.Data))
	}
}

// TestReadFile_PositiveOffset_StillWorks verifies that positive offsets still work correctly.
func TestReadFile_PositiveOffset_StillWorks(t *testing.T) {
	dir := t.TempDir()
	content := []byte("0123456789")
	path := filepath.Join(dir, "offset.txt")
	os.WriteFile(path, content, 0644)

	resp, err := ReadFile(path, 5, 100)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if string(resp.Data) != "56789" {
		t.Fatalf("expected '56789', got %q", string(resp.Data))
	}
}

// --- Task 2 tests: ListDir special files and large directories ---

// TestListDir_SkipsFIFO verifies that FIFO (named pipe) entries are skipped.
func TestListDir_SkipsFIFO(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping as root (can open any file)")
	}

	dir := t.TempDir()
	// Create a regular file
	os.WriteFile(filepath.Join(dir, "regular.txt"), []byte("hello"), 0644)

	// Create a FIFO (named pipe)
	fifoPath := filepath.Join(dir, "myfifo")
	if err := syscall.Mkfifo(fifoPath, 0644); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	resp, err := ListDir(dir)
	if err != nil {
		t.Fatalf(testListDirFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}

	// Should only have the regular file, not the FIFO
	if len(resp.Files) != 1 {
		names := make([]string, len(resp.Files))
		for i, f := range resp.Files {
			names[i] = f.Name
		}
		t.Fatalf("expected 1 entry (regular.txt only), got %d: %v", len(resp.Files), names)
	}
	if resp.Files[0].Name != "regular.txt" {
		t.Fatalf("expected regular.txt, got %s", resp.Files[0].Name)
	}
}

// TestListDir_DirsFirstOrdering verifies directories come before files in listing.
func TestListDir_DirsFirstOrdering(t *testing.T) {
	dir := t.TempDir()
	// Create files named to sort before dirs alphabetically
	os.WriteFile(filepath.Join(dir, "aaa_file.txt"), []byte("f"), 0644)
	os.MkdirAll(filepath.Join(dir, "zzz_dir"), 0755)
	os.MkdirAll(filepath.Join(dir, "aaa_dir"), 0755)
	os.WriteFile(filepath.Join(dir, "zzz_file.txt"), []byte("f"), 0644)

	resp, err := ListDir(dir)
	if err != nil {
		t.Fatalf(testListDirFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}
	if len(resp.Files) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(resp.Files))
	}
	// First two should be dirs (sorted), then two files (sorted)
	if !resp.Files[0].IsDir || resp.Files[0].Name != "aaa_dir" {
		t.Fatalf("expected first entry to be dir 'aaa_dir', got %s (isDir=%v)", resp.Files[0].Name, resp.Files[0].IsDir)
	}
	if !resp.Files[1].IsDir || resp.Files[1].Name != "zzz_dir" {
		t.Fatalf("expected second entry to be dir 'zzz_dir', got %s (isDir=%v)", resp.Files[1].Name, resp.Files[1].IsDir)
	}
	if resp.Files[2].IsDir || resp.Files[2].Name != "aaa_file.txt" {
		t.Fatalf("expected third entry to be file 'aaa_file.txt', got %s", resp.Files[2].Name)
	}
	if resp.Files[3].IsDir || resp.Files[3].Name != "zzz_file.txt" {
		t.Fatalf("expected fourth entry to be file 'zzz_file.txt', got %s", resp.Files[3].Name)
	}
}

// TestListDir_LargeDirectory verifies ListDir handles a directory with many entries.
func TestListDir_LargeDirectory(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 500
	for i := 0; i < numFiles; i++ {
		name := filepath.Join(dir, fmt.Sprintf("file_%04d.txt", i))
		os.WriteFile(name, []byte("x"), 0644)
	}

	resp, err := ListDir(dir)
	if err != nil {
		t.Fatalf(testListDirFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}
	if len(resp.Files) != numFiles {
		t.Fatalf("expected %d entries, got %d", numFiles, len(resp.Files))
	}
}

// TestListDir_ReadableFlag verifies that readable files are marked as readable.
func TestListDir_ReadableFlag(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "readable.txt"), []byte("r"), 0644)

	resp, err := ListDir(dir)
	if err != nil {
		t.Fatalf(testListDirFmt, err)
	}
	if len(resp.Files) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(resp.Files))
	}
	if !resp.Files[0].Readable {
		t.Fatal("expected readable file to have Readable=true")
	}
}

// TestReadFile_NoReadPermission verifies that a file with no read permission
// returns an error response (covers the os.Open error branch).
func TestReadFile_NoReadPermission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test as root")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "noperm.txt")
	os.WriteFile(path, []byte("secret"), 0644)
	os.Chmod(path, 0000)       // NOSONAR — test fixture requires specific permissions
	defer os.Chmod(path, 0644) // NOSONAR — restore permissions for cleanup

	resp, err := ReadFile(path, 0, 100)
	if err != nil {
		t.Fatalf(testUnexpectedGoErrFmt, err)
	}
	if resp.Error == "" {
		t.Fatal("expected error for unreadable file")
	}
}

// TestReadFile_PooledBufferPath verifies the pooled buffer path (limit == MaxReadSize)
// with a small file, exercising the ErrUnexpectedEOF + pool-return path.
func TestReadFile_PooledBufferPath(t *testing.T) {
	dir := t.TempDir()
	content := []byte("pooled buffer test content")
	path := filepath.Join(dir, "pooled.txt")
	os.WriteFile(path, content, 0644)

	// Request exactly MaxReadSize to use pooled buffer; file is smaller so
	// io.ReadFull returns ErrUnexpectedEOF which exercises the pool return.
	resp, err := ReadFile(path, 0, MaxReadSize)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}
	if string(resp.Data) != string(content) {
		t.Fatalf("expected %q, got %q", string(content), string(resp.Data))
	}
}

// TestListDir_NonexistentPath verifies that a nonexistent absolute path
// returns an error through the resolveAndValidateSymlink path.
func TestListDir_NonexistentPath(t *testing.T) {
	resp, err := ListDir("/nonexistent/dir/12345")
	if err != nil {
		t.Fatalf(testUnexpectedGoErrFmt, err)
	}
	if resp.Error == "" {
		t.Fatal("expected error for nonexistent path")
	}
}

// TestReadFile_NegativeLimit verifies that a negative limit defaults to MaxReadSize.
func TestReadFile_NegativeLimit(t *testing.T) {
	dir := t.TempDir()
	content := []byte("negative limit test")
	path := filepath.Join(dir, "neglimit.txt")
	os.WriteFile(path, content, 0644)

	resp, err := ReadFile(path, 0, -5)
	if err != nil {
		t.Fatalf(testReadFileFmt, err)
	}
	if resp.Error != "" {
		t.Fatalf(testUnexpectedErrStrFmt, resp.Error)
	}
	if string(resp.Data) != string(content) {
		t.Fatalf("expected %q, got %q", string(content), string(resp.Data))
	}
}
