package dropzone

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	testVulnFileTxt     = "file.txt"
	testUploadReqPrefix = ".upload-req-1"
)

// #41: Verify concurrent uploads to same filename don't corrupt each other.
func TestHandleChunk_ConcurrentSameFilename(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	// Upload 1 starts writing testVulnFileTxt
	ack := d.HandleChunk("req-1", testVulnFileTxt, []byte("data-from-upload-1"), false)
	if ack != nil {
		t.Fatalf("unexpected ack for req-1 first chunk: %v", ack)
	}

	// Upload 2 starts writing testVulnFileTxt concurrently (different request ID)
	ack = d.HandleChunk("req-2", testVulnFileTxt, []byte("data-from-upload-2"), false)
	if ack != nil {
		t.Fatalf("unexpected ack for req-2 first chunk: %v", ack)
	}

	// Verify temp files exist (not the final file yet)
	if _, err := os.Stat(filepath.Join(dir, testUploadReqPrefix)); err != nil {
		t.Fatalf("expected temp file for req-1: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".upload-req-2")); err != nil {
		t.Fatalf("expected temp file for req-2: %v", err)
	}

	// Upload 1 completes
	ack = d.HandleChunk("req-1", "", nil, true)
	if ack == nil || !ack.Success {
		t.Fatalf("expected success for req-1 completion, got %v", ack)
	}

	// Verify final file contains upload 1 data
	data, _ := os.ReadFile(filepath.Join(dir, testVulnFileTxt))
	if string(data) != "data-from-upload-1" {
		t.Fatalf("expected 'data-from-upload-1', got '%s'", string(data))
	}

	// Upload 2 completes — overwrites with its data
	ack = d.HandleChunk("req-2", "", nil, true)
	if ack == nil || !ack.Success {
		t.Fatalf("expected success for req-2 completion, got %v", ack)
	}

	// Final file now has upload 2 data (atomic rename)
	data, _ = os.ReadFile(filepath.Join(dir, testVulnFileTxt))
	if string(data) != "data-from-upload-2" {
		t.Fatalf("expected 'data-from-upload-2', got '%s'", string(data))
	}
}

// #41: Verify temp files are cleaned up on upload failure.
func TestHandleChunk_TempFileCleanedOnSizeExceed(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	// Start upload
	ack := d.HandleChunk("req-1", "bigfile.txt", []byte("start"), false)
	if ack != nil {
		t.Fatal("unexpected ack")
	}

	// Verify temp file exists
	tmpPath := filepath.Join(dir, testUploadReqPrefix)
	if _, err := os.Stat(tmpPath); err != nil {
		t.Fatalf("expected temp file: %v", err)
	}

	// Send chunk that exceeds limit
	bigData := make([]byte, MaxUploadSize+1)
	ack = d.HandleChunk("req-1", "", bigData, false)
	if ack == nil || ack.Success {
		t.Fatal("expected failure ack for size exceeded")
	}

	// Verify temp file was cleaned up
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatal("expected temp file to be removed after size exceeded")
	}

	// Verify final file was NOT created
	if _, err := os.Stat(filepath.Join(dir, "bigfile.txt")); !os.IsNotExist(err) {
		t.Fatal("expected no final file after size exceeded")
	}
}

// #41: Verify cleanup removes temp files.
func TestCleanup_RemovesTempFiles(t *testing.T) {
	dir := t.TempDir()
	d := New(dir)

	// Start upload but don't finish
	d.HandleChunk("req-1", "partial.txt", []byte("some data"), false)

	tmpPath := filepath.Join(dir, testUploadReqPrefix)
	if _, err := os.Stat(tmpPath); err != nil {
		t.Fatalf("expected temp file: %v", err)
	}

	d.Cleanup()

	// Temp file should be removed
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatal("expected temp file to be removed after cleanup")
	}
}
