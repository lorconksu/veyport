package dropzone

import (
	"log"
	"os"
	"path/filepath"
	"sync"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const DefaultDir = "/tmp/veyport-dropzone"

const errFileOperation = "file operation failed"

// MaxUploadSize is the maximum total bytes allowed per file upload (100MB).
const MaxUploadSize = 100 * 1024 * 1024

// MaxConcurrentUploads limits simultaneous in-progress uploads.
const MaxConcurrentUploads = 10

// uploadState tracks an in-progress upload's file handle and byte count.
type uploadState struct {
	file      *os.File
	bytes     int64
	finalName string
}

// Dropzone manages file uploads to a staging directory.
type Dropzone struct {
	dir     string
	mu      sync.Mutex
	uploads map[string]*uploadState
}

// New creates a Dropzone that writes files to dir.
func New(dir string) *Dropzone {
	os.MkdirAll(dir, 0700)
	os.Chmod(dir, 0700)
	return &Dropzone{
		dir:     dir,
		uploads: make(map[string]*uploadState),
	}
}

// Dir returns the dropzone directory path.
func (d *Dropzone) Dir() string {
	return d.dir
}

// openNewUpload validates the filename, checks concurrent upload limits, and
// opens a temp file for a new upload. Returns the upload state on success, or
// a FileUploadAck error response on failure.
func (d *Dropzone) openNewUpload(requestID, filename string) (*uploadState, *pb.FileUploadAck) {
	if len(d.uploads) >= MaxConcurrentUploads {
		return nil, &pb.FileUploadAck{
			RequestId: requestID,
			Success:   false,
			Error:     "too many concurrent uploads",
		}
	}

	if filename == "" {
		return nil, &pb.FileUploadAck{
			RequestId: requestID,
			Success:   false,
			Error:     "no filename provided",
		}
	}

	safe := sanitizeFilename(filename)
	if safe == "" {
		return nil, &pb.FileUploadAck{
			RequestId: requestID,
			Success:   false,
			Error:     "invalid filename",
		}
	}

	tmpPath := filepath.Join(d.dir, ".upload-"+requestID)
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("dropzone create error: %v", err)
		return nil, &pb.FileUploadAck{
			RequestId: requestID,
			Success:   false,
			Error:     errFileOperation,
		}
	}
	return &uploadState{file: f, finalName: safe}, nil
}

// HandleChunk processes a file upload chunk.
// Returns a FileUploadAck when done=true or on error, nil otherwise.
func (d *Dropzone) HandleChunk(requestID, filename string, data []byte, done bool) *pb.FileUploadAck {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, exists := d.uploads[requestID]

	// First chunk — open the file
	if !exists {
		var ack *pb.FileUploadAck
		state, ack = d.openNewUpload(requestID, filename)
		if ack != nil {
			return ack
		}
		d.uploads[requestID] = state
	}

	// Write data with size limit enforcement
	if len(data) > 0 {
		if state.bytes+int64(len(data)) > MaxUploadSize {
			log.Printf("dropzone: upload %s exceeds %d byte limit", requestID, MaxUploadSize)
			state.file.Close()
			os.Remove(state.file.Name())
			delete(d.uploads, requestID)
			return &pb.FileUploadAck{
				RequestId: requestID,
				Success:   false,
				Error:     "file size limit exceeded",
			}
		}
		if _, err := state.file.Write(data); err != nil {
			log.Printf("dropzone write error: %v", err)
			state.file.Close()
			delete(d.uploads, requestID)
			return &pb.FileUploadAck{
				RequestId: requestID,
				Success:   false,
				Error:     errFileOperation,
			}
		}
		state.bytes += int64(len(data))
	}

	// Final chunk — close temp file and rename to final name
	if done {
		tmpPath := state.file.Name()
		state.file.Close()
		finalPath := filepath.Join(d.dir, state.finalName)
		if err := os.Rename(tmpPath, finalPath); err != nil {
			log.Printf("dropzone rename error: %v", err)
			os.Remove(tmpPath)
			delete(d.uploads, requestID)
			return &pb.FileUploadAck{
				RequestId: requestID,
				Success:   false,
				Error:     errFileOperation,
			}
		}
		delete(d.uploads, requestID)
		return &pb.FileUploadAck{
			RequestId: requestID,
			Success:   true,
		}
	}

	return nil
}

// Cleanup closes any open uploads (called on disconnect).
func (d *Dropzone) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, state := range d.uploads {
		tmpPath := state.file.Name()
		state.file.Close()
		os.Remove(tmpPath)
		delete(d.uploads, id)
	}
}

func sanitizeFilename(name string) string {
	// Take only the base name (strips directory components and ..)
	base := filepath.Base(name)
	if base == "." || base == ".." || base == "/" {
		return ""
	}
	return base
}
