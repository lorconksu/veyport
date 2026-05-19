package filebrowser

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/sys/unix"
)

// isRoot is true when the agent runs as uid 0; checked once at init to skip
// per-entry unix.Access calls (root can read everything).
var isRoot = os.Getuid() == 0

// readBufPool reuses 1MB byte slices to reduce allocations in ReadFile.
var readBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, MaxReadSize)
		return &buf
	},
}

const MaxReadSize = 1048576 // 1MB

const errCannotReadFile = "cannot read file"
const errPathRestricted = "access to this path is restricted"

// blockedPaths are sensitive system paths that the file browser must never expose.
// Checked against the cleaned path prefix — blocks the path itself and all children.
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

// blockedPrefixes are path prefixes whose entire subtree is blocked.
var blockedPrefixes = []string{
	"/proc/",
	"/sys/kernel/",
}

func validatePath(path string) error {
	// Reject paths that contain ".." components before cleaning
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed")
	}
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return fmt.Errorf("path must be absolute")
	}

	// Check against blocklist of sensitive paths
	for _, blocked := range blockedPaths {
		if cleaned == blocked || strings.HasPrefix(cleaned, blocked+"/") {
			return fmt.Errorf(errPathRestricted)
		}
	}
	for _, prefix := range blockedPrefixes {
		if strings.HasPrefix(cleaned, prefix) {
			return fmt.Errorf(errPathRestricted)
		}
	}

	return nil
}

// resolveAndValidateSymlink resolves symlinks and ensures the target stays
// within the requested path. Returns the resolved path or an error string.
func resolveAndValidateSymlink(path string) (string, string) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		log.Printf("resolveAndValidateSymlink: cannot resolve path %q: %v", path, err)
		return "", "cannot access path"
	}
	// Re-validate the resolved path against the blocklist
	if err := validatePath(resolved); err != nil {
		return "", errPathRestricted
	}
	cleanPath := filepath.Clean(path)
	if resolved != cleanPath && !strings.HasPrefix(resolved, cleanPath+"/") {
		return "", "path resolves outside requested directory"
	}
	return resolved, ""
}

// buildFileNode creates a FileNode from a directory entry, returning nil
// for entries that should be skipped (e.g. FIFOs, devices, stat errors).
func buildFileNode(e os.DirEntry, basePath, resolvedPath string) *pb.FileNode {
	info, err := e.Info()
	if err != nil {
		return nil
	}
	mode := info.Mode()
	if !mode.IsRegular() && !mode.IsDir() {
		return nil
	}
	node := &pb.FileNode{
		Name:  e.Name(),
		Path:  filepath.Join(basePath, e.Name()),
		IsDir: e.IsDir(),
		Size:  info.Size(),
	}
	if isRoot {
		node.Readable = true
	} else {
		entryPath := filepath.Join(resolvedPath, e.Name())
		if unix.Access(entryPath, unix.R_OK) == nil {
			node.Readable = true
		}
	}
	return node
}

func ListDir(path string) (*pb.FileListResponse, error) {
	if err := validatePath(path); err != nil {
		return &pb.FileListResponse{Error: err.Error()}, nil
	}

	resolved, errMsg := resolveAndValidateSymlink(path)
	if errMsg != "" {
		return &pb.FileListResponse{Error: errMsg}, nil
	}

	entries, err := os.ReadDir(resolved)
	if err != nil {
		log.Printf("ListDir: cannot read directory %q: %v", resolved, err)
		return &pb.FileListResponse{Error: "cannot read directory"}, nil
	}

	var dirs, files []*pb.FileNode
	for _, e := range entries {
		node := buildFileNode(e, path, resolved)
		if node == nil {
			continue
		}
		if e.IsDir() {
			dirs = append(dirs, node)
		} else {
			files = append(files, node)
		}
	}

	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	allFiles := append(dirs, files...)
	return &pb.FileListResponse{Files: allFiles}, nil
}

// clampLimit normalises the read limit to be within [1, MaxReadSize].
func clampLimit(limit int64) int64 {
	if limit <= 0 || limit > MaxReadSize {
		return MaxReadSize
	}
	return limit
}

// computeTailOffset converts a negative offset (tail read) into an actual
// byte position within the file.
func computeTailOffset(offset, limit, totalSize int64) int64 {
	if offset >= 0 {
		return offset
	}
	if totalSize > limit {
		return totalSize - limit
	}
	return 0
}

// readFileData reads up to limit bytes from f (already seeked), using
// a pooled buffer when possible. Returns the read bytes or an error string.
func readFileData(f *os.File, limit int64, resolved string) ([]byte, string) {
	var data []byte
	var poolBuf *[]byte
	if limit == MaxReadSize {
		poolBuf = readBufPool.Get().(*[]byte)
		data = (*poolBuf)[:limit]
	} else {
		data = make([]byte, limit)
	}

	n, err := io.ReadFull(f, data)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		if poolBuf != nil {
			readBufPool.Put(poolBuf)
		}
		log.Printf("ReadFile: read failed for %q: %v", resolved, err)
		return nil, errCannotReadFile
	}

	result := make([]byte, n)
	copy(result, data[:n])
	if poolBuf != nil {
		readBufPool.Put(poolBuf)
	}
	return result, ""
}

func ReadFile(path string, offset, limit int64) (*pb.FileReadResponse, error) {
	if err := validatePath(path); err != nil {
		return &pb.FileReadResponse{Error: err.Error()}, nil
	}

	limit = clampLimit(limit)

	resolved, errMsg := resolveAndValidateSymlink(path)
	if errMsg != "" {
		return &pb.FileReadResponse{Error: errMsg}, nil
	}

	f, err := os.Open(resolved)
	if err != nil {
		log.Printf("ReadFile: cannot open file %q: %v", resolved, err)
		return &pb.FileReadResponse{Error: errCannotReadFile}, nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.Printf("ReadFile: cannot stat file %q: %v", resolved, err)
		return &pb.FileReadResponse{Error: errCannotReadFile}, nil
	}
	if info.IsDir() {
		return &pb.FileReadResponse{Error: "path is a directory"}, nil
	}

	totalSize := info.Size()
	offset = computeTailOffset(offset, limit, totalSize)

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			log.Printf("ReadFile: seek failed for %q at offset %d: %v", resolved, offset, err)
			return &pb.FileReadResponse{Error: errCannotReadFile}, nil
		}
	}

	result, readErr := readFileData(f, limit, resolved)
	if readErr != "" {
		return &pb.FileReadResponse{Error: readErr}, nil
	}

	return &pb.FileReadResponse{
		Data:      result,
		TotalSize: totalSize,
		MimeType:  detectMIME(filepath.Base(path)),
	}, nil
}

func detectMIME(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".txt", ".conf", ".cfg", ".ini", ".log", ".env":
		return "text/plain"
	case ".json":
		return "application/json"
	case ".md", ".markdown":
		return "text/markdown"
	case ".yaml", ".yml":
		return "text/yaml"
	case ".xml":
		return "text/xml"
	case ".html", ".htm":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "text/javascript"
	case ".go":
		return "text/x-go"
	case ".py":
		return "text/x-python"
	case ".rs":
		return "text/x-rust"
	case ".sh", ".bash":
		return "text/x-sh"
	case ".toml":
		return "text/x-toml"
	case ".sql":
		return "text/x-sql"
	default:
		return "application/octet-stream"
	}
}
