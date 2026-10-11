// Package protectedinput owns bounded raw input on administrator-provisioned
// encrypted storage. It never falls back to a system temporary directory.
package protectedinput

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const MaxScriptBytes = 16 << 20
const MaxAggregateBytes = 128 << 20

var ErrUnavailable = errors.New("protected encrypted input storage unavailable")
var ErrLimit = errors.New("protected input limit exceeded")

// Store and File make the storage boundary explicit. Runtime uses New; tests
// may inject their own storage implementation without enabling unsafe runtime
// mounts or adding a production encryption bypass.
type Store interface {
	Ready() error
	Create() (File, error)
}
type File interface {
	io.Writer
	Seal() error
	Open() (io.ReadCloser, error)
	Close() error
}

type Manager struct {
	mu        sync.Mutex
	path      string
	used      int64
	encrypted func(uint64) bool
}

func New(path string) (*Manager, error) {
	return newManager(path, func(dev uint64) bool { return encryptedDevice(dev, map[string]bool{}) })
}

// The private validator seam lets package tests exercise real private files;
// every public constructor always checks the actual Linux device ancestry.
func newManager(path string, encrypted func(uint64) bool) (*Manager, error) {
	m := &Manager{path: path, encrypted: encrypted}
	if err := m.Ready(); err != nil {
		return nil, err
	}
	// A new service lifetime cannot reuse a previous raw submission.
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "raw-exec-") {
			if err := os.Remove(filepath.Join(path, entry.Name())); err != nil {
				return nil, ErrUnavailable
			}
		}
	}
	return m, nil
}

func (m *Manager) Ready() error {
	if m == nil || !filepath.IsAbs(m.path) || filepath.Clean(m.path) != m.path {
		return ErrUnavailable
	}
	real, err := filepath.EvalSymlinks(m.path)
	if err != nil || real != m.path {
		return ErrUnavailable
	}
	info, err := os.Lstat(m.path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return ErrUnavailable
	}
	encrypted := m.encrypted
	if encrypted == nil {
		encrypted = func(dev uint64) bool { return encryptedDevice(dev, map[string]bool{}) }
	}
	if !encrypted(uint64(st.Dev)) {
		return ErrUnavailable
	}
	return nil
}

// Linux reports a filesystem's actual block device, avoiding trusting a path
// name, environment boolean, or administrator's claim that /tmp is encrypted.
// dm-crypt may sit below LVM; all backing paths must cross a CRYPT device.
func encryptedDevice(dev uint64, seen map[string]bool) bool {
	major := (dev>>8)&0xfff | (dev>>32)&0xfffff000
	minor := dev&0xff | (dev>>12)&0xffffff00
	return encryptedSysPath(filepath.Join("/sys/dev/block", fmtDevice(major, minor)), seen)
}

func fmtDevice(major, minor uint64) string { return decimal(major) + ":" + decimal(minor) }
func decimal(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
func encryptedSysPath(path string, seen map[string]bool) bool {
	real, err := filepath.EvalSymlinks(path)
	if err != nil || seen[real] {
		return false
	}
	seen[real] = true
	defer delete(seen, real)
	uuid, err := os.ReadFile(filepath.Join(real, "dm/uuid"))
	if err == nil && strings.HasPrefix(string(uuid), "CRYPT-") {
		return true
	}
	children, err := os.ReadDir(filepath.Join(real, "slaves"))
	if err != nil || len(children) == 0 {
		return false
	}
	for _, child := range children {
		if !encryptedSysPath(filepath.Join(real, "slaves", child.Name()), seen) {
			return false
		}
	}
	return true
}

func (m *Manager) Create() (File, error) {
	if err := m.Ready(); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(m.path, "raw-exec-")
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, ErrUnavailable
	}
	return &spool{manager: m, file: f, path: f.Name()}, nil
}

type spool struct {
	mu             sync.Mutex
	manager        *Manager
	file           *os.File
	path           string
	bytes          int64
	sealed, closed bool
}

func (s *spool) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.sealed {
		return 0, ErrUnavailable
	}
	s.manager.mu.Lock()
	if s.bytes+int64(len(p)) > MaxScriptBytes || s.manager.used+int64(len(p)) > MaxAggregateBytes {
		s.manager.mu.Unlock()
		return 0, ErrLimit
	}
	s.manager.used += int64(len(p))
	s.manager.mu.Unlock()
	n, err := s.file.Write(p)
	s.bytes += int64(n)
	s.manager.mu.Lock()
	s.manager.used -= int64(len(p) - n)
	s.manager.mu.Unlock()
	return n, err
}
func (s *spool) Seal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.sealed {
		return ErrUnavailable
	}
	if err := s.manager.Ready(); err != nil {
		return err
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	s.sealed = true
	return nil
}
func (s *spool) Open() (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sealed || s.closed {
		return nil, ErrUnavailable
	}
	return os.Open(s.path)
}
func (s *spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.file.Close()
	removeErr := os.Remove(s.path)
	s.manager.mu.Lock()
	s.manager.used -= s.bytes
	s.manager.mu.Unlock()
	return errors.Join(err, removeErr)
}
