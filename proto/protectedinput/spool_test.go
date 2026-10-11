package protectedinput

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

func privateManager(t *testing.T) *Manager {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	m, err := newManager(path, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPublicStorageRefusesUnencryptedFilesystem(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if encryptedDevice(uint64(info.Sys().(*syscall.Stat_t).Dev), map[string]bool{}) {
		t.Skip("test temporary directory is on an actual encrypted device")
	}
	if m, err := New(path); !errors.Is(err, ErrUnavailable) || m != nil {
		t.Fatal("public constructor accepted an ordinary filesystem")
	}
	if err := (&Manager{path: path}).Ready(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("zero-value validator bypassed actual encryption")
	}
}

func TestStorageRejectsUnsafePathsAndCleansOnlyOwnRawFiles(t *testing.T) {
	m := privateManager(t)
	for _, name := range []string{"raw-exec-orphan", "unrelated"} {
		if err := os.WriteFile(filepath.Join(m.path, name), []byte("raw"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := newManager(m.path, func(uint64) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.path, "raw-exec-orphan")); !os.IsNotExist(err) {
		t.Fatal("startup retained abandoned input")
	}
	if _, err := os.Stat(filepath.Join(m.path, "unrelated")); err != nil {
		t.Fatal("startup removed unrelated file")
	}
	link := filepath.Join(t.TempDir(), "spool")
	if err := os.Symlink(m.path, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", m.path + "/.", link} {
		if _, err := newManager(path, func(uint64) bool { return true }); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("unsafe path accepted: %s", path)
		}
	}
	if err := os.Chmod(m.path, 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("storage with unsafe permissions accepted")
	}
}

func TestRealPrivateFileHasExactLimitAndTerminalCleanup(t *testing.T) {
	m := privateManager(t)
	file, err := m.Create()
	if err != nil {
		t.Fatal(err)
	}
	s := file.(*spool)
	info, err := os.Stat(s.path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("raw file is not private")
	}
	if _, err := file.Open(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unsealed script became readable")
	}
	script := bytes.Repeat([]byte{0xa5}, MaxScriptBytes)
	if n, err := file.Write(script); err != nil || n != len(script) {
		t.Fatalf("exact limit rejected: %d %v", n, err)
	}
	if n, err := file.Write([]byte{1}); n != 0 || !errors.Is(err, ErrLimit) {
		t.Fatal("oversize write was partially accepted")
	}
	if err := file.Seal(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{1}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("sealed script was changed")
	}
	reader, err := file.Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, script) {
		t.Fatal("sealed script changed")
	}
	_ = reader.Close()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil || m.used != 0 {
		t.Fatal("idempotent cleanup leaked aggregate budget")
	}
	if _, err := os.Stat(s.path); !os.IsNotExist(err) {
		t.Fatal("terminal path retained raw input")
	}
	if _, err := file.Open(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed script became readable")
	}
}

func TestAggregateLimitIsAtomicAndCleanupReleasesBudget(t *testing.T) {
	m := privateManager(t)
	files := make([]File, 8)
	for i := range files {
		file, err := m.Create()
		if err != nil {
			t.Fatal(err)
		}
		files[i] = file
		defer file.Close()
	}
	data := make([]byte, MaxScriptBytes)
	var wg sync.WaitGroup
	results := make(chan error, len(files))
	for _, file := range files {
		wg.Add(1)
		go func(file File) {
			defer wg.Done()
			_, err := file.Write(data)
			results <- err
		}(file)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	extra, err := m.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if n, err := extra.Write([]byte{1}); n != 0 || !errors.Is(err, ErrLimit) {
		t.Fatal("aggregate limit exceeded")
	}
	if m.used != MaxAggregateBytes {
		t.Fatal("concurrent writes lost accounting")
	}
	if err := files[0].Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := extra.Write(data); err != nil || n != len(data) {
		t.Fatal("cleanup did not release aggregate capacity")
	}
}

func TestReadinessAndDiskErrorsFailClosedWithoutBudgetLeak(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	var ready atomic.Bool
	ready.Store(true)
	m, err := newManager(path, func(uint64) bool { return ready.Load() })
	if err != nil {
		t.Fatal(err)
	}
	file, err := m.Create()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("unexecuted")); err != nil {
		t.Fatal(err)
	}
	ready.Store(false)
	if err := file.Seal(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("lost encryption readiness accepted")
	}
	if _, err := m.Create(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("lost encryption readiness allowed a new file")
	}
	_ = file.Close()
	ready.Store(true)
	file, err = m.Create()
	if err != nil {
		t.Fatal(err)
	}
	s := file.(*spool)
	_ = s.file.Close()
	if n, err := file.Write([]byte("unexecuted")); n != 0 || err == nil || m.used != 0 {
		t.Fatal("failed disk write leaked bytes or capacity")
	}
	if err := file.Seal(); err == nil {
		t.Fatal("failed disk sync accepted")
	}
	_ = file.Close()
	if _, err := os.Stat(s.path); !os.IsNotExist(err) {
		t.Fatal("disk failure retained raw file")
	}
}

func TestEncryptionAncestryRequiresEveryBackingPath(t *testing.T) {
	root := t.TempDir()
	encrypted := filepath.Join(root, "crypt")
	if err := os.MkdirAll(filepath.Join(encrypted, "dm"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(encrypted, "dm", "uuid"), []byte("CRYPT-LUKS2-test"), 0600); err != nil {
		t.Fatal(err)
	}
	lvm := filepath.Join(root, "lvm")
	if err := os.MkdirAll(filepath.Join(lvm, "slaves"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(encrypted, filepath.Join(lvm, "slaves", "crypt")); err != nil {
		t.Fatal(err)
	}
	if !encryptedSysPath(lvm, map[string]bool{}) {
		t.Fatal("encrypted backing path beneath LVM was rejected")
	}
	plain := filepath.Join(root, "plain")
	if err := os.MkdirAll(filepath.Join(plain, "slaves"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(plain, filepath.Join(lvm, "slaves", "plain")); err != nil {
		t.Fatal(err)
	}
	if encryptedSysPath(lvm, map[string]bool{}) {
		t.Fatal("mixed encrypted and plain backing paths accepted")
	}
	if err := os.Symlink(plain, filepath.Join(plain, "slaves", "cycle")); err != nil {
		t.Fatal(err)
	}
	if encryptedSysPath(plain, map[string]bool{}) {
		t.Fatal("cyclic ancestry accepted")
	}
	if fmtDevice(253, 4) != "253:4" || decimal(0) != "0" {
		t.Fatal("device address was not preserved")
	}
}
