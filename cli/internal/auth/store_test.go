package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// A distinctive value so leak assertions cannot pass by accident.
const testToken = "refresh-token-MUST-NOT-LEAK-9f8e7d6c"

const (
	hubA = "https://hub-a.example.com"
	hubB = "https://hub-b.example.com:8443"
)

var errNoKeyring = errors.New("mock: keyring unavailable")

func sessionFor(hub string) StoredSession {
	return StoredSession{
		RefreshToken: testToken + "/" + hub,
		Username:     "alice",
		Role:         "admin",
		// Truncate strips the monotonic reading so the value survives a
		// JSON round trip unchanged.
		ObtainedAt: time.Now().UTC().Truncate(time.Second),
	}
}

func assertSession(t *testing.T, got, want StoredSession) {
	t.Helper()
	if got.RefreshToken != want.RefreshToken || got.Username != want.Username || got.Role != want.Role {
		t.Errorf("session mismatch:\n got %+v\nwant %+v", redact(got), redact(want))
	}
	if !got.ObtainedAt.Equal(want.ObtainedAt) {
		t.Errorf("ObtainedAt = %v, want %v", got.ObtainedAt, want.ObtainedAt)
	}
}

// redact keeps test failure output free of token material, mirroring the
// production rule that tokens are never printed.
func redact(s StoredSession) StoredSession {
	if s.RefreshToken != "" {
		s.RefreshToken = "<redacted>"
	}
	return s
}

// freshWarnOnce resets the process-wide one-time warning budget so each test
// observes it from a known state.
func freshWarnOnce(t *testing.T) {
	t.Helper()
	fallbackWarnOnce = sync.Once{}
	t.Cleanup(func() { fallbackWarnOnce = sync.Once{} })
}

func newTestStore(t *testing.T, backend string) Store {
	t.Helper()
	freshWarnOnce(t)
	switch backend {
	case BackendKeyring:
		keyring.MockInit()
	case BackendFile:
		keyring.MockInitWithError(errNoKeyring)
	default:
		t.Fatalf("unknown backend %q", backend)
	}

	// A not-yet-existing directory, as ~/.config/vey is on a first run, so
	// the store's own directory creation is exercised.
	s, err := NewStore(filepath.Join(t.TempDir(), "vey"), io.Discard)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.Backend() != backend {
		t.Fatalf("Backend() = %q, want %q", s.Backend(), backend)
	}
	return s
}

func newTestFileStore(t *testing.T) *fileStore {
	t.Helper()
	s := newTestStore(t, BackendFile)
	fs, ok := s.(*fileStore)
	if !ok {
		t.Fatalf("NewStore returned %T, want *fileStore", s)
	}
	return fs
}

func backends() []string { return []string{BackendKeyring, BackendFile} }

// --- construction and backend selection ------------------------------------

func TestNewStorePrefersKeyringAndCleansUpProbe(t *testing.T) {
	freshWarnOnce(t)
	keyring.MockInit()

	var warn bytes.Buffer
	s, err := NewStore(t.TempDir(), &warn)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.Backend() != BackendKeyring {
		t.Errorf("Backend() = %q, want %q", s.Backend(), BackendKeyring)
	}
	if warn.Len() != 0 {
		t.Errorf("keyring backend wrote a warning: %q", warn.String())
	}
	if _, err := keyring.Get(KeyringService, keyringProbeAccount); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("availability probe left a sentinel behind: err = %v", err)
	}
}

func TestNewStoreFallsBackToFileAndWarnsExactlyOnce(t *testing.T) {
	freshWarnOnce(t)
	keyring.MockInitWithError(errNoKeyring)

	dir := t.TempDir()
	var warn bytes.Buffer
	for i := 0; i < 3; i++ {
		s, err := NewStore(dir, &warn)
		if err != nil {
			t.Fatalf("NewStore #%d: %v", i, err)
		}
		if s.Backend() != BackendFile {
			t.Fatalf("Backend() = %q, want %q", s.Backend(), BackendFile)
		}
	}

	out := warn.String()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Errorf("got %d warning lines, want exactly 1:\n%s", n, out)
	}
	if !strings.Contains(out, filepath.Join(dir, CredentialsFileName)) {
		t.Errorf("warning does not name the fallback file: %q", out)
	}
	if !strings.Contains(out, "0600") {
		t.Errorf("warning does not mention the reduced protection: %q", out)
	}
}

func TestNewStoreNilWarnerDoesNotConsumeWarning(t *testing.T) {
	freshWarnOnce(t)
	keyring.MockInitWithError(errNoKeyring)

	dir := t.TempDir()
	if _, err := NewStore(dir, nil); err != nil {
		t.Fatalf("NewStore with nil warner: %v", err)
	}

	var warn bytes.Buffer
	if _, err := NewStore(dir, &warn); err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if warn.Len() == 0 {
		t.Error("warning budget was consumed by the nil writer")
	}
}

func TestNewStoreRejectsEmptyConfigDir(t *testing.T) {
	freshWarnOnce(t)
	keyring.MockInitWithError(errNoKeyring)

	for _, dir := range []string{"", "   "} {
		if _, err := NewStore(dir, io.Discard); err == nil {
			t.Errorf("NewStore(%q) succeeded, want error", dir)
		}
	}
}

// --- behavior shared by both backends --------------------------------------

func TestStoreRoundTrip(t *testing.T) {
	for _, backend := range backends() {
		t.Run(backend, func(t *testing.T) {
			s := newTestStore(t, backend)

			if _, ok, err := s.Load(hubA); err != nil || ok {
				t.Fatalf("Load on empty store = (ok %v, err %v), want (false, nil)", ok, err)
			}

			want := sessionFor(hubA)
			if err := s.Save(hubA, want); err != nil {
				t.Fatalf("Save: %v", err)
			}
			got, ok, err := s.Load(hubA)
			if err != nil || !ok {
				t.Fatalf("Load = (ok %v, err %v), want (true, nil)", ok, err)
			}
			assertSession(t, got, want)

			// Save replaces rather than accumulating: the rotated token must
			// fully supersede the old one.
			rotated := want
			rotated.RefreshToken = testToken + "/rotated"
			if err := s.Save(hubA, rotated); err != nil {
				t.Fatalf("Save rotated: %v", err)
			}
			got, _, err = s.Load(hubA)
			if err != nil {
				t.Fatalf("Load after rotation: %v", err)
			}
			assertSession(t, got, rotated)

			if err := s.Delete(hubA); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, ok, err := s.Load(hubA); err != nil || ok {
				t.Fatalf("Load after Delete = (ok %v, err %v), want (false, nil)", ok, err)
			}
			// Deleting an absent session is a no-op, not a failure.
			if err := s.Delete(hubA); err != nil {
				t.Errorf("second Delete: %v", err)
			}
		})
	}
}

// TestStoreScopesCredentialsPerHub covers spec edge case "stored session refers
// to hub A but --hub points at hub B" (FR-005) in both backends.
func TestStoreScopesCredentialsPerHub(t *testing.T) {
	for _, backend := range backends() {
		t.Run(backend, func(t *testing.T) {
			s := newTestStore(t, backend)

			sessA := sessionFor(hubA)
			if err := s.Save(hubA, sessA); err != nil {
				t.Fatalf("Save hub A: %v", err)
			}

			// Hub B must see nothing at all, not hub A's credentials.
			got, ok, err := s.Load(hubB)
			if err != nil {
				t.Fatalf("Load hub B: %v", err)
			}
			if ok {
				t.Fatalf("hub B returned a session it was never given: %+v", redact(got))
			}
			if got.RefreshToken != "" {
				t.Fatalf("hub B returned token material: %+v", redact(got))
			}

			// Both hubs populated: each keeps its own token.
			sessB := sessionFor(hubB)
			if err := s.Save(hubB, sessB); err != nil {
				t.Fatalf("Save hub B: %v", err)
			}
			gotA, _, err := s.Load(hubA)
			if err != nil {
				t.Fatalf("Load hub A: %v", err)
			}
			assertSession(t, gotA, sessA)
			gotB, _, err := s.Load(hubB)
			if err != nil {
				t.Fatalf("Load hub B: %v", err)
			}
			assertSession(t, gotB, sessB)

			// Deleting one hub leaves the other intact.
			if err := s.Delete(hubA); err != nil {
				t.Fatalf("Delete hub A: %v", err)
			}
			if _, ok, err := s.Load(hubA); err != nil || ok {
				t.Fatalf("hub A survived deletion: (ok %v, err %v)", ok, err)
			}
			gotB, ok, err = s.Load(hubB)
			if err != nil || !ok {
				t.Fatalf("hub B lost after deleting hub A: (ok %v, err %v)", ok, err)
			}
			assertSession(t, gotB, sessB)
		})
	}
}

func TestStoreRejectsEmptyHubURL(t *testing.T) {
	for _, backend := range backends() {
		t.Run(backend, func(t *testing.T) {
			s := newTestStore(t, backend)
			if err := s.Save("", sessionFor(hubA)); err == nil {
				t.Error("Save with empty hub URL succeeded, want error")
			}
			if _, _, err := s.Load("  "); err == nil {
				t.Error("Load with blank hub URL succeeded, want error")
			}
			if err := s.Delete(""); err == nil {
				t.Error("Delete with empty hub URL succeeded, want error")
			}
		})
	}
}

// --- file fallback specifics -----------------------------------------------

func TestFileStoreCreatesOwnerOnlyFileAndDir(t *testing.T) {
	fs := newTestFileStore(t)
	if err := fs.Save(hubA, sessionFor(hubA)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	fi, err := os.Stat(fs.path)
	if err != nil {
		t.Fatalf("stat credentials file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != credentialsFileMode {
		t.Errorf("credentials file mode = %04o, want %04o", perm, credentialsFileMode)
	}
	di, err := os.Stat(fs.dir)
	if err != nil {
		t.Fatalf("stat config dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm&^credentialsDirMode != 0 {
		t.Errorf("config dir mode = %04o, want no bits outside %04o", perm, credentialsDirMode)
	}
	if _, err := os.Stat(fs.path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file survived a successful write: err = %v", err)
	}
}

func TestFileStorePermissionEnforcement(t *testing.T) {
	tests := []struct {
		name       string
		mode       os.FileMode
		wantReject bool
	}{
		{"owner only", 0o600, false},
		{"owner read only", 0o400, false},
		{"group readable", 0o640, true},
		{"world readable", 0o644, true},
		{"world writable", 0o666, true},
		{"world executable only", 0o601, true},
		{"owner executable", 0o700, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFileStore(t)
			if err := fs.Save(hubA, sessionFor(hubA)); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if err := os.Chmod(fs.path, tc.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			_, _, err := fs.Load(hubA)
			if !tc.wantReject {
				if err != nil {
					t.Fatalf("Load with mode %04o failed: %v", tc.mode, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Load with mode %04o succeeded, want rejection", tc.mode)
			}
			msg := err.Error()
			if !strings.Contains(msg, "chmod 600 "+fs.path) {
				t.Errorf("error lacks remediation %q: %s", "chmod 600 "+fs.path, msg)
			}
			if strings.Contains(msg, testToken) {
				t.Error("error message leaked the refresh token")
			}
			// A rejected file must not be silently repaired or written over.
			if err := fs.Save(hubA, sessionFor(hubA)); err == nil {
				t.Error("Save over an exposed credentials file succeeded, want rejection")
			}
		})
	}
}

// TestFileStoreCrashBeforeRenameLeavesOldStateIntact covers spec edge case
// "machine crashes mid-way through persisting a renewed session": the store
// must hold the old or the new value in full, never a torn write.
func TestFileStoreCrashBeforeRenameLeavesOldStateIntact(t *testing.T) {
	fs := newTestFileStore(t)
	tmpPath := fs.path + ".tmp"

	oldSess := sessionFor(hubA)
	if err := fs.Save(hubA, oldSess); err != nil {
		t.Fatalf("Save old: %v", err)
	}
	oldBytes, err := os.ReadFile(fs.path)
	if err != nil {
		t.Fatalf("read credentials file: %v", err)
	}

	// Simulate a crash at the worst possible instant: the replacement has
	// been written and fsynced, but the rename has not happened.
	newSess := oldSess
	newSess.RefreshToken = testToken + "/rotated"
	fs.beforeRename = func() error { return errors.New("simulated crash") }
	if err := fs.Save(hubA, newSess); err == nil {
		t.Fatal("Save succeeded despite the simulated crash")
	}
	fs.beforeRename = nil

	if _, err := os.Stat(tmpPath); err != nil {
		t.Fatalf("expected the crash to leave a temp file behind: %v", err)
	}
	if got, err := os.ReadFile(fs.path); err != nil || !bytes.Equal(got, oldBytes) {
		t.Fatalf("live credentials file changed before the rename (err %v)", err)
	}

	// Reopen the store as a fresh process would: the old state must come
	// back complete, and the stale temp file must be ignored.
	reopened := newFileStore(fs.dir)
	got, ok, err := reopened.Load(hubA)
	if err != nil {
		t.Fatalf("Load after crash: %v", err)
	}
	if !ok {
		t.Fatal("session vanished after a crash mid-write")
	}
	assertSession(t, got, oldSess)

	// The next successful write publishes atomically and clears the stale
	// temp file.
	if err := reopened.Save(hubA, newSess); err != nil {
		t.Fatalf("Save after recovery: %v", err)
	}
	got, ok, err = reopened.Load(hubA)
	if err != nil || !ok {
		t.Fatalf("Load after recovery = (ok %v, err %v)", ok, err)
	}
	assertSession(t, got, newSess)
	if _, err := os.Stat(tmpPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale temp file survived the next write: err = %v", err)
	}

	// Whatever is on disk must always be complete, parseable JSON.
	raw, err := os.ReadFile(fs.path)
	if err != nil {
		t.Fatalf("read credentials file: %v", err)
	}
	var parsed map[string]StoredSession
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("credentials file is not complete JSON: %v", err)
	}
}

func TestFileStoreLoadHandlesMissingAndEmptyFile(t *testing.T) {
	fs := newTestFileStore(t)

	// Missing file: absent session, no error.
	if _, ok, err := fs.Load(hubA); err != nil || ok {
		t.Fatalf("Load with no file = (ok %v, err %v), want (false, nil)", ok, err)
	}
	// Delete against a missing file must not create one.
	if err := fs.Delete(hubA); err != nil {
		t.Fatalf("Delete with no file: %v", err)
	}
	if _, err := os.Stat(fs.path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no-op Delete created the credentials file: err = %v", err)
	}

	// Empty file: treated as an empty store rather than corruption.
	if err := os.MkdirAll(fs.dir, credentialsDirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fs.path, nil, credentialsFileMode); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	if _, ok, err := fs.Load(hubA); err != nil || ok {
		t.Fatalf("Load with empty file = (ok %v, err %v), want (false, nil)", ok, err)
	}
}

func TestFileStoreRejectsNonRegularFile(t *testing.T) {
	fs := newTestFileStore(t)
	if err := os.MkdirAll(fs.dir, credentialsDirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	decoy := filepath.Join(fs.dir, "decoy.json")
	if err := os.WriteFile(decoy, []byte("{}"), credentialsFileMode); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	if err := os.Symlink(decoy, fs.path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, _, err := fs.Load(hubA); err == nil {
		t.Error("Load followed a symlinked credentials file, want rejection")
	}
}

// --- secret hygiene ---------------------------------------------------------

func TestErrorsNeverContainTheRefreshToken(t *testing.T) {
	corrupt := `{"` + hubA + `": {"refresh_token": ` + testToken // truncated JSON containing the token

	t.Run("file corrupt", func(t *testing.T) {
		fs := newTestFileStore(t)
		if err := os.MkdirAll(fs.dir, credentialsDirMode); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(fs.path, []byte(corrupt), credentialsFileMode); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, _, err := fs.Load(hubA)
		if err == nil {
			t.Fatal("Load of corrupt file succeeded, want error")
		}
		if strings.Contains(err.Error(), testToken) {
			t.Errorf("error leaked the refresh token: %s", err)
		}
	})

	t.Run("keyring corrupt", func(t *testing.T) {
		s := newTestStore(t, BackendKeyring)
		if err := keyring.Set(KeyringService, hubA, corrupt); err != nil {
			t.Fatalf("seed keyring: %v", err)
		}
		_, _, err := s.Load(hubA)
		if err == nil {
			t.Fatal("Load of corrupt keyring entry succeeded, want error")
		}
		if strings.Contains(err.Error(), testToken) {
			t.Errorf("error leaked the refresh token: %s", err)
		}
	})
}

// --- refresh locking (R3) ---------------------------------------------------

func TestLockRefreshSerializesHolders(t *testing.T) {
	dir := t.TempDir()

	unlock, err := LockRefresh(dir)
	if err != nil {
		t.Fatalf("LockRefresh: %v", err)
	}

	lockPath := filepath.Join(dir, LockFileName)
	fi, err := os.Stat(lockPath)
	if err != nil {
		t.Fatalf("stat lock file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&^credentialsFileMode != 0 {
		t.Errorf("lock file mode = %04o, want no bits outside %04o", perm, credentialsFileMode)
	}

	// A second holder must block while the first holds the lock. flock is
	// per-descriptor, so a second acquisition in this process contends
	// exactly as another process would.
	type result struct {
		unlock func()
		err    error
	}
	got := make(chan result, 1)
	go func() {
		u, err := LockRefresh(dir)
		got <- result{u, err}
	}()

	select {
	case r := <-got:
		if r.unlock != nil {
			r.unlock()
		}
		t.Fatalf("second LockRefresh acquired while the first was held (err %v)", r.err)
	case <-time.After(200 * time.Millisecond):
	}

	unlock()

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("second LockRefresh after release: %v", r.err)
		}
		r.unlock()
	case <-time.After(5 * time.Second):
		t.Fatal("second LockRefresh never acquired after release")
	}
}

func TestLockRefreshUnlockIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	unlock, err := LockRefresh(dir)
	if err != nil {
		t.Fatalf("LockRefresh: %v", err)
	}
	unlock()
	unlock()

	again, err := LockRefresh(dir)
	if err != nil {
		t.Fatalf("LockRefresh after double unlock: %v", err)
	}
	again()
}

func TestLockRefreshRejectsEmptyConfigDir(t *testing.T) {
	if _, err := LockRefresh("  "); err == nil {
		t.Error("LockRefresh with blank dir succeeded, want error")
	}
}
