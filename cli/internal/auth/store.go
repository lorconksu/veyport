package auth

// Credential storage for vey (data-model.md "StoredSession", research.md R2/R3).
//
// Only the refresh token is ever persisted; access tokens live in process
// memory for their 15-minute lifetime and passwords/TOTP codes/API tokens are
// never written. Storage is scoped per hub: every operation takes the
// normalized hub URL, which is the key in both backends, so credentials issued
// by hub A are structurally unreachable under hub B (FR-005).
//
// This file uses golang.org/x/sys/unix for advisory locking. vey targets Linux
// and macOS only (FR-015), so no Windows variant is provided.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/sys/unix"
)

const (
	// KeyringService is the service name under which vey stores refresh
	// tokens in the OS keyring. The keyring "account" is the normalized hub
	// URL (data-model.md StoredSession).
	KeyringService = "veyport-cli"

	// BackendKeyring and BackendFile are the values returned by
	// Store.Backend; `vey status` reports them so the user can see which
	// protection level is actually in effect.
	BackendKeyring = "keyring"
	BackendFile    = "file"

	// CredentialsFileName is the fallback store, a JSON map of hub URL to
	// StoredSession. LockFileName sits next to it and carries the flock that
	// serializes refresh operations (R3).
	CredentialsFileName = "credentials.json"
	LockFileName        = "credentials.lock"

	// keyringProbeAccount is the sentinel account NewStore writes and
	// deletes to decide whether a usable keyring backend exists. Probing is
	// necessary because a keyring can be present but unusable (headless
	// session with no D-Bus, locked keychain), and that only surfaces on a
	// real operation.
	keyringProbeAccount = "veyport-cli.availability-probe"
	keyringProbeValue   = "probe"

	// credentialsFileMode is the only acceptable permission set for the
	// fallback file: owner read/write, nothing else. Anything broader is
	// rejected rather than silently repaired, so the user learns that the
	// file was exposed.
	credentialsFileMode = os.FileMode(0o600)
	credentialsDirMode  = os.FileMode(0o700)
)

// StoredSession is the persisted half of an interactive session. Field
// semantics and the "never logged/printed" rule for RefreshToken come from
// data-model.md.
type StoredSession struct {
	RefreshToken string    `json:"refresh_token"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	ObtainedAt   time.Time `json:"obtained_at"`
}

// Store persists one StoredSession per hub.
//
// Implementations must uphold the credential persistence invariant
// (data-model.md): at every observable moment a hub's entry is either the
// pre-write state or the post-write state in full, never a torn write.
//
// Implementations do not lock internally. Callers that need a read →
// network-call → write critical section to be atomic against other processes
// must wrap it in LockRefresh; nesting a lock inside Save would deadlock
// against that outer lock, since flock treats two file descriptors in one
// process as two independent lock holders.
type Store interface {
	// Save writes s as the session for hubURL, replacing any existing entry.
	Save(hubURL string, s StoredSession) error
	// Load returns the session stored for hubURL. The bool is false (with a
	// nil error) when no session exists for that hub, which is a normal
	// state, not a failure.
	Load(hubURL string) (StoredSession, bool, error)
	// Delete removes the session for hubURL. Deleting an absent session is
	// not an error.
	Delete(hubURL string) error
	// Backend reports which storage is in use: BackendKeyring or BackendFile.
	Backend() string
}

// fallbackWarnOnce keeps the reduced-protection warning to a single line per
// process (FR-003), no matter how many stores get constructed.
var fallbackWarnOnce sync.Once

// NewStore returns the credential store for configDir.
//
// The OS keyring is preferred and is probed (a sentinel set followed by a
// delete) rather than assumed, because an unusable keyring only reveals
// itself on a real operation. When the probe fails, the store falls back to
// <configDir>/credentials.json at 0600 and writes exactly one warning line to
// warnW per process. A nil warnW suppresses the warning without consuming the
// one-time budget.
func NewStore(configDir string, warnW io.Writer) (Store, error) {
	if strings.TrimSpace(configDir) == "" {
		return nil, errors.New("auth: config directory is empty")
	}
	if keyringAvailable() {
		return &keyringStore{}, nil
	}
	fs := newFileStore(configDir)
	warnFallback(warnW, fs.path)
	return fs, nil
}

// keyringAvailable reports whether the OS keyring can actually hold a secret.
// The probe value is a fixed non-secret string, and it is deleted immediately;
// a failure to clean up does not make the keyring unusable, so it is ignored.
func keyringAvailable() bool {
	if err := keyring.Set(KeyringService, keyringProbeAccount, keyringProbeValue); err != nil {
		return false
	}
	_ = keyring.Delete(KeyringService, keyringProbeAccount)
	return true
}

func warnFallback(w io.Writer, path string) {
	if w == nil {
		return
	}
	fallbackWarnOnce.Do(func() {
		fmt.Fprintf(w, "warning: OS keyring unavailable; storing credentials in %s with 0600 file permissions (reduced protection)\n", path)
	})
}

// LockRefresh takes an exclusive advisory lock on <configDir>/credentials.lock
// and returns a function that releases it.
//
// The refresh token is single-use at the hub, so the whole critical section
// (read stored token → POST /api/auth/refresh → persist the rotated pair) must
// be serialized; otherwise the loser of a race persists a token the hub has
// already invalidated, over a live one (spec edge case 1, R3). The lock lives
// at store level, not inside the file backend, so keyring-backed and
// file-backed installs share one serialization point.
//
// flock is per-file-descriptor: the returned release function must be called
// (defer it) and the same process must not nest LockRefresh calls. The lock is
// released by the kernel if the process dies, so a crash cannot strand it.
func LockRefresh(configDir string) (func(), error) {
	if strings.TrimSpace(configDir) == "" {
		return nil, errors.New("auth: config directory is empty")
	}
	if err := os.MkdirAll(configDir, credentialsDirMode); err != nil {
		return nil, fmt.Errorf("auth: create config directory %s: %w", configDir, err)
	}

	path := filepath.Join(configDir, LockFileName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, credentialsFileMode)
	if err != nil {
		return nil, fmt.Errorf("auth: open lock file %s: %w", path, err)
	}

	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX)
		// The Go runtime preempts goroutines with signals, which can
		// interrupt a blocking flock; that is not a lock failure.
		if errors.Is(err, unix.EINTR) {
			continue
		}
		break
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("auth: lock %s: %w", path, err)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			_ = f.Close()
		})
	}, nil
}

// validateHubKey guards the storage key. An empty key would collapse every
// hub's credentials into one entry, defeating per-hub scoping.
func validateHubKey(hubURL string) error {
	if strings.TrimSpace(hubURL) == "" {
		return errors.New("auth: hub URL is empty")
	}
	return nil
}

// keyringStore keeps one JSON-encoded StoredSession per hub in the OS keyring.
type keyringStore struct{}

func (s *keyringStore) Backend() string { return BackendKeyring }

func (s *keyringStore) Save(hubURL string, sess StoredSession) error {
	if err := validateHubKey(hubURL); err != nil {
		return err
	}
	blob, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("auth: encode session for %s: %w", hubURL, err)
	}
	if err := keyring.Set(KeyringService, hubURL, string(blob)); err != nil {
		return fmt.Errorf("auth: store credentials for %s in keyring: %w", hubURL, err)
	}
	return nil
}

func (s *keyringStore) Load(hubURL string) (StoredSession, bool, error) {
	if err := validateHubKey(hubURL); err != nil {
		return StoredSession{}, false, err
	}
	blob, err := keyring.Get(KeyringService, hubURL)
	if errors.Is(err, keyring.ErrNotFound) {
		return StoredSession{}, false, nil
	}
	if err != nil {
		return StoredSession{}, false, fmt.Errorf("auth: read credentials for %s from keyring: %w", hubURL, err)
	}

	var sess StoredSession
	// The decode error is deliberately not wrapped: json errors can quote
	// fragments of the input, and the input here is the refresh token.
	if err := json.Unmarshal([]byte(blob), &sess); err != nil {
		return StoredSession{}, false, fmt.Errorf("auth: stored credentials for %s are corrupt; run: vey login --hub %s", hubURL, hubURL)
	}
	return sess, true, nil
}

func (s *keyringStore) Delete(hubURL string) error {
	if err := validateHubKey(hubURL); err != nil {
		return err
	}
	err := keyring.Delete(KeyringService, hubURL)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("auth: delete credentials for %s from keyring: %w", hubURL, err)
}

// fileStore is the reduced-protection fallback: a single JSON object mapping
// hub URL to StoredSession, owner-only, replaced by atomic rename.
type fileStore struct {
	dir  string
	path string

	// beforeRename, when non-nil, runs after the temp file has been written
	// and fsynced but before the rename that publishes it. Returning an
	// error aborts the write at exactly the point a crash would be most
	// damaging, which is how the atomicity test simulates one. Always nil in
	// production.
	beforeRename func() error
}

func newFileStore(configDir string) *fileStore {
	return &fileStore{
		dir:  configDir,
		path: filepath.Join(configDir, CredentialsFileName),
	}
}

func (s *fileStore) Backend() string { return BackendFile }

func (s *fileStore) Save(hubURL string, sess StoredSession) error {
	if err := validateHubKey(hubURL); err != nil {
		return err
	}
	all, err := s.readAll()
	if err != nil {
		return err
	}
	all[hubURL] = sess
	return s.writeAll(all)
}

func (s *fileStore) Load(hubURL string) (StoredSession, bool, error) {
	if err := validateHubKey(hubURL); err != nil {
		return StoredSession{}, false, err
	}
	all, err := s.readAll()
	if err != nil {
		return StoredSession{}, false, err
	}
	sess, ok := all[hubURL]
	return sess, ok, nil
}

func (s *fileStore) Delete(hubURL string) error {
	if err := validateHubKey(hubURL); err != nil {
		return err
	}
	all, err := s.readAll()
	if err != nil {
		return err
	}
	if _, ok := all[hubURL]; !ok {
		// Nothing to remove; avoid creating the file as a side effect of a
		// no-op delete.
		return nil
	}
	delete(all, hubURL)
	return s.writeAll(all)
}

// readAll loads the whole credentials map, refusing to read a file that other
// users can see.
func (s *fileStore) readAll() (map[string]StoredSession, error) {
	// Lstat, not Stat: a symlink here would let the permission check inspect
	// one file while the read consumes another.
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]StoredSession{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: inspect credentials file %s: %w", s.path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("auth: credentials file %s is not a regular file; remove it and run vey login again", s.path)
	}
	if perm := info.Mode().Perm(); perm&^credentialsFileMode != 0 {
		return nil, fmt.Errorf(
			"auth: credentials file %s has permissions %04o, which are broader than 0600 and expose your refresh token; fix it with: chmod 600 %s",
			s.path, perm, s.path)
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("auth: read credentials file %s: %w", s.path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]StoredSession{}, nil
	}

	var all map[string]StoredSession
	// As in keyringStore.Load, the decode error is not wrapped: it may quote
	// the token.
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("auth: credentials file %s is corrupt (invalid JSON); remove it and run vey login again", s.path)
	}
	if all == nil { // literal JSON null
		all = map[string]StoredSession{}
	}
	return all, nil
}

// writeAll replaces the credentials file with all, atomically.
//
// The sequence is write-temp → fsync → rename, so a crash at any point leaves
// either the previous file untouched (temp not yet renamed) or the new file
// complete (rename is atomic on POSIX). A stale temp file is never read by
// readAll and is overwritten by the next write.
func (s *fileStore) writeAll(all map[string]StoredSession) error {
	if err := os.MkdirAll(s.dir, credentialsDirMode); err != nil {
		return fmt.Errorf("auth: create config directory %s: %w", s.dir, err)
	}

	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return fmt.Errorf("auth: encode credentials: %w", err)
	}
	data = append(data, '\n')

	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, credentialsFileMode)
	if err != nil {
		return fmt.Errorf("auth: create temp credentials file %s: %w", tmp, err)
	}

	if err := s.writeAndSync(f, data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("auth: close temp credentials file %s: %w", tmp, err)
	}

	if s.beforeRename != nil {
		if err := s.beforeRename(); err != nil {
			// Leave the temp file behind: that is exactly the on-disk state
			// a crash at this instant would produce.
			return fmt.Errorf("auth: write credentials aborted before rename: %w", err)
		}
	}

	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("auth: replace credentials file %s: %w", s.path, err)
	}

	// Persist the rename itself, so the durability guarantee survives a power
	// loss and not just a process crash. Some filesystems refuse directory
	// fsync; that is not a write failure.
	if dir, err := os.Open(s.dir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// writeAndSync chmods (O_TRUNC preserves the mode of a pre-existing temp
// file), writes, and flushes to stable storage.
func (s *fileStore) writeAndSync(f *os.File, data []byte) error {
	if err := f.Chmod(credentialsFileMode); err != nil {
		return fmt.Errorf("auth: set permissions on %s: %w", f.Name(), err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("auth: write %s: %w", f.Name(), err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("auth: sync %s: %w", f.Name(), err)
	}
	return nil
}
