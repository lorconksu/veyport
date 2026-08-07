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

// testSSHKey stands in for the openssh-form private key `vey ssh-cert`
// generates. The store never parses it, so a distinctive placeholder is
// enough — and, like testToken, a substring hit anywhere it does not belong
// is unambiguous.
const testSSHKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nssh-private-key-MUST-NOT-LEAK-1a2b3c4d\n-----END OPENSSH PRIVATE KEY-----\n"

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

// sshFor builds the SSH material for one hub, distinct per hub so a
// cross-hub leak is visible (data-model.md "Stored SSH material").
func sshFor(hub string) StoredSSH {
	return StoredSSH{
		PrivateKey:  testSSHKey + hub,
		Certificate: "ssh-ed25519-cert-v01@openssh.com AAAAcert-" + hub + " alice",
		// Truncate strips the monotonic reading so the value survives a
		// JSON round trip unchanged.
		CertExpiresAt:   time.Now().UTC().Add(12 * time.Hour).Truncate(time.Second),
		HostFingerprint: "SHA256:host-key-fingerprint-" + hub,
	}
}

func assertSSH(t *testing.T, got, want StoredSSH) {
	t.Helper()
	if got.PrivateKey != want.PrivateKey {
		t.Errorf("SSH private key mismatch:\n got %+v\nwant %+v", redactSSH(got), redactSSH(want))
	}
	if got.Certificate != want.Certificate || got.HostFingerprint != want.HostFingerprint {
		t.Errorf("SSH material mismatch:\n got %+v\nwant %+v", redactSSH(got), redactSSH(want))
	}
	if !got.CertExpiresAt.Equal(want.CertExpiresAt) {
		t.Errorf("CertExpiresAt = %v, want %v", got.CertExpiresAt, want.CertExpiresAt)
	}
}

// redactSSH is redact's counterpart for SSH material: the certificate,
// expiry, and fingerprint are public, the private key is not.
func redactSSH(m StoredSSH) StoredSSH {
	if m.PrivateKey != "" {
		m.PrivateKey = "<redacted>"
	}
	return m
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
		t.Run(backend, func(t *testing.T) { runStoreRoundTrip(t, backend) })
	}
}

// runStoreRoundTrip is TestStoreRoundTrip's per-backend body, split out so the
// sequence of assertions is not nested inside the loop/subtest closure (which
// otherwise pushes cognitive complexity well past the threshold).
func runStoreRoundTrip(t *testing.T, backend string) {
	t.Helper()
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
}

// TestStoreScopesCredentialsPerHub covers spec edge case "stored session refers
// to hub A but --hub points at hub B" (FR-005) in both backends.
func TestStoreScopesCredentialsPerHub(t *testing.T) {
	for _, backend := range backends() {
		t.Run(backend, func(t *testing.T) { runStoreScopesCredentialsPerHub(t, backend) })
	}
}

// runStoreScopesCredentialsPerHub is TestStoreScopesCredentialsPerHub's
// per-backend body, extracted so its assertions run outside the loop/subtest
// closure nesting.
func runStoreScopesCredentialsPerHub(t *testing.T, backend string) {
	t.Helper()
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

// --- SSH material (005-ssh-gateway T012) ------------------------------------

// TestStoreSSHRoundTrip pins the SSH half of the store in both backends:
// absent until written, returned in full once written, and replaced (not
// accumulated) by the next write — the re-issuance path of FR-004.
func TestStoreSSHRoundTrip(t *testing.T) {
	for _, backend := range backends() {
		t.Run(backend, func(t *testing.T) { runStoreSSHRoundTrip(t, backend) })
	}
}

func runStoreSSHRoundTrip(t *testing.T, backend string) {
	t.Helper()
	s := newTestStore(t, backend)

	if got, ok, err := s.LoadSSH(hubA); err != nil || ok || got.PrivateKey != "" {
		t.Fatalf("LoadSSH on empty store = (%+v, ok %v, err %v), want (zero, false, nil)", redactSSH(got), ok, err)
	}

	want := sshFor(hubA)
	if err := s.SaveSSH(hubA, want); err != nil {
		t.Fatalf("SaveSSH: %v", err)
	}
	got, ok, err := s.LoadSSH(hubA)
	if err != nil || !ok {
		t.Fatalf("LoadSSH = (ok %v, err %v), want (true, nil)", ok, err)
	}
	assertSSH(t, got, want)

	// Re-issuance replaces the certificate and keeps whatever key the caller
	// hands back (FR-004: the CLI reuses the keypair, the hub re-signs it).
	reissued := want
	reissued.Certificate = "ssh-ed25519-cert-v01@openssh.com AAAAcert-reissued alice"
	reissued.CertExpiresAt = want.CertExpiresAt.Add(12 * time.Hour)
	if err := s.SaveSSH(hubA, reissued); err != nil {
		t.Fatalf("SaveSSH reissued: %v", err)
	}
	got, _, err = s.LoadSSH(hubA)
	if err != nil {
		t.Fatalf("LoadSSH after re-issuance: %v", err)
	}
	assertSSH(t, got, reissued)
}

// TestStoreSSHWithoutPrivateKeyIsAbsent pins LoadSSH's "ok" contract: SSH
// material with no private key is unusable (nothing can be signed with it),
// so it reports absent rather than handing a caller a half-record it would
// have to re-validate.
func TestStoreSSHWithoutPrivateKeyIsAbsent(t *testing.T) {
	for _, backend := range backends() {
		t.Run(backend, func(t *testing.T) {
			s := newTestStore(t, backend)
			if err := s.SaveSSH(hubA, StoredSSH{HostFingerprint: "SHA256:only-a-fingerprint"}); err != nil {
				t.Fatalf("SaveSSH: %v", err)
			}
			got, ok, err := s.LoadSSH(hubA)
			if err != nil {
				t.Fatalf("LoadSSH: %v", err)
			}
			if ok {
				t.Errorf("LoadSSH reported present for keyless material: %+v", redactSSH(got))
			}
		})
	}
}

// TestSaveSessionPreservesSSHMaterial is the invariant that decides the
// storage shape. AuthContext.persistAndAdopt builds a *fresh* StoredSession
// on every refresh-token rotation and hands it to Save; if the SSH key and
// certificate lived on StoredSession, every rotation (i.e. every session-mode
// command) would silently erase them. Each half of a hub's record must
// therefore survive a write of the other half.
func TestSaveSessionPreservesSSHMaterial(t *testing.T) {
	for _, backend := range backends() {
		t.Run(backend, func(t *testing.T) { runSaveSessionPreservesSSHMaterial(t, backend) })
	}
}

func runSaveSessionPreservesSSHMaterial(t *testing.T, backend string) {
	t.Helper()
	s := newTestStore(t, backend)

	sess := sessionFor(hubA)
	material := sshFor(hubA)
	if err := s.Save(hubA, sess); err != nil {
		t.Fatalf("Save session: %v", err)
	}
	if err := s.SaveSSH(hubA, material); err != nil {
		t.Fatalf("SaveSSH: %v", err)
	}

	// A rotation: exactly what refresh.go writes, a whole new StoredSession.
	rotated := sess
	rotated.RefreshToken = testToken + "/rotated"
	if err := s.Save(hubA, rotated); err != nil {
		t.Fatalf("Save rotated session: %v", err)
	}

	gotSSH, ok, err := s.LoadSSH(hubA)
	if err != nil || !ok {
		t.Fatalf("LoadSSH after a session rotation = (ok %v, err %v), want (true, nil)", ok, err)
	}
	assertSSH(t, gotSSH, material)

	// And the mirror image: re-issuing the certificate must not disturb the
	// session that authorized it.
	reissued := material
	reissued.Certificate = "ssh-ed25519-cert-v01@openssh.com AAAAcert-reissued alice"
	if err := s.SaveSSH(hubA, reissued); err != nil {
		t.Fatalf("SaveSSH re-issued: %v", err)
	}
	gotSess, ok, err := s.Load(hubA)
	if err != nil || !ok {
		t.Fatalf("Load after re-issuance = (ok %v, err %v), want (true, nil)", ok, err)
	}
	assertSession(t, gotSess, rotated)
}

// TestStoreScopesSSHMaterialPerHub extends FR-005's per-hub scoping to the
// SSH key: a certificate issued by hub A must be structurally unreachable
// under hub B.
func TestStoreScopesSSHMaterialPerHub(t *testing.T) {
	for _, backend := range backends() {
		t.Run(backend, func(t *testing.T) { runStoreScopesSSHMaterialPerHub(t, backend) })
	}
}

func runStoreScopesSSHMaterialPerHub(t *testing.T, backend string) {
	t.Helper()
	s := newTestStore(t, backend)

	if err := s.SaveSSH(hubA, sshFor(hubA)); err != nil {
		t.Fatalf("SaveSSH hub A: %v", err)
	}
	got, ok, err := s.LoadSSH(hubB)
	if err != nil {
		t.Fatalf("LoadSSH hub B: %v", err)
	}
	if ok || got.PrivateKey != "" {
		t.Fatalf("hub B returned SSH material it was never given: %+v", redactSSH(got))
	}

	if err := s.SaveSSH(hubB, sshFor(hubB)); err != nil {
		t.Fatalf("SaveSSH hub B: %v", err)
	}
	gotA, _, err := s.LoadSSH(hubA)
	if err != nil {
		t.Fatalf("LoadSSH hub A: %v", err)
	}
	assertSSH(t, gotA, sshFor(hubA))
	gotB, _, err := s.LoadSSH(hubB)
	if err != nil {
		t.Fatalf("LoadSSH hub B: %v", err)
	}
	assertSSH(t, gotB, sshFor(hubB))
}

// TestDeleteRemovesSSHMaterial pins `vey logout`'s promise ("removes all
// locally stored credentials for that hub", FR-006 of 004): the single
// store.Delete logout issues must take the SSH private key and certificate
// with it, not just the refresh token.
func TestDeleteRemovesSSHMaterial(t *testing.T) {
	for _, backend := range backends() {
		t.Run(backend, func(t *testing.T) { runDeleteRemovesSSHMaterial(t, backend) })
	}
}

func runDeleteRemovesSSHMaterial(t *testing.T, backend string) {
	t.Helper()
	s := newTestStore(t, backend)
	if err := s.Save(hubA, sessionFor(hubA)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.SaveSSH(hubA, sshFor(hubA)); err != nil {
		t.Fatalf("SaveSSH: %v", err)
	}
	if err := s.Delete(hubA); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, ok, err := s.LoadSSH(hubA)
	if err != nil {
		t.Fatalf("LoadSSH after Delete: %v", err)
	}
	if ok || got.PrivateKey != "" {
		t.Errorf("SSH material survived logout: %+v", redactSSH(got))
	}
}

func TestStoreRejectsEmptyHubURLForSSH(t *testing.T) {
	for _, backend := range backends() {
		t.Run(backend, func(t *testing.T) {
			s := newTestStore(t, backend)
			if err := s.SaveSSH("", sshFor(hubA)); err == nil {
				t.Error("SaveSSH with empty hub URL succeeded, want error")
			}
			if _, _, err := s.LoadSSH("  "); err == nil {
				t.Error("LoadSSH with blank hub URL succeeded, want error")
			}
		})
	}
}

// TestFileStoreSSHMaterialIsOwnerOnly holds SSH material to the refresh
// token's at-rest bar: the same 0600 file, written the same atomic way.
func TestFileStoreSSHMaterialIsOwnerOnly(t *testing.T) {
	fs := newTestFileStore(t)
	if err := fs.SaveSSH(hubA, sshFor(hubA)); err != nil {
		t.Fatalf("SaveSSH: %v", err)
	}
	fi, err := os.Stat(fs.path)
	if err != nil {
		t.Fatalf("stat credentials file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != credentialsFileMode {
		t.Errorf("credentials file mode = %04o, want %04o", perm, credentialsFileMode)
	}
	if _, err := os.Stat(fs.path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file survived a successful SSH write: err = %v", err)
	}

	// The world-readable check applies to the SSH read path too.
	if err := os.Chmod(fs.path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, _, err := fs.LoadSSH(hubA); err == nil {
		t.Error("LoadSSH succeeded on a world-readable credentials file, want rejection")
	} else if strings.Contains(err.Error(), testSSHKey) {
		t.Error("permission error leaked the SSH private key")
	}
}

// TestFileStoreOnDiskShapeMatchesDataModel pins the persisted field names
// (data-model.md "Stored SSH material") and the format compatibility that
// makes one record per hub safe: an entry with no SSH material still
// serializes without SSH keys. See TestFileStoreLoadsLegacySessionOnlyEntry
// for the other half — a 004-era entry (session only) still loads.
func TestFileStoreOnDiskShapeMatchesDataModel(t *testing.T) {
	fs := newTestFileStore(t)
	if err := fs.Save(hubA, sessionFor(hubA)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	sessionOnly, err := os.ReadFile(fs.path)
	if err != nil {
		t.Fatalf("read credentials file: %v", err)
	}
	if strings.Contains(string(sessionOnly), "ssh_") {
		t.Errorf("a session-only entry emitted SSH fields, breaking format compatibility with 004:\n%s", sessionOnly)
	}

	if err := fs.SaveSSH(hubA, sshFor(hubA)); err != nil {
		t.Fatalf("SaveSSH: %v", err)
	}
	raw, err := os.ReadFile(fs.path)
	if err != nil {
		t.Fatalf("read credentials file: %v", err)
	}
	assertOnDiskSSHFields(t, raw)
}

// assertOnDiskSSHFields pins the persisted SSH field names (data-model.md
// "Stored SSH material") and confirms the refresh token still sits at the
// top level of the entry, where a store written by 004 puts it.
func assertOnDiskSSHFields(t *testing.T, raw []byte) {
	t.Helper()
	for _, field := range []string{"ssh_private_key", "ssh_certificate", "ssh_cert_expires_at", "ssh_host_fingerprint"} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("credentials file does not carry %q:\n%s", field, raw)
		}
	}
	var parsed map[string]struct {
		RefreshToken  string `json:"refresh_token"`
		SSHPrivateKey string `json:"ssh_private_key"`
		CertExpiresAt string `json:"ssh_cert_expires_at"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("credentials file is not the documented flat shape: %v", err)
	}
	entry := parsed[hubA]
	if entry.RefreshToken == "" || entry.SSHPrivateKey == "" {
		t.Fatalf("entry lost a half of its record: refresh token present=%v, ssh key present=%v",
			entry.RefreshToken != "", entry.SSHPrivateKey != "")
	}
	if _, err := time.Parse(time.RFC3339, entry.CertExpiresAt); err != nil {
		t.Errorf("ssh_cert_expires_at = %q, want RFC3339 (data-model.md): %v", entry.CertExpiresAt, err)
	}
}

// TestFileStoreLoadsLegacySessionOnlyEntry pins the other half of format
// compatibility (data-model.md "Stored SSH material"): a credentials file
// written by 004 (session only, no SSH fields at all) still loads, and
// correctly reports no SSH material rather than erroring.
func TestFileStoreLoadsLegacySessionOnlyEntry(t *testing.T) {
	fs := newTestFileStore(t)
	// newTestFileStore only builds the Store value; the config directory
	// itself is created lazily on first write (writeAll's own MkdirAll), so
	// it must exist before this test writes the legacy file directly.
	if err := os.MkdirAll(fs.dir, credentialsDirMode); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	legacy := `{"` + hubA + `":{"refresh_token":"` + testToken + `","username":"alice","role":"admin"}}`
	if err := os.WriteFile(fs.path, []byte(legacy), credentialsFileMode); err != nil {
		t.Fatalf("write legacy credentials file: %v", err)
	}
	sess, ok, err := fs.Load(hubA)
	if err != nil || !ok || sess.RefreshToken != testToken {
		t.Fatalf("legacy entry did not load: (ok %v, err %v)", ok, err)
	}
	if _, ok, err := fs.LoadSSH(hubA); err != nil || ok {
		t.Fatalf("legacy entry reported SSH material = (ok %v, err %v), want (false, nil)", ok, err)
	}
}

// TestKeyringStoreSaveOverCorruptEntryRepairs pins the keyring backend's
// merge tolerance: Save and SaveSSH read the existing entry to carry the
// other half over, and an unreadable entry must not turn a fresh `vey login`
// into a permanent failure. The write replaces the corrupt value outright.
func TestKeyringStoreSaveOverCorruptEntryRepairs(t *testing.T) {
	s := newTestStore(t, BackendKeyring)
	if err := keyring.Set(KeyringService, hubA, "{not json"); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}
	if _, _, err := s.Load(hubA); err == nil {
		t.Fatal("Load of a corrupt keyring entry succeeded, want error")
	}
	if err := s.Save(hubA, sessionFor(hubA)); err != nil {
		t.Fatalf("Save over a corrupt keyring entry: %v", err)
	}
	got, ok, err := s.Load(hubA)
	if err != nil || !ok {
		t.Fatalf("Load after repair = (ok %v, err %v), want (true, nil)", ok, err)
	}
	assertSession(t, got, sessionFor(hubA))
}

// TestKeyringStoreSurfacesSSHBackendErrors is
// TestKeyringStoreSurfacesBackendErrors' counterpart for the SSH half.
// SaveSSH is deliberately absent from the "must fail" list: it tolerates an
// unreadable existing entry (see TestKeyringStoreSaveOverCorruptEntryRepairs)
// but must still fail when the write itself cannot land.
func TestKeyringStoreSurfacesSSHBackendErrors(t *testing.T) {
	keyring.MockInitWithError(errNoKeyring)
	s := &keyringStore{}

	if err := s.SaveSSH(hubA, sshFor(hubA)); err == nil {
		t.Error("keyringStore.SaveSSH succeeded against a failing keyring, want error")
	}
	if _, _, err := s.LoadSSH(hubA); err == nil {
		t.Error("keyringStore.LoadSSH succeeded against a failing keyring, want error")
	}
}

func TestFileStoreSSHPropagatesReadAllError(t *testing.T) {
	fs := newTestFileStore(t)
	if err := fs.SaveSSH(hubA, sshFor(hubA)); err != nil {
		t.Fatalf("SaveSSH: %v", err)
	}
	if err := os.Chmod(fs.path, 0o200); err != nil { // owner write-only: unreadable
		t.Fatalf("chmod: %v", err)
	}
	if _, _, err := fs.LoadSSH(hubA); err == nil {
		t.Error("LoadSSH succeeded on a write-only credentials file, want a read error")
	}
	if err := fs.SaveSSH(hubA, sshFor(hubA)); err == nil {
		t.Error("SaveSSH succeeded on a write-only credentials file, want a read error")
	}
}

// TestErrorsNeverContainTheSSHPrivateKey is
// TestErrorsNeverContainTheRefreshToken's counterpart for the second piece
// of long-lived secret material vey persists.
func TestErrorsNeverContainTheSSHPrivateKey(t *testing.T) {
	corrupt := `{"` + hubA + `": {"ssh_private_key": "` + testSSHKey // truncated JSON containing the key

	t.Run("file corrupt", func(t *testing.T) {
		fs := newTestFileStore(t)
		if err := os.MkdirAll(fs.dir, credentialsDirMode); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(fs.path, []byte(corrupt), credentialsFileMode); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, _, err := fs.LoadSSH(hubA)
		if err == nil {
			t.Fatal("LoadSSH of corrupt file succeeded, want error")
		}
		if strings.Contains(err.Error(), testSSHKey) {
			t.Errorf("error leaked the SSH private key: %s", err)
		}
	})

	t.Run("keyring corrupt", func(t *testing.T) {
		s := newTestStore(t, BackendKeyring)
		if err := keyring.Set(KeyringService, hubA, corrupt); err != nil {
			t.Fatalf("seed keyring: %v", err)
		}
		_, _, err := s.LoadSSH(hubA)
		if err == nil {
			t.Fatal("LoadSSH of corrupt keyring entry succeeded, want error")
		}
		if strings.Contains(err.Error(), testSSHKey) {
			t.Errorf("error leaked the SSH private key: %s", err)
		}
	})
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
		t.Run(tc.name, func(t *testing.T) { runFileStorePermissionCase(t, tc.mode, tc.wantReject) })
	}
}

// runFileStorePermissionCase is TestFileStorePermissionEnforcement's
// per-case body, extracted so the accept/reject branches are not nested
// inside the table loop's subtest closure.
func runFileStorePermissionCase(t *testing.T, mode os.FileMode, wantReject bool) {
	t.Helper()
	fs := newTestFileStore(t)
	if err := fs.Save(hubA, sessionFor(hubA)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(fs.path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, _, err := fs.Load(hubA)
	if !wantReject {
		if err != nil {
			t.Fatalf("Load with mode %04o failed: %v", mode, err)
		}
		return
	}
	if err == nil {
		t.Fatalf("Load with mode %04o succeeded, want rejection", mode)
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

// --- error paths (fault injection) ------------------------------------------
//
// These exercise the store's I/O failure branches — MkdirAll/OpenFile/Rename
// rejecting a blocked or hostile path, and a keyring that answers every call
// with an error — none of which the happy-path tests above ever provoke.

// blockedPath returns a path that can never be created as a directory: dir
// is first created as a regular file, so anything under it fails MkdirAll
// with "not a directory".
func blockedPath(t *testing.T, sub string) string {
	t.Helper()
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	return filepath.Join(blocker, sub)
}

func TestLockRefreshFailsWhenConfigDirCannotBeCreated(t *testing.T) {
	dir := blockedPath(t, "vey")
	if _, err := LockRefresh(dir); err == nil {
		t.Error("LockRefresh under a path blocked by a file succeeded, want error")
	}
}

func TestLockRefreshFailsWhenLockPathIsADirectory(t *testing.T) {
	dir := t.TempDir()
	// Pre-create the lock file's own path as a directory: opening it for
	// read/write then fails (EISDIR), the same as a hostile or corrupted
	// config directory would produce.
	lockAsDir := filepath.Join(dir, LockFileName)
	if err := os.Mkdir(lockAsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := LockRefresh(dir); err == nil {
		t.Error("LockRefresh succeeded with the lock path occupied by a directory, want error")
	}
}

// TestKeyringStoreSurfacesBackendErrors drives the unexported keyringStore
// directly (this file is in package auth) against a keyring mocked to fail
// every call, covering the Save/Load/Delete error paths that NewStore's own
// fallback-to-file behavior never reaches once the file backend is selected.
func TestKeyringStoreSurfacesBackendErrors(t *testing.T) {
	keyring.MockInitWithError(errNoKeyring)
	s := &keyringStore{}

	if err := s.Save(hubA, sessionFor(hubA)); err == nil {
		t.Error("keyringStore.Save succeeded against a failing keyring, want error")
	}
	if _, _, err := s.Load(hubA); err == nil {
		t.Error("keyringStore.Load succeeded against a failing keyring, want error")
	}
	if err := s.Delete(hubA); err == nil {
		t.Error("keyringStore.Delete succeeded against a failing keyring, want error")
	}
}

func TestFileStoreReadAllRejectsPathWithNonDirectoryParent(t *testing.T) {
	fs := newFileStore(blockedPath(t, "vey"))
	if _, _, err := fs.Load(hubA); err == nil {
		t.Error("Load succeeded with a credentials path blocked by a file, want error")
	}
}

func TestFileStoreReadAllRejectsUnreadableFile(t *testing.T) {
	fs := newTestFileStore(t)
	if err := fs.Save(hubA, sessionFor(hubA)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Owner-write-only: within the "no bits outside 0600" check (0200 is a
	// subset of 0600's bits), so the permission-remediation branch does not
	// fire, but the file genuinely cannot be read back.
	if err := os.Chmod(fs.path, 0o200); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, _, err := fs.Load(hubA); err == nil {
		t.Error("Load succeeded on a write-only credentials file, want a read error")
	}
}

// TestFileStoreLoadTreatsLiteralJSONNullAsEmpty covers the defensive branch
// for a credentials file whose entire content decodes to the JSON literal
// null: unmarshaling into a map leaves it nil, and the store must treat that
// the same as an absent file rather than panicking on a nil map read.
func TestFileStoreLoadTreatsLiteralJSONNullAsEmpty(t *testing.T) {
	fs := newTestFileStore(t)
	if err := os.MkdirAll(fs.dir, credentialsDirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fs.path, []byte("null"), credentialsFileMode); err != nil {
		t.Fatalf("write literal null: %v", err)
	}
	if _, ok, err := fs.Load(hubA); err != nil || ok {
		t.Fatalf("Load of a literal-null credentials file = (ok %v, err %v), want (false, nil)", ok, err)
	}
}

// TestFileStoreSaveFailsWhenConfigDirCannotBeCreated covers Save propagating
// a readAll failure (the credentials path is blocked by a file standing
// where a directory needs to be) before it ever attempts to write.
func TestFileStoreSaveFailsWhenConfigDirCannotBeCreated(t *testing.T) {
	fs := newFileStore(blockedPath(t, "vey"))
	if err := fs.Save(hubA, sessionFor(hubA)); err == nil {
		t.Error("Save under a path blocked by a file succeeded, want error")
	}
}

// TestFileStoreWriteAllFailsWhenConfigDirCannotBeCreated drives the
// unexported writeAll directly (this file is in package auth), bypassing
// Save's own readAll precheck, so writeAll's own os.MkdirAll error path is
// exercised on its own rather than shadowed by readAll rejecting the same
// blocked path first.
func TestFileStoreWriteAllFailsWhenConfigDirCannotBeCreated(t *testing.T) {
	fs := newFileStore(blockedPath(t, "vey"))
	if err := fs.writeAll(map[string]hubEntry{hubA: {StoredSession: sessionFor(hubA)}}); err == nil {
		t.Error("writeAll under a path blocked by a file succeeded, want error")
	}
}

// TestFileStoreDeletePropagatesReadAllError covers Delete's own readAll-error
// return (as distinct from Load's, which TestFileStoreReadAllRejectsUnreadableFile
// already exercises).
func TestFileStoreDeletePropagatesReadAllError(t *testing.T) {
	fs := newTestFileStore(t)
	if err := fs.Save(hubA, sessionFor(hubA)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(fs.path, 0o200); err != nil { // owner write-only: unreadable
		t.Fatalf("chmod: %v", err)
	}
	if err := fs.Delete(hubA); err == nil {
		t.Error("Delete succeeded on a write-only credentials file, want a read error")
	}
}

// TestFileStoreSaveFailsWhenTempPathIsADirectory covers writeAll's own
// os.OpenFile failure for the temp file: if something already occupies
// <path>.tmp as a directory, creating the temp file for a new write can
// never succeed.
func TestFileStoreSaveFailsWhenTempPathIsADirectory(t *testing.T) {
	fs := newTestFileStore(t)
	if err := os.MkdirAll(fs.path+".tmp", 0o700); err != nil {
		t.Fatalf("occupy the temp path with a directory: %v", err)
	}
	if err := fs.Save(hubA, sessionFor(hubA)); err == nil {
		t.Error("Save succeeded with the temp path occupied by a directory, want error")
	}
}

// TestFileStoreSaveFailsWhenRenameDestinationBecomesADirectory covers
// writeAll's atomic-rename failure path. Pre-creating the credentials path as
// a directory would only trip readAll's own "not a regular file" check
// before writeAll ever runs, so this instead uses the beforeRename hook (the
// same seam TestFileStoreCrashBeforeRenameLeavesOldStateIntact uses) to swap
// in a directory at the very last instant — after the temp file is written
// and fsynced, but before the rename that publishes it — mirroring a hostile
// or racing change to the destination path.
func TestFileStoreSaveFailsWhenRenameDestinationBecomesADirectory(t *testing.T) {
	fs := newTestFileStore(t)
	fs.beforeRename = func() error {
		if err := os.MkdirAll(fs.path, 0o700); err != nil {
			t.Fatalf("occupy the rename destination with a directory: %v", err)
		}
		return nil
	}
	if err := fs.Save(hubA, sessionFor(hubA)); err == nil {
		t.Error("Save succeeded despite the rename destination becoming a directory mid-write, want error")
	}
	if _, err := os.Stat(fs.path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file survived a failed rename: err = %v", err)
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
