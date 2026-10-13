package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const oldVersion = "v2.0.50-prototype.3"
const newVersion = "v2.0.50-prototype.4"
const testRevision = "0123456789abcdef0123456789abcdef01234567"

var fixtureOnce sync.Once
var fixtureDir string
var fixtureErr error
var oldBinary, newBinary []byte

func TestMain(m *testing.M) {
	code := m.Run()
	if fixtureDir != "" {
		_ = os.RemoveAll(fixtureDir)
	}
	os.Exit(code)
}

func binaries(t *testing.T) ([]byte, []byte) {
	t.Helper()
	fixtureOnce.Do(func() {
		fixtureDir, fixtureErr = os.MkdirTemp("", "vey-binary-fixtures-")
		if fixtureErr != nil {
			return
		}
		for _, item := range []struct{ name, version string }{{"old", oldVersion}, {"new", newVersion}} {
			path := filepath.Join(fixtureDir, item.name)
			cmd := exec.Command("go", "build", "-ldflags", "-X main.version="+item.version+" -X main.revision="+testRevision, "-o", path, "./cmd/vey")
			cmd.Dir = "../.."
			if output, err := cmd.CombinedOutput(); err != nil {
				fixtureErr = fmt.Errorf("build fixture: %w: %s", err, output)
				return
			}
			data, err := os.ReadFile(path)
			if err != nil {
				fixtureErr = err
				return
			}
			if item.name == "old" {
				oldBinary = data
			} else {
				newBinary = data
			}
		}
	})
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	return oldBinary, newBinary
}

func artifact(data []byte) Artifact {
	return Artifact{SchemaVersion: 1, Component: "cli", OS: runtime.GOOS, Arch: runtime.GOARCH, Version: newVersion, Revision: testRevision, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Bytes: int64(len(data)), Path: "/install/cli/" + runtime.GOOS + "/" + runtime.GOARCH}
}

func source(t *testing.T, a Artifact, data []byte, beforeDownload func()) (*updater, *httptest.Server, *int) {
	t.Helper()
	downloads := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/install/metadata/") {
			_ = json.NewEncoder(w).Encode(a)
			return
		}
		downloads++
		if beforeDownload != nil {
			beforeDownload()
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(s.Close)
	u := newUpdater()
	u.currentRevision = testRevision
	u.client = s.Client()
	u.client.CheckRedirect = rejectRedirect
	return u, s, &downloads
}

func installation(t *testing.T, u *updater, old []byte) string {
	t.Helper()
	// A private directory in the current home has safe ancestors; /tmp is
	// intentionally rejected by the production directory safety check.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".vey-update-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	u.target = filepath.Join(dir, "vey")
	if err = os.WriteFile(u.target, old, 0o755); err != nil {
		t.Fatal(err)
	}
	u.executable = func() (string, error) { return u.target, nil }
	return dir
}

func TestCheckDoesNotDownloadOrInspectInstallation(t *testing.T) {
	a := artifact([]byte("metadata-only-fixture"))
	u, s, downloads := source(t, a, nil, nil)
	u.executable = func() (string, error) { t.Fatal("check inspected installation"); return "", nil }
	r, err := u.check(context.Background(), s.URL, oldVersion)
	if err != nil || !r.UpdateAvailable || r.Installed || *downloads != 0 {
		t.Fatalf("check result=%+v err=%v downloads=%d", r, err, *downloads)
	}
	for _, current := range []string{newVersion, "v2.0.51", "v2.0.28-11-g1234567-staging"} {
		r, err = u.check(context.Background(), s.URL, current)
		if err != nil || r.UpdateAvailable != (current == "v2.0.28-11-g1234567-staging") {
			t.Fatalf("current=%s result=%+v err=%v", current, r, err)
		}
	}
}

func TestMetadataRefusesUnsafeFields(t *testing.T) {
	cases := map[string]func(*Artifact){
		"component": func(a *Artifact) { a.Component = "agent" }, "platform": func(a *Artifact) { a.Arch = "arm32" },
		"absolute_url": func(a *Artifact) { a.Path = "https://other.example/evil" }, "traversal": func(a *Artifact) { a.Path = "/install/cli/../../tmp/evil" },
		"schema": func(a *Artifact) { a.SchemaVersion = 2 }, "missing_revision": func(a *Artifact) { a.Revision = "unknown" },
		"hash": func(a *Artifact) { a.SHA256 = strings.Repeat("G", 64) }, "oversize": func(a *Artifact) { a.Bytes = MaxBinaryBytes + 1 },
		"empty": func(a *Artifact) { a.Bytes = 0 }, "unknown_version": func(a *Artifact) { a.Version = "dev" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := artifact([]byte("fake"))
			mutate(&a)
			u, s, d := source(t, a, nil, nil)
			if _, err := u.check(context.Background(), s.URL, oldVersion); err == nil {
				t.Fatal("accepted invalid metadata")
			}
			if *d != 0 {
				t.Fatal("downloaded unsafe artifact")
			}
		})
	}
}

func TestTransportAndBoundedMetadata(t *testing.T) {
	t.Run("https_only", func(t *testing.T) {
		if _, err := Check(context.Background(), "http://localhost:8080", oldVersion); err == nil {
			t.Fatal("accepted plain HTTP")
		}
	})
	t.Run("unknown_current", func(t *testing.T) {
		if _, err := Check(context.Background(), "https://invalid.example", "dev"); err == nil || !strings.Contains(err.Error(), "current CLI") {
			t.Fatalf("error=%v", err)
		}
	})
	for _, kind := range []string{"redirect", "oversized", "invalid_json", "status", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "redirect":
					http.Redirect(w, r, "/redirected", http.StatusFound)
				case "oversized":
					_, _ = w.Write(bytes.Repeat([]byte("x"), int(metadataLimit+1)))
				case "invalid_json":
					_, _ = w.Write([]byte("{bad"))
				case "status":
					http.Error(w, "unavailable", 503)
				case "timeout":
					<-r.Context().Done()
				}
			}))
			defer s.Close()
			u := newUpdater()
			u.client = s.Client()
			u.client.CheckRedirect = rejectRedirect
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if _, err := u.check(ctx, s.URL, oldVersion); err == nil {
				t.Fatal("accepted failed metadata transport")
			}
		})
	}
	t.Run("untrusted_tls", func(t *testing.T) {
		u, s, _ := source(t, artifact([]byte("x")), nil, nil)
		u.client = &http.Client{Timeout: time.Second}
		if _, err := u.check(context.Background(), s.URL, oldVersion); err == nil {
			t.Fatal("accepted untrusted certificate")
		}
	})
}

func TestApplyReplacesActualBinaryAndPreservesCredentials(t *testing.T) {
	old, next := binaries(t)
	u, s, downloads := source(t, artifact(next), next, nil)
	dir := installation(t, u, old)
	for _, name := range []string{"config.json", "credentials.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("preserve-exactly"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := u.apply(context.Background(), s.URL, oldVersion)
	if err != nil || !r.Installed || *downloads != 1 {
		t.Fatalf("result=%+v err=%v downloads=%d", r, err, *downloads)
	}
	got, _ := os.ReadFile(u.target)
	backup, _ := os.ReadFile(r.Backup)
	if !bytes.Equal(got, next) || !bytes.Equal(backup, old) {
		t.Fatal("replacement or retained executable differs")
	}
	if err = runVersion(context.Background(), u.target, newVersion); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.json", "credentials.json"} {
		data, _ := os.ReadFile(filepath.Join(dir, name))
		if string(data) != "preserve-exactly" {
			t.Fatal("changed user state")
		}
	}
	info, _ := os.Stat(u.target)
	if info.Mode().Perm() != 0o755 {
		t.Fatal("changed executable permissions")
	}
	backupDir, _ := os.Stat(filepath.Dir(r.Backup))
	if backupDir.Mode().Perm() != 0o700 {
		t.Fatal("backup directory is not private")
	}
}

func TestApplyFailuresNeverOverwriteUnverifiedBytes(t *testing.T) {
	old, next := binaries(t)
	for _, kind := range []string{"corrupt", "truncated", "wrong_revision", "wrong_platform", "not_go"} {
		t.Run(kind, func(t *testing.T) {
			a := artifact(next)
			body := next
			switch kind {
			case "corrupt":
				body = append([]byte(nil), next...)
				body[len(body)-1] ^= 1
			case "truncated":
				body = next[:len(next)-1]
			case "wrong_revision":
				a.Revision = strings.Repeat("a", 40)
			case "wrong_platform":
				a.OS = "darwin"
				a.Path = "/install/cli/darwin/" + a.Arch
			case "not_go":
				body = []byte("#!/bin/sh\necho should-never-run\n")
				a = artifact(body)
			}
			u, s, _ := source(t, a, body, nil)
			installation(t, u, old)
			if _, err := u.apply(context.Background(), s.URL, oldVersion); err == nil {
				t.Fatal("accepted invalid binary")
			}
			got, _ := os.ReadFile(u.target)
			if !bytes.Equal(got, old) {
				t.Fatal("overwrote original binary")
			}
		})
	}
}

func TestPostInstallValidationRollsBack(t *testing.T) {
	old, next := binaries(t)
	u, s, _ := source(t, artifact(next), next, nil)
	dir := installation(t, u, old)
	u.validateInstalled = func(context.Context, string, string) error { return fmt.Errorf("injected final validation failure") }
	if _, err := u.apply(context.Background(), s.URL, oldVersion); err == nil || !strings.Contains(err.Error(), "previous executable restored") {
		t.Fatalf("error=%v", err)
	}
	got, _ := os.ReadFile(u.target)
	if !bytes.Equal(got, old) {
		t.Fatal("failed to restore original")
	}
	stages, _ := filepath.Glob(filepath.Join(dir, ".vey-update-*"))
	if len(stages) != 0 {
		t.Fatal("left an incomplete stage")
	}
}

func TestRollbackFailureRetainsRecoveryBinary(t *testing.T) {
	old, next := binaries(t)
	u, s, _ := source(t, artifact(next), next, nil)
	dir := installation(t, u, old)
	u.validateInstalled = func(context.Context, string, string) error {
		if err := os.Rename(u.target, filepath.Join(dir, "unexpected")); err != nil {
			return err
		}
		if err := os.Mkdir(u.target, 0o700); err != nil {
			return err
		}
		return fmt.Errorf("injected replacement interference")
	}
	if _, err := u.apply(context.Background(), s.URL, oldVersion); err == nil || !strings.Contains(err.Error(), "rollback failed") || !strings.Contains(err.Error(), "previous executable retained at") {
		t.Fatalf("error=%v", err)
	}
	backups, _ := filepath.Glob(filepath.Join(dir, ".vey-update-*", "previous"))
	if len(backups) != 1 {
		t.Fatal("lost recovery backup")
	}
	data, _ := os.ReadFile(backups[0])
	if !bytes.Equal(data, old) {
		t.Fatal("backup differs from original")
	}
}

func TestDestinationChangeDetectedBeforeReplacement(t *testing.T) {
	old, next := binaries(t)
	var target string
	changed := []byte("other installer's replacement")
	u, s, _ := source(t, artifact(next), next, func() {
		if err := os.WriteFile(target, changed, 0o755); err != nil {
			t.Error(err)
		}
	})
	installation(t, u, old)
	target = u.target
	if _, err := u.apply(context.Background(), s.URL, oldVersion); err == nil || !strings.Contains(err.Error(), "changed during update") {
		t.Fatalf("error=%v", err)
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, changed) {
		t.Fatal("overwrote concurrently changed destination")
	}
}

func TestUnsafeDestinationRefused(t *testing.T) {
	for _, kind := range []string{"different_executable", "symlink", "parent_symlink", "writable_executable", "writable_directory", "setuid"} {
		t.Run(kind, func(t *testing.T) {
			u := newUpdater()
			dir := installation(t, u, []byte("old"))
			switch kind {
			case "different_executable":
				u.executable = func() (string, error) { return "/other/vey", nil }
			case "symlink":
				_ = os.Rename(u.target, filepath.Join(dir, "original"))
				_ = os.Symlink("original", u.target)
			case "parent_symlink":
				real := dir + "-real"
				if err := os.Rename(dir, real); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(real) })
				_ = os.Symlink(real, dir)
			case "writable_executable":
				_ = os.Chmod(u.target, 0o777)
			case "writable_directory":
				_ = os.Chmod(dir, 0o777)
			case "setuid":
				_ = os.Chmod(u.target, 0o755|os.ModeSetuid)
			}
			if _, err := u.checkDestination(); err == nil {
				t.Fatal("accepted unsafe destination")
			}
		})
	}
}

func TestLockCrashRecoveryAndSymlinkSafety(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := acquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := acquireLock(path); !errors.Is(err, unix.EWOULDBLOCK) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second lock error=%v", err)
	}
	first.Close()
	third, err := acquireLock(path)
	if err != nil {
		t.Fatalf("existing unlocked file blocked recovery: %v", err)
	}
	third.Close()
	link := path + "-link"
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if f, err := acquireLock(link); err == nil {
		f.Close()
		t.Fatal("followed lock symlink")
	}
	_ = os.Chmod(path, 0o644)
	if f, err := acquireLock(path); err == nil {
		f.Close()
		t.Fatal("accepted unsafe lock mode")
	}
}

func TestPermissionErrorHasExactSudoCommandAndNoFallback(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged process")
	}
	old, next := binaries(t)
	u, s, d := source(t, artifact(next), next, nil)
	dir := installation(t, u, old)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err := u.apply(context.Background(), s.URL, oldVersion)
	if err == nil || !strings.Contains(err.Error(), "sudo /usr/local/bin/vey --hub '"+s.URL+"' update") || *d != 0 {
		t.Fatalf("error=%v downloads=%d", err, *d)
	}
	got, _ := os.ReadFile(u.target)
	if !bytes.Equal(got, old) {
		t.Fatal("changed original despite permissions")
	}
}

func TestApplyRefusesBusyAndUnsafeInstallBeforeDownloading(t *testing.T) {
	old, next := binaries(t)
	for _, kind := range []string{"busy", "wrong_path", "not_owner", "no_newer"} {
		t.Run(kind, func(t *testing.T) {
			u, s, d := source(t, artifact(next), next, nil)
			dir := installation(t, u, old)
			current := oldVersion
			switch kind {
			case "busy":
				lock, err := acquireLock(filepath.Join(dir, ".vey.update.lock"))
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			case "wrong_path":
				u.executable = func() (string, error) { return "/different/vey", nil }
			case "not_owner":
				if os.Geteuid() == 0 {
					t.Skip("requires unprivileged process")
				}
				u.target = "/usr/bin/env"
				u.executable = func() (string, error) { return u.target, nil }
			case "no_newer":
				current = newVersion
			}
			r, err := u.apply(context.Background(), s.URL, current)
			if kind == "no_newer" {
				if err != nil || r.Installed {
					t.Fatalf("no-op=%+v,%v", r, err)
				}
			} else if err == nil {
				t.Fatal("accepted unavailable installation")
			}
			if *d != 0 {
				t.Fatal("downloaded before installation refusal")
			}
		})
	}
	if _, err := Apply(context.Background(), "https://hub.example", "dev", testRevision); err == nil {
		t.Fatal("public Apply accepted unknown version")
	}
}

func TestRunningProcessIdentityCannotOverwriteNewerOrUnstampedTarget(t *testing.T) {
	old, next := binaries(t)
	for _, kind := range []string{"newer_target", "unstamped_process"} {
		t.Run(kind, func(t *testing.T) {
			u, s, d := source(t, artifact(next), next, nil)
			original := old
			if kind == "newer_target" {
				original = next
			}
			installation(t, u, original)
			if kind == "unstamped_process" {
				u.currentRevision = "unknown"
			}
			if _, err := u.apply(context.Background(), s.URL, oldVersion); err == nil {
				t.Fatal("overwrote mismatched current identity")
			}
			if *d != 0 {
				t.Fatal("downloaded before validating current identity")
			}
			got, _ := os.ReadFile(u.target)
			if !bytes.Equal(got, original) {
				t.Fatal("changed mismatched installed binary")
			}
		})
	}
}

func TestTrustedButFaultyCandidateCannotReplaceInstalledCLI(t *testing.T) {
	old, _ := binaries(t)
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "main.go")
	overlayPath := filepath.Join(dir, "overlay.json")
	candidatePath := filepath.Join(dir, "faulty")
	contents := []byte("package main\nimport \"fmt\"\nvar version=\"dev\"\nvar revision=\"unknown\"\nfunc main(){fmt.Println(\"vey defective-runtime\")}\n")
	if err := os.WriteFile(sourcePath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	mainPath, err := filepath.Abs("../../cmd/vey/main.go")
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{mainPath: sourcePath}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-overlay", overlayPath, "-ldflags", "-X main.version="+newVersion+" -X main.revision="+testRevision, "-o", candidatePath, "./cmd/vey")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build faulty trusted fixture: %v: %s", err, output)
	}
	faulty, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	u, s, _ := source(t, artifact(faulty), faulty, nil)
	installation(t, u, old)
	if _, err := u.apply(context.Background(), s.URL, oldVersion); err == nil || !strings.Contains(err.Error(), "candidate failed version validation") {
		t.Fatalf("error=%v", err)
	}
	got, _ := os.ReadFile(u.target)
	if !bytes.Equal(got, old) {
		t.Fatal("replaced installed CLI with faulty trusted artifact")
	}
}

type alteredOwnerInfo struct {
	os.FileInfo
	value any
}

func (i alteredOwnerInfo) Sys() any { return i.value }

func TestFilesystemErrorsFailClosed(t *testing.T) {
	u := newUpdater()
	dir := installation(t, u, []byte("old"))
	info, err := os.Stat(u.target)
	if err != nil {
		t.Fatal(err)
	}
	u.executable = func() (string, error) { return "", fmt.Errorf("unavailable executable") }
	if _, err = u.checkDestination(); err == nil {
		t.Fatal("ignored executable lookup failure")
	}
	u.executable = func() (string, error) { return u.target, nil }
	_ = os.Remove(u.target)
	if _, err = u.checkDestination(); err == nil {
		t.Fatal("accepted missing installation")
	}
	u.target = filepath.Join(dir, "missing-parent", "vey")
	if _, err = u.checkDestination(); err == nil {
		t.Fatal("accepted missing parent")
	}
	if err := verifyBinary(dir, artifact(nil)); err == nil {
		t.Fatal("accepted directory as artifact")
	}
	if err := verifyBinary(filepath.Join(dir, "missing"), artifact(nil)); err == nil {
		t.Fatal("accepted missing artifact")
	}
	if err := syncDirectory(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("ignored missing sync directory")
	}
	if err := safeOwner(alteredOwnerInfo{info, nil}, dir); err == nil {
		t.Fatal("accepted unverifiable owner")
	}
	if err := safeOwner(alteredOwnerInfo{info, &syscall.Stat_t{Uid: 999999}}, dir); err == nil {
		t.Fatal("accepted unrelated owner")
	}
	if err := prepareFile(filepath.Join(dir, "missing"), alteredOwnerInfo{info, nil}); err == nil {
		t.Fatal("accepted unverifiable original owner")
	}
	if err := prepareFile(filepath.Join(dir, "missing"), info); err == nil {
		t.Fatal("accepted missing staged file")
	}
	if os.Geteuid() != 0 {
		rootInfo, err := os.Stat("/usr/bin/env")
		if err != nil {
			t.Fatal(err)
		}
		if err := prepareFile(filepath.Join(dir, "missing"), rootInfo); err == nil {
			t.Fatal("changed installation owner")
		}
	}
	if err := u.sameDestination(info); err == nil {
		t.Fatal("accepted vanished destination")
	}
}

func TestVersionValidationBoundsFailureAndOutput(t *testing.T) {
	old, _ := binaries(t)
	u := newUpdater()
	dir := installation(t, u, old)
	if err := runVersion(context.Background(), u.target, newVersion); err == nil {
		t.Fatal("accepted wrong runtime version")
	}
	for name, script := range map[string]string{
		"exit": "#!/bin/sh\nexit 1\n",
		"huge": "#!/bin/sh\nhead -c 8192 /dev/zero\n",
		"wait": "#!/bin/sh\nsleep 10\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			if err := runVersion(ctx, path, oldVersion); err == nil {
				t.Fatal("accepted failed version validation")
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("validation escaped its process/pipe time bound")
			}
		})
	}
}

func TestDownloadAndMetadataReadFailuresAreBounded(t *testing.T) {
	for _, kind := range []string{"download_status", "length", "extra_bytes", "truncated_body", "metadata_truncated"} {
		t.Run(kind, func(t *testing.T) {
			a := artifact([]byte("expected"))
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "metadata_truncated" {
					w.Header().Set("Content-Length", "500")
					_, _ = w.Write([]byte("{"))
					return
				}
				switch kind {
				case "download_status":
					http.Error(w, "missing", 404)
				case "length":
					_, _ = w.Write([]byte("small"))
				case "extra_bytes":
					w.(http.Flusher).Flush()
					_, _ = w.Write([]byte("expectedx"))
				case "truncated_body":
					w.Header().Set("Content-Length", fmt.Sprint(a.Bytes))
					_, _ = w.Write([]byte("short"))
				}
			}))
			defer s.Close()
			u := newUpdater()
			u.client = s.Client()
			u.client.CheckRedirect = rejectRedirect
			if kind == "metadata_truncated" {
				if _, err := u.check(context.Background(), s.URL, oldVersion); err == nil {
					t.Fatal("accepted truncated metadata")
				}
				return
			}
			if err := u.download(context.Background(), s.URL, filepath.Join(t.TempDir(), "binary"), a); err == nil {
				t.Fatal("accepted failed bounded download")
			}
		})
	}
	u, s, _ := source(t, artifact([]byte("expected")), []byte("expected"), nil)
	if err := u.download(context.Background(), s.URL, filepath.Join(t.TempDir(), "absent", "binary"), artifact([]byte("expected"))); err == nil {
		t.Fatal("ignored staging write failure")
	}
	u.osName = "windows"
	if _, err := u.check(context.Background(), s.URL, oldVersion); err == nil {
		t.Fatal("accepted unsupported platform")
	}
	if _, err := u.get(context.Background(), ":invalid", "/bad"); err == nil {
		t.Fatal("accepted invalid HTTP request URL")
	}
}
