package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/wyiu/veyport/proto/updateutil"
)

const InstallPath = "/usr/local/bin/vey"

func elevationError(hub string, err error) error {
	// validateHub excludes userinfo/control characters; shell quote anyway so
	// the guidance remains one exact command even for unusual host spelling.
	quoted := "'" + strings.ReplaceAll(hub, "'", "'\"'\"'") + "'"
	return fmt.Errorf("cannot update %s: %w; rerun explicitly with sudo (sudo may not retain your Hub configuration): sudo %s --hub %s update", InstallPath, err, InstallPath, quoted)
}

// Apply installs only a newer verified Hub release at InstallPath. It never
// elevates privileges, changes another destination or opens credential files.
func Apply(ctx context.Context, hub, current, revision string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()
	u := newUpdater()
	u.currentRevision = revision
	return u.apply(ctx, hub, current)
}

func (u *updater) apply(ctx context.Context, hub, current string) (Result, error) {
	result, err := u.check(ctx, hub, current)
	if err != nil || !result.UpdateAvailable {
		return result, err
	}
	original, lock, err := u.lockInstallation(hub, current)
	if err != nil {
		return result, err
	}
	defer lock.Close() // flock releases automatically even after a process crash.
	stage, err := os.MkdirTemp(filepath.Dir(u.target), ".vey-update-")
	if err != nil {
		return result, elevationError(hub, err)
	}
	keepBackup := false
	defer func() {
		if !keepBackup {
			_ = os.RemoveAll(stage)
		}
	}()
	newPath, backup := filepath.Join(stage, "new"), filepath.Join(stage, "previous")
	if err = u.prepareCandidate(ctx, hub, newPath, original, result.Artifact); err != nil {
		return result, err
	}
	keepBackup, err = u.commitCandidate(ctx, current, newPath, backup, original, result.Artifact)
	if err != nil {
		return result, err
	}
	result.Installed = true
	result.InstalledVersion = result.Artifact.Version
	result.Backup = backup
	return result, nil
}

func (u *updater) lockInstallation(hub, current string) (os.FileInfo, *os.File, error) {
	original, err := u.checkDestination()
	if err != nil {
		return nil, nil, err
	}
	if stat, ok := original.Sys().(*syscall.Stat_t); ok && os.Geteuid() != 0 && int(stat.Uid) != os.Geteuid() {
		return nil, nil, elevationError(hub, fmt.Errorf("only the installation owner may replace the CLI"))
	}
	lockPath := filepath.Join(filepath.Dir(u.target), ".vey.update.lock")
	lock, err := acquireLock(lockPath)
	if err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, nil, fmt.Errorf("another update holds %s; retry when that update finishes", lockPath)
		}
		return nil, nil, elevationError(hub, err)
	}
	if !revisionPattern.MatchString(u.currentRevision) {
		lock.Close()
		return nil, nil, fmt.Errorf("current CLI has no exact release revision; install a versioned release explicitly")
	}
	if err = u.verifyCurrentIdentity(current); err != nil {
		lock.Close()
		return nil, nil, fmt.Errorf("installed CLI differs from this running process; run the current %s and retry: %w", InstallPath, err)
	}
	return original, lock, nil
}

func (u *updater) verifyCurrentIdentity(current string) error {
	return updateutil.VerifyBuildIdentity(u.target, "github.com/wyiu/veyport/cli/cmd/vey", u.osName, u.arch, current, u.currentRevision)
}

func (u *updater) prepareCandidate(ctx context.Context, hub, path string, original os.FileInfo, a Artifact) error {
	if err := u.download(ctx, hub, path, a); err != nil {
		return err
	}
	if err := verifyBinary(path, a); err != nil {
		return err
	}
	if err := prepareFile(path, original); err != nil {
		return err
	}
	if err := runVersion(ctx, path, a.Version); err != nil {
		return fmt.Errorf("verified candidate failed version validation: %w", err)
	}
	return nil
}

func (u *updater) commitCandidate(ctx context.Context, current, newPath, backup string, original os.FileInfo, a Artifact) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := u.sameDestination(original); err != nil {
		return false, err
	}
	if err := u.verifyCurrentIdentity(current); err != nil {
		return false, fmt.Errorf("installed CLI changed during update: %w", err)
	}
	if err := os.Link(u.target, backup); err != nil {
		return false, fmt.Errorf("retain previous executable: %w", err)
	}
	if err := syncDirectory(filepath.Dir(backup)); err != nil {
		return false, err
	}
	if err := u.sameDestination(original); err != nil {
		return false, err
	}
	if err := os.Rename(newPath, u.target); err != nil {
		return false, fmt.Errorf("replace CLI atomically: %w", err)
	}
	// Every error after replacement restores the previous executable. The
	// final check has its own deadline even if downloading consumed the budget.
	if err := u.validateReplacement(a); err != nil {
		return restorePrevious(u.target, backup, err)
	}
	return true, nil
}

func (u *updater) validateReplacement(a Artifact) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := verifyBinary(u.target, a); err != nil {
		return err
	}
	if err := u.validateInstalled(ctx, u.target, a.Version); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(u.target))
}

func restorePrevious(target, backup string, validationErr error) (bool, error) {
	if err := os.Rename(backup, target); err != nil {
		return true, fmt.Errorf("updated CLI failed validation (%v) and rollback failed (%v); previous executable retained at %s", validationErr, err, backup)
	}
	if err := syncDirectory(filepath.Dir(target)); err != nil {
		return false, fmt.Errorf("previous executable restored after update validation failed (%v), but directory sync failed: %w", validationErr, err)
	}
	return false, fmt.Errorf("update validation failed; previous executable restored: %w", validationErr)
}

func acquireLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o600) {
		err = fmt.Errorf("unsafe update lock %s", path)
	}
	if err == nil {
		err = safeOwner(info, path)
	}
	if err == nil {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (u *updater) download(ctx context.Context, hub, path string, a Artifact) error {
	resp, err := u.get(ctx, hub, a.Path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.ContentLength >= 0 && resp.ContentLength != a.Bytes {
		return fmt.Errorf("download length differs from Hub metadata")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, a.Bytes+1))
	if copyErr == nil && n != a.Bytes {
		copyErr = fmt.Errorf("download size differs from Hub metadata")
	}
	if copyErr == nil {
		copyErr = f.Sync()
	}
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("download update binary: %w", copyErr)
	}
	return closeErr
}

func (u *updater) checkDestination() (os.FileInfo, error) {
	executable, err := u.executable()
	if err != nil {
		return nil, fmt.Errorf("locate current executable: %w", err)
	}
	if filepath.Clean(executable) != u.target {
		return nil, fmt.Errorf("vey update must run from %s; current executable is %s; install there explicitly before updating", InstallPath, executable)
	}
	// Refuse symlink components and writable parents before privileged writes.
	// An unprivileged owner may update their own installation, while root
	// requires a root-owned path throughout the installation hierarchy.
	for path := filepath.Dir(u.target); ; path = filepath.Dir(path) {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return nil, statErr
		}
		if !info.IsDir() || info.Mode()&0o022 != 0 {
			return nil, fmt.Errorf("unsafe installation directory %s: real directory without group/world write permission required", path)
		}
		if err = safeOwner(info, path); err != nil {
			return nil, err
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	info, err := os.Lstat(u.target)
	if err != nil {
		return nil, fmt.Errorf("inspect fixed installation: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&(0o022|os.ModeSetuid|os.ModeSetgid) != 0 || info.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("unsafe CLI installation %s: regular executable without symlinks, set-ID or group/world write permission required", u.target)
	}
	if err = safeOwner(info, u.target); err != nil {
		return nil, err
	}
	return info, nil
}

func safeOwner(info os.FileInfo, path string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify installation owner for %s", path)
	}
	if stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("unsafe installation owner for %s", path)
	}
	return nil
}

func (u *updater) sameDestination(original os.FileInfo) error {
	current, err := u.checkDestination()
	if err != nil {
		return err
	}
	if !os.SameFile(original, current) || original.Mode() != current.Mode() || original.Size() != current.Size() || !original.ModTime().Equal(current.ModTime()) {
		return fmt.Errorf("CLI installation changed during update; retry after other installers finish")
	}
	return nil
}

func prepareFile(path string, original os.FileInfo) error {
	stat, ok := original.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot preserve CLI owner")
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, int(stat.Uid), int(stat.Gid)); err != nil {
			return fmt.Errorf("preserve CLI owner: %w", err)
		}
	} else if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("cannot preserve CLI owner; update requires the installation owner's permissions")
	} else if err := os.Chown(path, -1, int(stat.Gid)); err != nil {
		return fmt.Errorf("preserve CLI group: %w", err)
	}
	if err := os.Chmod(path, original.Mode().Perm()); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

type boundedOutput struct{ data []byte }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 4096 {
		return 0, fmt.Errorf("version output exceeds limit")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func runVersion(ctx context.Context, path, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.WaitDelay = time.Second
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	var output boundedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("execute version check: %w", err)
	}
	if strings.TrimSpace(string(output.data)) != "vey "+version {
		return fmt.Errorf("installed executable did not report the approved version")
	}
	return nil
}
