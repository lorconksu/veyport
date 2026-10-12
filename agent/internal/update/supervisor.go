package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/sys/unix"
)

type supervisor struct {
	paths        paths
	run          func(context.Context, string, ...string) error
	authorize    func(context.Context, string) (*pb.UpdateAuthorization, error)
	wait         time.Duration
	rollbackWait time.Duration
}

// Supervise runs only in the finite systemd transient unit. It never starts
// another supervisor, enrolls a node, edits configuration, or writes certificates.
func Supervise(ctx context.Context, operation string, authorize func(context.Context, string) (*pb.UpdateAuthorization, error)) error {
	if os.Geteuid() != 0 || !operationPattern.MatchString(operation) {
		return errors.New("invalid privileged update supervisor invocation")
	}
	p := fixedPaths()
	executable, err := os.Executable()
	if err != nil || executable != p.candidate(operation) {
		return errors.New("update supervisor must run from its private verified staging directory")
	}
	s := supervisor{paths: p, run: runCommand, authorize: authorize, wait: 90 * time.Second, rollbackWait: 30 * time.Second}
	ctx, cancel := context.WithTimeout(ctx, 170*time.Second)
	defer cancel()
	return s.runOperation(ctx, operation)
}

func (s supervisor) transition(operation, state string) error {
	lock, err := s.paths.lock("agent-update.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	entry, err := s.paths.read()
	if err != nil || entry == nil || entry.Operation != operation {
		return errors.New("update operation journal changed")
	}
	if entry.Confirmed {
		return errors.New("update operation is already durably confirmed")
	}
	entry.State = state
	entry.Confirmed = false
	return s.paths.write(*entry)
}

func (s supervisor) runOperation(ctx context.Context, operation string) error {
	recoveryDeadline := time.Now().Add(170 * time.Second)
	forwardCtx, forwardCancel := context.WithTimeout(ctx, 120*time.Second)
	defer forwardCancel()
	// Forward cancellation must not prevent restoring the previously verified
	// binary. Recovery has a separate finite reserve inside the unit lifetime.
	recoverOperation := func(entry record, cause error) error {
		recoveryCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), recoveryDeadline)
		defer cancel()
		err := s.rollback(recoveryCtx, entry, cause)
		if err == nil {
			s.cleanupStage(entry.Operation)
		}
		return err
	}
	ctx = forwardCtx
	// This separate lock is held for the supervisor's entire bounded lifetime.
	// The short journal lock remains available to the reconnected main agent.
	owner, err := s.paths.lock("agent-update-supervisor.lock")
	if err != nil {
		return err
	}
	defer owner.Close()
	entry, err := s.paths.read()
	if err != nil || entry == nil || entry.Operation != operation || entry.State != "staged" || entry.Confirmed {
		return errors.New("supervisor operation is not staged")
	}
	if time.Now().UnixMilli() >= entry.Expires {
		_ = s.transition(operation, "failed")
		return errors.New("staged update expired")
	}
	if err := s.paths.verify(s.paths.candidate(operation), entry.Target, true); err != nil {
		_ = s.transition(operation, "failed")
		return err
	}
	if err := s.paths.verify(s.paths.binary, entry.Original, false); err != nil {
		_ = s.transition(operation, "failed")
		return err
	}
	authCtx, authCancel := context.WithTimeout(ctx, 10*time.Second)
	authorization, err := s.authorize(authCtx, operation)
	authCancel()
	if err != nil || authorization == nil || authorization.OperationId != operation || authorization.ExpiresUnixMilli > entry.Expires || authorization.ExpiresUnixMilli <= time.Now().UnixMilli() {
		_ = s.transition(operation, "failed")
		return errors.New("live Hub update authorization refused")
	}
	if err := s.paths.copyVerified(s.paths.binary, s.paths.backup(operation), entry.Original, false); err != nil {
		_ = s.transition(operation, "failed")
		return fmt.Errorf("cannot preserve update rollback binary: %w", err)
	}
	if authorization.ExpiresUnixMilli <= time.Now().UnixMilli() {
		_ = s.transition(operation, "failed")
		return errors.New("live Hub update authorization expired")
	}
	if err := s.transition(operation, "installing"); err != nil {
		return err
	}
	if err := s.run(ctx, "/usr/bin/systemctl", "stop", Service); err != nil {
		// Stop may have happened despite a lost service-manager reply. Always
		// attempt to start the verified original and require a fresh observation.
		return recoverOperation(*entry, err)
	}
	if err := s.paths.copyVerified(s.paths.candidate(operation), s.paths.binary, entry.Target, true); err != nil {
		return recoverOperation(*entry, err)
	}
	if err := s.transition(operation, "reconnecting"); err != nil {
		return recoverOperation(*entry, err)
	}
	if err := s.run(ctx, "/usr/bin/systemctl", "start", Service); err != nil {
		return recoverOperation(*entry, err)
	}
	if err := s.waitConfirmed(ctx, operation, "succeeded", s.wait); err != nil {
		return recoverOperation(*entry, err)
	}
	// The journal and fsynced original backup are retained for operator recovery.
	s.cleanupStage(operation)
	return nil
}

func (s supervisor) waitConfirmed(ctx context.Context, operation, state string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		entry, err := s.paths.read()
		if err != nil || entry == nil || entry.Operation != operation {
			return errors.New("update confirmation journal unavailable")
		}
		if entry.Confirmed && entry.State == state {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("Hub did not confirm actual agent reconnection")
		case <-ticker.C:
		}
	}
}

func (s supervisor) rollback(ctx context.Context, entry record, cause error) error {
	committed, err := s.beginRollback(entry.Operation)
	if err != nil {
		return fmt.Errorf("update failed and rollback journal unavailable: %w", err)
	}
	if committed {
		return nil
	}
	if err := s.paths.verify(s.paths.backup(entry.Operation), entry.Original, false); err != nil {
		return fmt.Errorf("update failed and rollback artifact invalid: %w", err)
	}
	if err := s.run(ctx, "/usr/bin/systemctl", "stop", Service); err != nil {
		return fmt.Errorf("update failed and service stop for rollback failed: %w", err)
	}
	if err := s.paths.copyVerified(s.paths.backup(entry.Operation), s.paths.binary, entry.Original, true); err != nil {
		return fmt.Errorf("update failed and atomic rollback failed: %w", err)
	}
	// The file transition precedes start, so the restored process can report
	// its exact original bytes; this is not a remote success assertion.
	if err := s.transition(entry.Operation, "rolled_back"); err != nil {
		return err
	}
	if err := s.run(ctx, "/usr/bin/systemctl", "start", Service); err != nil {
		return fmt.Errorf("original binary restored but service restart failed: %w", err)
	}
	if err := s.waitConfirmed(ctx, entry.Operation, "rolled_back", s.rollbackWait); err != nil {
		return fmt.Errorf("original binary restored; reconnection remains unconfirmed: %w", cause)
	}
	return fmt.Errorf("update failed; Hub confirmed original agent restored: %w", cause)
}

// The timeout/confirmation race is decided under the same journal lock used
// by Confirm. A durable success wins; otherwise rolling_back makes any late
// success confirmation ineligible before a service or binary is changed.
func (s supervisor) beginRollback(operation string) (bool, error) {
	lock, err := s.paths.lock("agent-update.lock")
	if err != nil {
		return false, err
	}
	defer lock.Close()
	entry, err := s.paths.read()
	if err != nil || entry == nil || entry.Operation != operation {
		return false, errors.New("update operation journal changed")
	}
	if entry.Confirmed {
		if entry.State == "succeeded" {
			return true, nil
		}
		return false, errors.New("rollback was already durably confirmed")
	}
	entry.State = "rolling_back"
	return false, s.paths.write(*entry)
}

func (s supervisor) cleanupStage(operation string) {
	if s.paths.checkDir(s.paths.stage(operation), true) != nil {
		return
	}
	_ = os.Remove(s.paths.candidate(operation))
	_ = os.Remove(s.paths.stage(operation))
	_ = syncDirectory(filepath.Dir(s.paths.binary))
}

// copyVerified hashes the same descriptor being copied and rejects a changed
// source before an atomic rename. Both the backup and replacement are fsynced
// in the canonical executable directory, on the same filesystem.
func (p paths) copyVerified(source, destination string, expected Metadata, replace bool) error {
	if err := p.verify(source, expected, source == p.candidateFromPath(source)); err != nil {
		return err
	}
	if err := p.checkDir(filepath.Dir(destination), false); err != nil {
		return err
	}
	if replace {
		if f, err := p.open(destination, unix.O_RDONLY, 0, false); err == nil {
			_ = f.Close()
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("rollback destination already exists")
	}
	f, err := p.open(source, unix.O_RDONLY, 0, false)
	if err != nil {
		return err
	}
	defer f.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".veyport-agent-replace-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(f, expected.Bytes+1))
	if err != nil {
		return err
	}
	if n != expected.Bytes || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return errors.New("agent artifact changed during installation")
	}
	if err := tmp.Chmod(0755); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func (p paths) candidateFromPath(path string) string {
	if filepath.Base(path) == "candidate" && filepath.Dir(filepath.Dir(path)) == filepath.Dir(p.binary) {
		return path
	}
	return ""
}
