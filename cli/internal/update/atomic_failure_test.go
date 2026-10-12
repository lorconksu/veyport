package update

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These failures occur after download verification, at the actual filesystem
// commit boundary. Every fixture remains in its disposable private directory.
func TestAtomicCommitFailuresPreserveInstalledExecutable(t *testing.T) {
	old, next := binaries(t)
	for _, fault := range []string{"canceled", "backup_directory_lost", "candidate_removed", "candidate_corrupted"} {
		t.Run(fault, func(t *testing.T) {
			u := newUpdater()
			u.currentRevision = testRevision
			directory := installation(t, u, old)
			stage := filepath.Join(directory, "stage")
			if err := os.Mkdir(stage, 0o700); err != nil {
				t.Fatal(err)
			}
			candidate, backup := filepath.Join(stage, "new"), filepath.Join(stage, "previous")
			if err := os.WriteFile(candidate, next, 0o755); err != nil {
				t.Fatal(err)
			}
			approved := artifact(next)
			if err := verifyBinary(candidate, approved); err != nil {
				t.Fatal(err)
			}
			original, err := os.Stat(u.target)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "canceled":
				cancel()
			case "backup_directory_lost":
				backup = filepath.Join(stage, "removed", "previous")
			case "candidate_removed":
				if err := os.Remove(candidate); err != nil {
					t.Fatal(err)
				}
			case "candidate_corrupted":
				changed := append([]byte(nil), next...)
				changed[len(changed)-1] ^= 1
				if err := os.WriteFile(candidate, changed, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			versionCheckCalled := false
			u.validateInstalled = func(context.Context, string, string) error {
				versionCheckCalled = true
				return nil
			}
			retain, err := u.commitCandidate(ctx, oldVersion, candidate, backup, original, approved)
			if err == nil || retain || versionCheckCalled {
				t.Fatalf("fault=%s retain=%t version_check=%t error=%v", fault, retain, versionCheckCalled, err)
			}
			installed, readErr := os.ReadFile(u.target)
			if readErr != nil || !bytes.Equal(installed, old) {
				t.Fatal("failed commit changed the installed executable")
			}
			if fault == "candidate_corrupted" && !strings.Contains(err.Error(), "previous executable restored") {
				t.Fatalf("late corruption did not report rollback: %v", err)
			}
		})
	}
}

func TestCandidatePreparationRefusesChangingInstallationOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a process that cannot assume another installation owner")
	}
	_, next := binaries(t)
	u, hub, _ := source(t, artifact(next), next, nil)
	original, err := os.Stat("/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(t.TempDir(), "new")
	if err := u.prepareCandidate(context.Background(), hub.URL, candidate, original, artifact(next)); err == nil || !strings.Contains(err.Error(), "preserve CLI owner") {
		t.Fatalf("candidate owner mismatch error=%v", err)
	}
	// The external installation supplies only read-only ownership metadata.
	// The candidate is private and the updater never invokes it after refusal.
	if err := verifyBinary(candidate, artifact(next)); err != nil {
		t.Fatal("owner refusal changed verified candidate bytes")
	}
}
