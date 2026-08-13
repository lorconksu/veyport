// Package scguard hosts the SC-008 "zero-agent-change" guard for feature
// 005-ssh-gateway (specs/005-ssh-gateway/spec.md SC-008, tasks.md T023).
//
// The feature's premise is that the SSH gateway is entirely a Hub-side
// addition: the agent needs no new capability, no new logging, and no new
// recording to support it (FR-008, SC-008). That promise is only as good as
// something that checks it, so this package diffs agent/ and proto/ against
// the point where this branch diverged from main and fails if either changed.
//
// This lives in its own tiny package — not in hub/internal/sshgw,
// hub/internal/server, or hub/internal/integration — so it has no
// dependency on, and no risk of file-level conflict with, the packages that
// carry the feature's actual implementation. It has no non-test source file:
// a directory containing only a _test.go is a normal, buildable Go test
// package.
package scguard

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// guardedPaths are the trees SC-008 promises are untouched by this feature.
// proto/ is included alongside agent/ because a wire-format change is the
// other half of "no new agent capability" — see tasks.md's note that a
// protocol-level accommodation, if ever unavoidable, must itself add zero new
// logging/recording capability.
var guardedPaths = []string{"agent/", "proto/"}

// candidateMainRefs are tried in order when resolving the merge-base. A local
// checkout typically has "main"; a CI checkout of a feature branch often has
// only "origin/main" fetched.
var candidateMainRefs = []string{"main", "origin/main"}

// TestAgentAndProtoUnchangedSinceMainMergeBase is the SC-008 guard: it fails
// the build if this feature branch has modified anything under agent/ or
// proto/ relative to the commit where it forked from main.
//
// It is deliberately tolerant of running outside a full git checkout (a
// downloaded source tarball, a git-less container, a shallow clone with no
// "main" ref reachable) — in every such case it SKIPS with a clear message
// rather than FAILS, because "the guard machinery isn't available here" is a
// different fact from "the agent was modified" and must not be conflated with
// it.
func TestAgentAndProtoUnchangedSinceMainMergeBase(t *testing.T) {
	repoRoot, ok := requireGitCheckout(t)
	if !ok {
		return
	}

	mergeBase, ok := resolveMergeBase(t, repoRoot)
	if !ok {
		return
	}

	diffArgs := append([]string{"diff", "--stat", mergeBase, "--"}, guardedPaths...)
	out, err := runGit(repoRoot, diffArgs...)
	if err != nil {
		// Unlike an unresolvable merge-base, a diff invocation failing after
		// we already have a valid merge-base is a real tooling problem, not
		// an environment we should silently tolerate — fail loudly.
		t.Fatalf("SC-008 guard: %v", err)
	}

	if strings.TrimSpace(out) != "" {
		t.Fatalf("SC-008 violated: agent/ or proto/ changed relative to merge-base %s with main:\n\n%s\n"+
			"Feature 005-ssh-gateway (spec.md SC-008) requires the agent codebase to ship "+
			"with zero changes. Revert the offending file(s), or — if a protocol-level "+
			"accommodation has genuinely proven unavoidable — get explicit review sign-off "+
			"confirming it adds no new logging/recording capability before updating this guard.",
			mergeBase, out)
	}
}

// requireGitCheckout reports the repository root, skipping the test with an
// explanatory message when git itself, or a working checkout, isn't
// available.
func requireGitCheckout(t *testing.T) (string, bool) {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("SC-008 guard: 'git' not found on PATH (%v); skipping outside a git checkout", err)
		return "", false
	}

	root, err := runGit("", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Skipf("SC-008 guard: not running inside a git checkout (%v); skipping", err)
		return "", false
	}
	return strings.TrimSpace(root), true
}

// resolveMergeBase finds the commit where the current branch diverged from
// main, trying each of candidateMainRefs in turn. It skips (rather than
// fails) when none resolve, since that reflects an incomplete checkout — a
// shallow clone with no main ref fetched — not a violation.
func resolveMergeBase(t *testing.T, repoRoot string) (string, bool) {
	t.Helper()

	var errs []string
	for _, ref := range candidateMainRefs {
		if base, err := runGit(repoRoot, "merge-base", ref, "HEAD"); err == nil {
			return strings.TrimSpace(base), true
		} else {
			errs = append(errs, err.Error())
		}
	}
	t.Skipf("SC-008 guard: could not resolve a merge-base with any of %v; skipping.\n%s",
		candidateMainRefs, strings.Join(errs, "\n"))
	return "", false
}

// runGit runs git with args, optionally in dir, and returns combined output.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
