// Package scguard hosts the SC-008 "zero-agent-change" guard for feature
// 005-ssh-gateway (specs/005-ssh-gateway/spec.md SC-008, tasks.md T023).
//
// The feature's premise is that the SSH gateway is entirely a Hub-side
// addition: the agent needs no new capability, no new logging, and no new
// recording to support it (FR-008, SC-008). That promise is only as good as
// something that checks it, so this package diffs agent/ and proto/ against
// the point where this branch diverged from main and fails if either changed.
//
// The guard's concern is capability, logging/recording, and wire format —
// not exact dependency versions. A routine dependency bump (e.g. a Go
// toolchain or grpc point release to clear a CVE) touches agent/go.mod,
// agent/go.sum, proto/go.mod, and proto/go.sum without adding the agent any
// new capability, so those four manifests are excluded from the diff via
// dependencyManifests below. Everything else under agent/ and proto/ stays
// guarded: hand-written .go, .proto sources, generated .pb.go output,
// Dockerfiles, and scripts. In particular, if a dependency bump ever changes
// generated .pb.go output (a real wire-format change), that file is NOT in
// dependencyManifests, so the guard still catches it.
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

// dependencyManifests are pathspecs excluded from the SC-008 diff because
// they record third-party dependency *versions*, not agent capability. A
// security patch bump (Go toolchain, grpc, x/net, x/text, ...) touches these
// files as a side effect and is not itself a capability, logging, or
// wire-format change — see the package comment above. Keep this list to
// exactly the dependency manifests for the guarded trees; do not widen it to
// cover any other file, and do not add lockfiles for anything other than
// agent/ or proto/ (hub/'s own go.mod and go.sum are not under guardedPaths
// and so need no exclusion here).
var dependencyManifests = []string{
	":(exclude)agent/go.mod",
	":(exclude)agent/go.sum",
	":(exclude)proto/go.mod",
	":(exclude)proto/go.sum",
}

// candidateMainRefs are tried in order when resolving the merge-base. A local
// checkout typically has "main"; a CI checkout of a feature branch often has
// only "origin/main" fetched.
var candidateMainRefs = []string{"main", "origin/main"}

// TestAgentAndProtoUnchangedSinceMainMergeBase is the SC-008 guard: it fails
// the build if this feature branch has modified anything under agent/ or
// proto/ — other than the dependency manifests in dependencyManifests —
// relative to the commit where it forked from main.
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

	diffArgs := []string{"diff", "--stat", mergeBase, "--"}
	diffArgs = append(diffArgs, guardedPaths...)
	diffArgs = append(diffArgs, dependencyManifests...)
	out, err := runGit(repoRoot, diffArgs...)
	if err != nil {
		// Unlike an unresolvable merge-base, a diff invocation failing after
		// we already have a valid merge-base is a real tooling problem, not
		// an environment we should silently tolerate — fail loudly.
		t.Fatalf("SC-008 guard: %v", err)
	}

	if strings.TrimSpace(out) != "" {
		t.Fatalf("SC-008 violated: agent/ or proto/ changed relative to merge-base %s with main "+
			"(dependency manifests agent/go.{mod,sum} and proto/go.{mod,sum} are already excluded "+
			"from this diff, so this is a real change to source, generated, or build files):\n\n%s\n"+
			"Feature 005-ssh-gateway (spec.md SC-008) requires the agent codebase to ship "+
			"with zero new capability. Revert the offending file(s), or — if a protocol-level "+
			"accommodation has genuinely proven unavoidable — get explicit review sign-off "+
			"confirming it adds no new logging/recording capability before updating this guard.",
			mergeBase, out)
	}
}

// TestGuardPathspecExcludesOnlyDependencyManifests locks the scope of
// dependencyManifests down to exactly the four dependency manifest files for
// agent/ and proto/. It exists so that widening the exclude list — say, to
// silence an unrelated future violation — can't happen silently: this test
// fails the moment anyone adds, removes, or generalizes an entry.
func TestGuardPathspecExcludesOnlyDependencyManifests(t *testing.T) {
	want := []string{
		":(exclude)agent/go.mod",
		":(exclude)agent/go.sum",
		":(exclude)proto/go.mod",
		":(exclude)proto/go.sum",
	}

	if len(dependencyManifests) != len(want) {
		t.Fatalf("dependencyManifests has %d entries, want exactly %d: got %v, want %v",
			len(dependencyManifests), len(want), dependencyManifests, want)
	}
	for i, w := range want {
		if dependencyManifests[i] != w {
			t.Fatalf("dependencyManifests[%d] = %q, want %q (full slice: %v)",
				i, dependencyManifests[i], w, dependencyManifests)
		}
	}
}

// TestAgentAndProtoDiffWithoutExcludesIsOnlyDependencyManifests documents,
// and pins, the exact situation the dependencyManifests exclusion exists
// for on this branch: with NO excludes applied, the only files that differ
// under agent/ and proto/ relative to main's merge-base must be the four
// dependency manifests themselves. If this test ever fails because some
// other file also changed, that file needs its own review under SC-008 —
// it must not be silently swept in by widening dependencyManifests.
//
// On main (and on any branch with no agent/proto changes at all) this test
// passes trivially, since the unfiltered diff is then empty too.
func TestAgentAndProtoDiffWithoutExcludesIsOnlyDependencyManifests(t *testing.T) {
	repoRoot, ok := requireGitCheckout(t)
	if !ok {
		return
	}

	mergeBase, ok := resolveMergeBase(t, repoRoot)
	if !ok {
		return
	}

	diffArgs := append([]string{"diff", "--name-only", mergeBase, "--"}, guardedPaths...)
	out, err := runGit(repoRoot, diffArgs...)
	if err != nil {
		t.Fatalf("SC-008 guard: %v", err)
	}

	allowed := map[string]bool{
		"agent/go.mod": true,
		"agent/go.sum": true,
		"proto/go.mod": true,
		"proto/go.sum": true,
	}

	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return // nothing changed under agent/ or proto/ at all — fine.
	}

	for _, file := range strings.Split(trimmed, "\n") {
		if !allowed[file] {
			t.Fatalf("unfiltered agent/proto diff against merge-base %s with main contains %q, "+
				"which is not a dependency manifest — this file needs SC-008 review, not a widened "+
				"exclusion:\n\n%s", mergeBase, file, out)
		}
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
