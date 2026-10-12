package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureArtifacts(t *testing.T, dir string) {
	t.Helper()
	names := []string{"veyport"}
	for _, name := range []string{"veyport-agent", "veyport-audit-ingest", "veyport-audit-export"} {
		for _, arch := range []string{"amd64", "arm64"} {
			names = append(names, name+"-linux-"+arch)
		}
	}
	for _, system := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			names = append(names, "vey-"+system+"-"+arch)
		}
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("artifact fixture "+name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDockerManifestMatchesReleaseManifestExactly(t *testing.T) {
	dir := t.TempDir()
	fixtureArtifacts(t, dir)
	version, revision := "2.0.50-prototype.4", strings.Repeat("a", 40)
	if err := writeManifest(dir, version, revision); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "artifact-manifest.json")
	generated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "../../../scripts/release/artifacts.py", "--directory", dir, "--version", version, "--revision", revision)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("release manifest generation: %v: %s", err, output)
	}
	release, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, release) {
		t.Fatalf("Docker manifest differs from exact release manifest:\n%s\n%s", generated, release)
	}
}

func TestDevManifestBuildsWithoutAdvertisingReleaseIdentity(t *testing.T) {
	dir := t.TempDir()
	fixtureArtifacts(t, dir)
	if err := writeManifest(dir, "dev", "unknown"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "artifact-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct{ Version, Revision string }
	if err = json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Version != "dev" || payload.Revision != "unknown" {
		t.Fatal("dev identity changed")
	}
}

func TestManifestRejectsMissingUnsafeAndOversizedArtifacts(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "empty", "oversize", "cli_oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			fixtureArtifacts(t, dir)
			path := filepath.Join(dir, "veyport")
			switch kind {
			case "missing":
				_ = os.Remove(path)
			case "symlink":
				_ = os.Rename(path, path+"-real")
				_ = os.Symlink(path+"-real", path)
			case "empty":
				_ = os.Truncate(path, 0)
			case "oversize":
				_ = os.Truncate(path, (128<<20)+1)
			case "cli_oversize":
				_ = os.Truncate(filepath.Join(dir, "vey-linux-amd64"), (15<<20)+1)
			}
			if err := writeManifest(dir, "dev", "unknown"); err == nil {
				t.Fatal("accepted invalid artifact")
			}
			if _, err := os.Stat(filepath.Join(dir, "artifact-manifest.json")); err == nil {
				t.Fatal("wrote manifest for invalid artifact")
			}
		})
	}
}

func TestManifestCommandAndWriteFailures(t *testing.T) {
	dir := t.TempDir()
	fixtureArtifacts(t, dir)
	for _, tc := range []struct {
		args []string
		code int
	}{
		{nil, 2}, {[]string{"--unknown"}, 2}, {[]string{"--directory", dir, "extra"}, 2},
		{[]string{"--directory", dir + "-missing"}, 1},
		{[]string{"--directory", dir}, 0},
	} {
		var stderr bytes.Buffer
		if code := run(tc.args, &stderr); code != tc.code {
			t.Fatalf("args=%v code=%d err=%s", tc.args, code, stderr.String())
		}
	}
	if os.Geteuid() != 0 {
		path := filepath.Join(dir, "veyport")
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		if err := writeManifest(dir, "dev", "unknown"); err == nil {
			t.Fatal("accepted unreadable artifact")
		}
		_ = os.Chmod(path, 0o755)
		_ = os.Remove(filepath.Join(dir, "artifact-manifest.json"))
		_ = os.Chmod(dir, 0o555)
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if err := writeManifest(dir, "dev", "unknown"); err == nil {
			t.Fatal("silently accepted non-writable manifest destination")
		}
	}
}
