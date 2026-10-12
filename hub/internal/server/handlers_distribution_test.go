package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const distributionFixtureVersion = "v2.0.50-prototype.4"
const distributionFixtureRevision = "0123456789abcdef0123456789abcdef01234567"

func distributionFixture(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vey")
	cmd := exec.Command("go", "build", "-ldflags", "-X main.version="+distributionFixtureVersion+" -X main.revision="+distributionFixtureRevision, "-o", path, "./cmd/vey")
	cmd.Dir = "../../../cli"
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI distribution fixture: %v: %s", err, output)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeDistribution(t *testing.T, dir string, data []byte) (string, distributionManifest) {
	t.Helper()
	name := "vey-" + runtime.GOOS + "-" + runtime.GOARCH
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
		t.Fatal(err)
	}
	var manifest distributionManifest
	manifest.SchemaVersion = 1
	manifest.Version = distributionFixtureVersion
	manifest.Revision = distributionFixtureRevision
	manifest.Binaries = append(manifest.Binaries, struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	}{name, fmt.Sprintf("%x", sha256.Sum256(data)), int64(len(data))})
	writeDistributionManifest(t, dir, manifest)
	return name, manifest
}

func writeDistributionManifest(t *testing.T, dir string, manifest distributionManifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "artifact-manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDistributionMetadataAndCache(t *testing.T) {
	data := distributionFixture(t)
	oldVersion, oldRevision := Version, Revision
	Version, Revision = distributionFixtureVersion, distributionFixtureRevision
	t.Cleanup(func() { Version, Revision = oldVersion, oldRevision })
	s := testServer(t)
	s.agentBinDir = t.TempDir()
	name, _ := writeDistribution(t, s.agentBinDir, data)
	path := "/install/metadata/cli/" + runtime.GOOS + "/" + runtime.GOARCH
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("status=%d body=%s", w.Code, w.Body)
		}
		var a distributionArtifact
		if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		if a.Version != Version || a.Revision != Revision || a.BinaryPath != "" || strings.Contains(w.Body.String(), s.agentBinDir) {
			t.Fatal("incorrect catalog identity or leaked local path")
		}
	}
	if len(s.distributionCache) != 1 {
		t.Fatal("cache not bounded by artifact entry")
	}
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			if _, err := s.resolveDistribution("cli", runtime.GOOS, runtime.GOARCH); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	changed := append([]byte(nil), data...)
	changed[len(changed)-1] ^= 1
	if err := os.WriteFile(filepath.Join(s.agentBinDir, name), changed, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveDistribution("cli", runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("served stale cached metadata after corruption")
	}
}

func TestDistributionRefusesInvalidManifestAndArtifact(t *testing.T) {
	data := distributionFixture(t)
	oldVersion, oldRevision := Version, Revision
	Version, Revision = distributionFixtureVersion, distributionFixtureRevision
	t.Cleanup(func() { Version, Revision = oldVersion, oldRevision })
	for _, kind := range []string{"missing_manifest", "manifest_symlink", "oversized_manifest", "malformed_manifest", "unreadable_manifest", "schema", "version", "revision", "invalid_hash", "invalid_size", "oversized_binary", "missing_entry", "different_entry", "duplicate_entry", "binary_missing", "binary_symlink", "binary_corrupt", "unreadable_binary", "wrong_build_identity"} {
		t.Run(kind, func(t *testing.T) {
			s := &Server{agentBinDir: t.TempDir()}
			name, m := writeDistribution(t, s.agentBinDir, data)
			manifestPath := filepath.Join(s.agentBinDir, "artifact-manifest.json")
			binaryPath := filepath.Join(s.agentBinDir, name)
			switch kind {
			case "unreadable_manifest":
				if os.Geteuid() == 0 {
					t.Skip("requires unprivileged process")
				}
				_ = os.Chmod(manifestPath, 0)
			case "unreadable_binary":
				if os.Geteuid() == 0 {
					t.Skip("requires unprivileged process")
				}
				_ = os.Chmod(binaryPath, 0)
			case "missing_manifest":
				_ = os.Remove(manifestPath)
			case "manifest_symlink":
				_ = os.Rename(manifestPath, manifestPath+"-real")
				_ = os.Symlink(manifestPath+"-real", manifestPath)
			case "oversized_manifest":
				_ = os.WriteFile(manifestPath, []byte(strings.Repeat("x", int(distributionManifestLimit+1))), 0o644)
			case "malformed_manifest":
				_ = os.WriteFile(manifestPath, []byte("{bad"), 0o644)
			case "schema":
				m.SchemaVersion = 2
				writeDistributionManifest(t, s.agentBinDir, m)
			case "version":
				m.Version = "dev"
				writeDistributionManifest(t, s.agentBinDir, m)
			case "revision":
				m.Revision = strings.Repeat("a", 40)
				writeDistributionManifest(t, s.agentBinDir, m)
			case "invalid_hash":
				m.Binaries[0].SHA256 = "bad"
				writeDistributionManifest(t, s.agentBinDir, m)
			case "invalid_size":
				m.Binaries[0].Bytes = 0
				writeDistributionManifest(t, s.agentBinDir, m)
			case "oversized_binary":
				m.Binaries[0].Bytes = 16 << 20
				writeDistributionManifest(t, s.agentBinDir, m)
			case "missing_entry":
				m.Binaries = nil
				writeDistributionManifest(t, s.agentBinDir, m)
			case "different_entry":
				m.Binaries[0].Path = "other-artifact"
				writeDistributionManifest(t, s.agentBinDir, m)
			case "duplicate_entry":
				m.Binaries = append(m.Binaries, m.Binaries[0])
				writeDistributionManifest(t, s.agentBinDir, m)
			case "binary_missing":
				_ = os.Remove(binaryPath)
			case "binary_symlink":
				_ = os.Rename(binaryPath, binaryPath+"-real")
				_ = os.Symlink(binaryPath+"-real", binaryPath)
			case "binary_corrupt":
				_ = os.WriteFile(binaryPath, []byte("corrupt"), 0o755)
			case "wrong_build_identity":
				fake := []byte("not a Go binary")
				m.Binaries[0].Bytes = int64(len(fake))
				m.Binaries[0].SHA256 = fmt.Sprintf("%x", sha256.Sum256(fake))
				_ = os.WriteFile(binaryPath, fake, 0o755)
				writeDistributionManifest(t, s.agentBinDir, m)
			}
			if _, err := s.resolveDistribution("cli", runtime.GOOS, runtime.GOARCH); err == nil {
				t.Fatal("accepted unapproved distribution")
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/unused", nil)
			r.SetPathValue("component", "cli")
			r.SetPathValue("os", runtime.GOOS)
			r.SetPathValue("arch", runtime.GOARCH)
			s.handleDistributionMetadata(w, r)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "matching artifact manifest") {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
		})
	}
	for _, p := range [][3]string{{"cli", "windows", "amd64"}, {"cli", "linux", "../etc"}, {"agent", "darwin", "amd64"}, {"arbitrary", "linux", "amd64"}} {
		if _, _, _, err := distributionName(p[0], p[1], p[2]); err == nil {
			t.Fatal("accepted unsupported platform")
		}
		s := &Server{}
		if _, err := s.resolveDistribution(p[0], p[1], p[2]); err == nil {
			t.Fatal("resolver accepted unsupported platform")
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/unused", nil)
		r.SetPathValue("component", p[0])
		r.SetPathValue("os", p[1])
		r.SetPathValue("arch", p[2])
		s.handleDistributionMetadata(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("unsupported platform status=%d", w.Code)
		}
	}
	if name, path, size, err := distributionName("agent", "linux", "amd64"); err != nil || name != "veyport-agent-linux-amd64" || path != "/install/linux/amd64" || size != distributionBinaryLimit {
		t.Fatal("invalid agent distribution mapping")
	}
	Version, Revision = "dev", "unknown"
	s := &Server{agentBinDir: t.TempDir()}
	writeDistribution(t, s.agentBinDir, data)
	if _, err := s.resolveDistribution("cli", runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("dev Hub advertised release metadata")
	}
}
