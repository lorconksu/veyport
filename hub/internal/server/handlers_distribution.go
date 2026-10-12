package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/wyiu/veyport/proto/updateutil"
)

// Revision is stamped with the exact source revision in release builds.
// Development Hubs still start; update metadata fails closed when unstamped.
var Revision = "unknown"

const distributionManifestLimit int64 = 64 << 10
const distributionBinaryLimit int64 = 128 << 20

var distributionRevision = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

type distributionArtifact struct {
	SchemaVersion int    `json:"schema_version"`
	Component     string `json:"component"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Version       string `json:"version"`
	Revision      string `json:"revision"`
	SHA256        string `json:"sha256"`
	Bytes         int64  `json:"bytes"`
	Path          string `json:"path"`
	BinaryPath    string `json:"-"`
}

type distributionManifest struct {
	SchemaVersion int    `json:"schema_version"`
	Version       string `json:"version"`
	Revision      string `json:"revision"`
	Binaries      []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	} `json:"binaries"`
}

// At most six allowlisted platform entries exist per Hub. Only immutable
// file identities with unchanged stat metadata reuse a verified digest.
type distributionCacheEntry struct {
	manifestInfo os.FileInfo
	binaryInfo   os.FileInfo
	artifact     distributionArtifact
}

func unchangedDistributionFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func distributionName(component, osName, arch string) (string, string, int64, error) {
	if !isValidCLIPlatform(osName, arch) {
		return "", "", 0, fmt.Errorf("unsupported platform")
	}
	switch component {
	case "cli":
		return "vey-" + osName + "-" + arch, "/install/cli/" + osName + "/" + arch, 15 << 20, nil
	case "agent":
		if osName == "linux" {
			return "veyport-agent-" + osName + "-" + arch, "/install/" + osName + "/" + arch, distributionBinaryLimit, nil
		}
	}
	return "", "", 0, fmt.Errorf("unsupported distribution component or platform")
}

// resolveDistribution verifies the fixed build manifest and bytes served by
// this Hub. Clients receive only a fixed public artifact path, never local paths.
func (s *Server) resolveDistribution(component, osName, arch string) (distributionArtifact, error) {
	s.distributionMu.Lock()
	defer s.distributionMu.Unlock()
	var empty distributionArtifact
	name, path, maxBytes, err := distributionName(component, osName, arch)
	if err != nil {
		return empty, err
	}
	manifestPath := filepath.Join(s.agentBinDir, "artifact-manifest.json")
	manifestInfo, err := statDistributionManifest(manifestPath)
	if err != nil {
		return empty, err
	}
	binaryInfo, statErr := os.Lstat(filepath.Join(s.agentBinDir, name))
	if cached, ok := s.distributionCache[name]; ok && statErr == nil && cached.artifact.Version == Version && cached.artifact.Revision == Revision && unchangedDistributionFile(cached.manifestInfo, manifestInfo) && unchangedDistributionFile(cached.binaryInfo, binaryInfo) {
		return cached.artifact, nil
	}
	manifest, err := readDistributionManifest(manifestPath)
	if err != nil {
		return empty, err
	}
	query := distributionRequest{component, osName, arch, name, path, maxBytes}
	result, err := s.artifactFromManifest(manifest, query)
	if err != nil {
		return empty, err
	}
	binaryInfo, err = verifyDistributionArtifact(result, maxBytes)
	if err != nil {
		return empty, err
	}
	finalManifest, manifestErr := os.Lstat(manifestPath)
	finalBinary, binaryErr := os.Lstat(result.BinaryPath)
	if manifestErr != nil || binaryErr != nil || !unchangedDistributionFile(manifestInfo, finalManifest) || !unchangedDistributionFile(binaryInfo, finalBinary) {
		return empty, fmt.Errorf("distribution files changed during verification")
	}
	if s.distributionCache == nil {
		s.distributionCache = make(map[string]distributionCacheEntry, 6)
	}
	s.distributionCache[name] = distributionCacheEntry{manifestInfo: finalManifest, binaryInfo: finalBinary, artifact: result}
	return result, nil
}

type distributionRequest struct {
	component, osName, arch, name, path string
	maxBytes                            int64
}

func statDistributionManifest(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("approved distribution manifest is unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > distributionManifestLimit {
		return nil, fmt.Errorf("invalid approved distribution manifest")
	}
	return info, nil
}

func readDistributionManifest(path string) (distributionManifest, error) {
	var manifest distributionManifest
	f, err := os.Open(path)
	if err != nil {
		return manifest, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, distributionManifestLimit+1))
	if err != nil {
		return manifest, err
	}
	if len(data) > int(distributionManifestLimit) {
		return manifest, fmt.Errorf("approved distribution manifest exceeds size limit")
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("invalid approved distribution manifest: %w", err)
	}
	if manifest.SchemaVersion != 1 || updateutil.ValidateVersion(manifest.Version) != nil || !distributionRevision.MatchString(manifest.Revision) || manifest.Version != Version || manifest.Revision != Revision {
		return manifest, fmt.Errorf("approved manifest does not match this versioned Hub revision")
	}
	return manifest, nil
}

func (s *Server) artifactFromManifest(manifest distributionManifest, q distributionRequest) (distributionArtifact, error) {
	var result distributionArtifact
	found := false
	for _, entry := range manifest.Binaries {
		if entry.Path != q.name {
			continue
		}
		if found {
			return result, fmt.Errorf("duplicate approved artifact")
		}
		found = true
		hash, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(hash) != sha256.Size || strings.ToLower(entry.SHA256) != entry.SHA256 || entry.Bytes <= 0 || entry.Bytes > q.maxBytes {
			return result, fmt.Errorf("invalid approved artifact digest or size")
		}
		result = distributionArtifact{SchemaVersion: 1, Component: q.component, OS: q.osName, Arch: q.arch, Version: manifest.Version, Revision: manifest.Revision, SHA256: entry.SHA256, Bytes: entry.Bytes, Path: q.path, BinaryPath: filepath.Join(s.agentBinDir, q.name)}
	}
	if !found {
		return result, fmt.Errorf("approved artifact is missing from the distribution manifest")
	}
	return result, nil
}

func verifyDistributionArtifact(a distributionArtifact, maxBytes int64) (os.FileInfo, error) {
	info, err := os.Lstat(a.BinaryPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() != a.Bytes {
		return nil, fmt.Errorf("approved artifact is unavailable or has a different size")
	}
	binary, err := os.Open(a.BinaryPath)
	if err != nil {
		return nil, err
	}
	defer binary.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(binary, maxBytes+1))
	if err != nil || n != a.Bytes || fmt.Sprintf("%x", h.Sum(nil)) != a.SHA256 {
		return nil, fmt.Errorf("approved artifact differs from its manifest digest")
	}
	packagePath := "github.com/wyiu/veyport/cli/cmd/vey"
	if a.Component == "agent" {
		packagePath = "github.com/wyiu/veyport/agent/cmd/veyport-agent"
	}
	if err = updateutil.VerifyBuildIdentity(a.BinaryPath, packagePath, a.OS, a.Arch, a.Version, a.Revision); err != nil {
		return nil, err
	}
	return info, nil
}

func (s *Server) handleDistributionMetadata(w http.ResponseWriter, r *http.Request) {
	component, osName, arch := r.PathValue("component"), r.PathValue("os"), r.PathValue("arch")
	if _, _, _, err := distributionName(component, osName, arch); err != nil {
		respondError(w, http.StatusNotFound, "unsupported distribution platform")
		return
	}
	artifact, err := s.resolveDistribution(component, osName, arch)
	if err != nil {
		respondError(w, http.StatusServiceUnavailable, "approved update distribution is unavailable; deploy a versioned Hub with its matching artifact manifest")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, artifact)
}
