package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/wyiu/veyport/proto/updateutil"
)

const MaxBinaryBytes int64 = 15 << 20
const metadataLimit int64 = 64 << 10
const updateTimeout = 2 * time.Minute

var revisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// Artifact describes the exact artifact approved by this Hub's distribution.
type Artifact struct {
	SchemaVersion int    `json:"schema_version"`
	Component     string `json:"component"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Version       string `json:"version"`
	Revision      string `json:"revision"`
	SHA256        string `json:"sha256"`
	Bytes         int64  `json:"bytes"`
	Path          string `json:"path"`
}

// Result reports a check or a verified installation. Backup is a retained
// copy of the previous executable, never a configuration or credential file.
type Result struct {
	Hub              string   `json:"hub"`
	CurrentVersion   string   `json:"current_version"`
	AvailableVersion string   `json:"available_version"`
	UpdateAvailable  bool     `json:"update_available"`
	Installed        bool     `json:"installed"`
	InstalledVersion string   `json:"installed_version,omitempty"`
	Backup           string   `json:"backup,omitempty"`
	Artifact         Artifact `json:"artifact"`
}

type updater struct {
	client            *http.Client
	osName, arch      string
	target            string
	executable        func() (string, error)
	validateInstalled func(context.Context, string, string) error
	currentRevision   string
}

func newUpdater() *updater {
	return &updater{client: &http.Client{Timeout: updateTimeout, CheckRedirect: rejectRedirect}, osName: runtime.GOOS, arch: runtime.GOARCH, target: InstallPath, executable: os.Executable, validateInstalled: runVersion}
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return fmt.Errorf("update redirects are refused; configure the final HTTPS Hub URL")
}

func validateHub(hub string) error {
	u, err := url.Parse(hub)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("updates require an HTTPS Hub base URL with a verified certificate and no path, userinfo, query or fragment")
	}
	return nil
}

func (u *updater) get(ctx context.Context, hub, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(hub, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch Hub distribution: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("Hub distribution returned HTTP %d; use a Hub with approved update metadata", resp.StatusCode)
	}
	return resp, nil
}

// Check fetches bounded metadata without opening any installation,
// configuration or credential files and without downloading executable code.
func Check(ctx context.Context, hub, current string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()
	return newUpdater().check(ctx, hub, current)
}

func (u *updater) check(ctx context.Context, hub, current string) (Result, error) {
	result := Result{Hub: hub, CurrentVersion: current}
	if err := updateutil.ValidateVersion(current); err != nil {
		return result, fmt.Errorf("cannot update the current CLI: %w", err)
	}
	if err := validateHub(hub); err != nil {
		return result, err
	}
	if (u.osName != "linux" && u.osName != "darwin") || (u.arch != "amd64" && u.arch != "arm64") {
		return result, fmt.Errorf("unsupported update platform %s/%s", u.osName, u.arch)
	}
	resp, err := u.get(ctx, hub, "/install/metadata/cli/"+u.osName+"/"+u.arch)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, metadataLimit+1))
	if err != nil {
		return result, fmt.Errorf("read update metadata: %w", err)
	}
	if len(data) > int(metadataLimit) {
		return result, fmt.Errorf("update metadata exceeds size limit")
	}
	if err = json.Unmarshal(data, &result.Artifact); err != nil {
		return result, fmt.Errorf("invalid update metadata: %w", err)
	}
	if err = u.validateMetadata(result.Artifact); err != nil {
		return result, err
	}
	comparison, err := updateutil.CompareVersions(result.Artifact.Version, current)
	if err != nil {
		return result, fmt.Errorf("cannot compare Hub version: %w", err)
	}
	result.AvailableVersion = result.Artifact.Version
	result.UpdateAvailable = comparison > 0
	return result, nil
}

func (u *updater) validateMetadata(a Artifact) error {
	hash, err := hex.DecodeString(a.SHA256)
	if a.SchemaVersion != 1 || a.Component != "cli" || a.OS != u.osName || a.Arch != u.arch || a.Path != "/install/cli/"+u.osName+"/"+u.arch || a.Bytes <= 0 || a.Bytes > MaxBinaryBytes || err != nil || len(hash) != sha256.Size || strings.ToLower(a.SHA256) != a.SHA256 || !revisionPattern.MatchString(a.Revision) {
		return fmt.Errorf("Hub update metadata has an invalid schema, platform, path, revision, checksum or size")
	}
	if err := updateutil.ValidateVersion(a.Version); err != nil {
		return fmt.Errorf("Hub update metadata: %w", err)
	}
	return nil
}

func verifyBinary(path string, a Artifact) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxBinaryBytes+1))
	if err != nil {
		return fmt.Errorf("hash update binary: %w", err)
	}
	if n != a.Bytes || fmt.Sprintf("%x", h.Sum(nil)) != a.SHA256 {
		return fmt.Errorf("update binary checksum or size differs from Hub metadata")
	}
	return updateutil.VerifyBuildIdentity(path, "github.com/wyiu/veyport/cli/cmd/vey", a.OS, a.Arch, a.Version, a.Revision)
}
