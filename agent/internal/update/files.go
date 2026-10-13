// Package update implements the fixed Linux/systemd agent update protocol.
// It never accepts an install destination, service name, or download URL.
package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

const BinaryPath = "/usr/local/bin/veyport-agent"
const ConfigPath = "/etc/veyport/agent.conf"
const CertDir = "/etc/veyport/tls"
const Service = "veyport-agent.service"
const MaxArtifactBytes = 128 << 20

var operationPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{7,79}$`)

type paths struct {
	binary, journalDir, root                  string
	config, systemdDir, systemdRun, systemctl string
	uid                                       uint32
}

func fixedPaths() paths {
	return paths{binary: BinaryPath, journalDir: CertDir, root: "/", uid: 0, config: ConfigPath, systemdDir: "/run/systemd/system", systemdRun: "/usr/bin/systemd-run", systemctl: "/usr/bin/systemctl"}
}
func (p paths) journal() string { return filepath.Join(p.journalDir, "agent-update.json") }
func (p paths) stage(op string) string {
	return filepath.Join(filepath.Dir(p.binary), ".veyport-agent-update-"+op)
}
func (p paths) candidate(op string) string { return filepath.Join(p.stage(op), "candidate") }
func (p paths) backup(op string) string {
	return filepath.Join(filepath.Dir(p.binary), ".veyport-agent-backup-"+op)
}

type Metadata struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
}

type record struct {
	Schema    int      `json:"schema"`
	Operation string   `json:"operation_id"`
	Target    Metadata `json:"target"`
	Original  Metadata `json:"original"`
	Expires   int64    `json:"expires_unix_milli"`
	State     string   `json:"state"`
	Confirmed bool     `json:"confirmed"`
}

func (r record) active() bool { return !r.Confirmed && r.State != "failed" }
func validMetadata(m Metadata) bool {
	decoded, err := hex.DecodeString(m.SHA256)
	return err == nil && len(decoded) == sha256.Size && m.SHA256 == strings.ToLower(m.SHA256) && m.Version != "" && len(m.Version) < 128 && m.Revision != "" && len(m.Revision) < 128 && m.Bytes > 0 && m.Bytes <= MaxArtifactBytes
}
func (r record) validate() error {
	if r.Schema != 1 || !operationPattern.MatchString(r.Operation) || !validMetadata(r.Target) || !validMetadata(r.Original) || r.Expires <= 0 {
		return errors.New("invalid update journal binding")
	}
	switch r.State {
	case "downloading", "staged", "installing", "reconnecting", "rolling_back", "rolled_back", "succeeded", "failed":
	default:
		return errors.New("invalid update journal state")
	}
	if r.Confirmed && r.State != "succeeded" && r.State != "rolled_back" {
		return errors.New("invalid update confirmation")
	}
	return nil
}

// Every writable ancestor must be owned by the expected privileged identity.
// Lstat rejects symlinked directories; fixture roots stop the walk in tests.
func (p paths) checkDir(dir string, private bool) error {
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || (dir != p.root && !strings.HasPrefix(dir, strings.TrimSuffix(p.root, "/")+"/")) {
		return errors.New("update path outside installation")
	}
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Lstat(current, &st); err != nil {
			return err
		}
		if !info.IsDir() || st.Uid != p.uid || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("update directory is not protected: %s uid=%d mode=%o", current, st.Uid, info.Mode().Perm())
		}
		if current == dir && private && info.Mode().Perm()&0077 != 0 {
			return errors.New("update private directory permissions are too broad")
		}
		if current == p.root {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("update installation root not found")
		}
	}
	return nil
}

func (p paths) open(path string, flags int, mode uint32, private bool) (*os.File, error) {
	if err := p.checkDir(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != p.uid || st.Nlink != 1 || st.Mode&0022 != 0 || (private && st.Mode&0077 != 0) {
		_ = f.Close()
		return nil, errors.New("update file is not protected")
	}
	return f, nil
}

func (p paths) lock(name string) (*os.File, error) {
	if err := p.checkDir(p.journalDir, true); err != nil {
		return nil, err
	}
	f, err := p.open(filepath.Join(p.journalDir, name), unix.O_CREAT|unix.O_RDWR, 0600, true)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("another update process owns the installation")
	}
	return f, nil
}

func (p paths) read() (*record, error) {
	if err := p.checkDir(p.journalDir, true); err != nil {
		return nil, err
	}
	f, err := p.open(p.journal(), unix.O_RDONLY, 0, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 8193))
	decoder.DisallowUnknownFields()
	var r record
	if err := decoder.Decode(&r); err != nil {
		return nil, errors.New("malformed update journal")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("unexpected update journal data")
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (p paths) write(r record) error {
	if err := r.validate(); err != nil {
		return err
	}
	if err := p.checkDir(p.journalDir, true); err != nil {
		return err
	}
	if old, err := p.open(p.journal(), unix.O_RDONLY, 0, true); err == nil {
		_ = old.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(p.journalDir, ".agent-update-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if err == nil {
		err = tmp.Close()
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p.journal())
	}
	if err == nil {
		err = syncDirectory(p.journalDir)
	}
	return err
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func hashFile(f *os.File) (string, int64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, MaxArtifactBytes+1))
	if err != nil {
		return "", n, err
	}
	if n <= 0 || n > MaxArtifactBytes {
		return "", n, fmt.Errorf("invalid agent executable size")
	}
	return hex.EncodeToString(hash.Sum(nil)), n, nil
}
