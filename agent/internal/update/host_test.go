package update

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
)

func TestSupportedHostProbeAndFailClosedRecovery(t *testing.T) {
	for _, fault := range []string{"supported", "os", "arch", "nonroot", "config", "certdir", "insecure", "executable", "tls_permissions", "config_symlink", "systemd_missing", "tool_missing", "version", "revision", "malformed_journal", "active_busy", "active_idle", "failed_journal"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := installation(t)
			p.config = filepath.Join(p.root, "agent.conf")
			p.systemdDir = filepath.Join(p.root, "systemd")
			p.systemdRun = filepath.Join(p.root, "systemd-run")
			p.systemctl = filepath.Join(p.root, "systemctl")
			os.WriteFile(p.config, []byte(`{"server_id":"existing-node","hub_url":"hub:9090"}`), 0600)
			os.Mkdir(p.systemdDir, 0700)
			for _, tool := range []string{p.systemdRun, p.systemctl} {
				os.WriteFile(tool, []byte("fixture only, never executed"), 0755)
			}
			host := hostEnvironment{paths: p, executable: p.binary, uid: 0, os: "linux", arch: runtime.GOARCH}
			config, certdir, version, revision, insecure := p.config, p.journalDir, oldMetadata.Version, oldMetadata.Revision, false
			budget := sessionlimit.New(8)
			switch fault {
			case "os":
				host.os = "darwin"
			case "arch":
				host.arch = "386"
			case "nonroot":
				host.uid = 1000
			case "config":
				config += ".other"
			case "certdir":
				certdir += ".other"
			case "insecure":
				insecure = true
			case "executable":
				host.executable = p.systemctl
			case "tls_permissions":
				os.Chmod(p.journalDir, 0755)
			case "config_symlink":
				os.Remove(p.config)
				os.Symlink(p.binary, p.config)
			case "systemd_missing":
				os.Remove(p.systemdDir)
			case "tool_missing":
				os.Remove(p.systemctl)
			case "version":
				version = "1.0.0"
			case "revision":
				revision = "unknown"
			case "malformed_journal":
				os.WriteFile(p.journal(), []byte("malformed"), 0600)
			case "active_busy", "active_idle":
				entry.State = "downloading"
				p.write(entry)
				if fault == "active_busy" {
					budget.Acquire()
				}
			case "failed_journal":
				entry.State = "failed"
				p.write(entry)
			}
			r := newRuntime(version, revision, config, certdir, insecure, budget, host)
			caps := r.Capabilities()
			expectedSupported := fault == "supported" || fault == "active_idle" || fault == "failed_journal"
			if caps.Supported != expectedSupported {
				t.Fatalf("supported=%v reason=%s", caps.Supported, caps.Reason)
			}
			if fault == "active_idle" && budget.Acquire() {
				t.Fatal("pending journal did not reserve exclusive admission")
			}
			if fault == "failed_journal" && !budget.Acquire() {
				t.Fatal("terminal failure blocked ordinary execution")
			}
			if !expectedSupported && caps.Reason == "" {
				t.Fatal("unsupported host omitted actionable reason")
			}
		})
	}
}
