package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The harness rewrites privileged installation paths into a private fixture and
// replaces the final helper execution with a marker. No host files, service or
// network is changed; the actual production shell parsing/verification runs.
func TestBootstrapScriptRejectsSourceIdentityAndArtifactFaults(t *testing.T) {
	source, err := os.ReadFile("../../../hub/static/agent-update.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"valid", "source", "config_mode", "cert_symlink", "tls_mode", "checksum", "truncated", "platform", "manifest_path"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			os.Chmod(root, 0700)
			bin := filepath.Join(root, "bin")
			cfg := filepath.Join(root, "etc")
			tls := filepath.Join(cfg, "tls")
			systemd := filepath.Join(root, "systemd")
			tools := filepath.Join(root, "tools")
			for _, dir := range []string{bin, cfg, tls, systemd, tools} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			config := filepath.Join(cfg, "agent.conf")
			os.WriteFile(config, []byte("{\n  \"hub_url\": \"hub.test:9090\"\n}\n"), 0600)
			for _, name := range []string{"client.key", "client.crt", "ca.crt"} {
				os.WriteFile(filepath.Join(tls, name), []byte("fixture identity"), 0600)
			}
			os.WriteFile(filepath.Join(bin, "veyport-agent"), []byte("preserved old fixture agent"), 0755)
			data := make([]byte, 256)
			copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1})
			data[18] = 0x3e
			sum := sha256.Sum256(data)
			sha := hex.EncodeToString(sum[:])
			size := len(data)
			path := "/install/linux/amd64"
			switch fault {
			case "config_mode":
				os.Chmod(config, 0644)
			case "cert_symlink":
				os.Remove(filepath.Join(tls, "client.key"))
				os.Symlink(config, filepath.Join(tls, "client.key"))
			case "tls_mode":
				os.Chmod(tls, 0755)
			case "checksum":
				data[50] = 1
			case "truncated":
				data = data[:len(data)-1]
			case "platform":
				data[18] = 0xb7
				sum = sha256.Sum256(data)
				sha = hex.EncodeToString(sum[:])
			case "manifest_path":
				path = "/unsafe"
			}
			artifact := filepath.Join(root, "artifact")
			os.WriteFile(artifact, data, 0600)
			metadata := filepath.Join(root, "metadata")
			os.WriteFile(metadata, []byte(fmt.Sprintf(`{"schema_version":1,"component":"agent","os":"linux","arch":"amd64","version":"0.2.0-prototype.4","revision":"%s","sha256":"%s","bytes":%d,"path":"%s"}`, strings.Repeat("a", 40), sha, size, path)), 0600)
			fakeCurl := "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$*\" >> \"$FIXTURE_CURL_LOG\"\nout=''\nurl=''\nwhile (($#)); do case \"$1\" in --output) out=\"$2\";shift 2;; *) url=\"$1\";shift;; esac;done\ncase \"$url\" in *metadata*) cp \"$FIXTURE_METADATA\" \"$out\";; *) cp \"$FIXTURE_ARTIFACT\" \"$out\";; esac\n"
			os.WriteFile(filepath.Join(tools, "curl"), []byte(fakeCurl), 0700)
			script := string(source)
			for _, replacement := range [][2]string{{"/usr/local/bin", bin}, {"/etc/veyport/tls", tls}, {"/etc/veyport", cfg}, {"/run/systemd/system", systemd}, {"for dir in /usr /usr/local ", "for dir in "}, {" /etc ", " "}, {"${EUID} -eq 0", fmt.Sprintf("${EUID} -eq %d", os.Geteuid())}, {"== '0:600:1'", fmt.Sprintf("== '%d:600:1'", os.Getuid())}, {"== 0 ]]", fmt.Sprintf("== %d ]]", os.Getuid())}, {`"$workdir/candidate" --update-bootstrap "$ticket" --update-hub "$hub"`, `printf 'FIXTURE_VERIFIED_CANDIDATE\n'`}} {
				script = strings.ReplaceAll(script, replacement[0], replacement[1])
			}
			scriptPath := filepath.Join(root, "bootstrap.sh")
			os.WriteFile(scriptPath, []byte(script), 0700)
			hub := "https://hub.test"
			if fault == "source" {
				hub = "https://other.test"
			}
			cmd := exec.Command("bash", scriptPath, "--hub", hub, "--ticket", strings.Repeat("x", 64))
			cmd.Env = append(os.Environ(), "PATH="+tools+":"+os.Getenv("PATH"), "FIXTURE_METADATA="+metadata, "FIXTURE_ARTIFACT="+artifact, "FIXTURE_CURL_LOG="+filepath.Join(root, "curl-log"))
			output, err := cmd.CombinedOutput()
			verified := strings.Contains(string(output), "FIXTURE_VERIFIED_CANDIDATE")
			if fault == "valid" {
				if err != nil || !verified {
					t.Fatalf("valid script refused: %v %s", err, output)
				}
			} else if err == nil || verified {
				t.Fatalf("unsafe script passed: %s", output)
			}
			if log, err := os.ReadFile(filepath.Join(root, "curl-log")); err == nil {
				if !strings.Contains(string(log), "--proto =https") || !strings.Contains(string(log), "--max-redirs 0") || !strings.Contains(string(log), "--max-time") {
					t.Fatal("download omitted trust/time bounds")
				}
			}
			identity, _ := os.ReadFile(config)
			if string(identity) != "{\n  \"hub_url\": \"hub.test:9090\"\n}\n" {
				t.Fatal("bootstrap modified enrolled configuration")
			}
		})
	}
}
