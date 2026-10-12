package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

var helperCoverageDir string

// Go ignores subprocess pods with a different executable metadata hash during
// test teardown. Convert both actual datasets after m.Run into its standard
// coverprofile; the existing CI artifact then includes the helper executions.
func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "veyport-helper-coverage-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	helperCoverageDir = directory
	code := m.Run()
	entries, readErr := os.ReadDir(directory)
	profile := flag.Lookup("test.coverprofile")
	if readErr == nil && len(entries) > 0 && testing.CoverMode() != "" && profile != nil && profile.Value.String() != "" {
		parentDirectory := os.Getenv("GOCOVERDIR")
		if parentDirectory == "" {
			fmt.Fprintln(os.Stderr, "standard Go coverage directory missing")
			code = 1
		} else {
			convert := exec.Command("go", "tool", "covdata", "textfmt", "-i="+parentDirectory+","+directory, "-o="+profile.Value.String())
			if output, err := convert.CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "merge actual helper execution coverage: %v %s\n", err, output)
				code = 1
			}
		}
	}
	if err := os.RemoveAll(directory); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

// These processes execute the actual main, including log.Fatal, inside a private
// root filesystem and mount namespace. They never reach a host service manager.
func TestUpdateHelperRefusalsPreserveEnrolledIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux mount namespace fixture")
	}
	prefix := []string{}
	if os.Geteuid() != 0 {
		if _, err := exec.LookPath("sudo"); err != nil {
			t.Skip("privileged Linux fixture requires passwordless sudo")
		}
		prefix = []string{"sudo", "-n"}
	}
	rootCommand := func(arguments ...string) *exec.Cmd {
		if len(prefix) == 0 {
			return exec.Command(arguments[0], arguments[1:]...)
		}
		return exec.Command(prefix[0], append(append([]string{}, prefix[1:]...), arguments...)...)
	}
	if output, err := rootCommand("unshare", "--mount", "--propagation", "private", "true").CombinedOutput(); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("Ubuntu CI must support isolated privileged fixtures: %v %s", err, output)
		}
		t.Skipf("private Linux mount namespace unavailable: %v", err)
	}
	buildDir := t.TempDir()
	binary := filepath.Join(buildDir, "veyport-agent")
	build := exec.Command("go", "build", "-race", "-cover", "-covermode=atomic", "-coverpkg=github.com/wyiu/veyport/agent/cmd/veyport-agent", "-ldflags", "-X main.version=0.2.0-prototype.4 -X main.revision="+strings.Repeat("a", 40), "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build instrumented helper fixture: %v %s", err, output)
	}
	dependencies, err := exec.Command("ldd", binary).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect fixture ELF dependencies: %v %s", err, dependencies)
	}
	copyFile := func(source, destination string, mode os.FileMode) {
		t.Helper()
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	ticket := strings.Repeat("x", 64)
	for _, fault := range []string{"alternate_config", "alternate_cert_dir", "insecure", "registration_token", "self_unregister", "mixed_helpers", "symlink_config", "broad_key_mode", "malformed_config", "missing_identity", "different_hub", "bootstrap_requires_mtls", "supervisor_requires_staging"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			fixture := filepath.Join(root, "root")
			if err := os.Mkdir(fixture, 0700); err != nil {
				t.Fatal(err)
			}
			copyFile(binary, filepath.Join(fixture, "usr/local/bin/veyport-agent"), 0755)
			for _, field := range strings.Fields(string(dependencies)) {
				if strings.HasPrefix(field, "/") {
					copyFile(field, filepath.Join(fixture, field), 0755)
				}
			}
			for _, dir := range []string{"etc/veyport/tls", "etc/veyport/tls/execution-journal", "proc", "coverage"} {
				if err := os.MkdirAll(filepath.Join(fixture, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			configuration := agentConfig{ServerID: "preserved-node", HubURL: "127.0.0.1:1", UnregisterToken: "fixture-private-unregister", HubCAPin: "fixture-ca-pin", AllowedPaths: []string{"/srv/preserved"}}
			data, err := json.Marshal(configuration)
			if err != nil {
				t.Fatal(err)
			}
			identity := map[string][]byte{"etc/veyport/agent.conf": data, "etc/veyport/tls/client.key": []byte("invalid fixture key"), "etc/veyport/tls/client.crt": []byte("invalid fixture certificate"), "etc/veyport/tls/ca.crt": []byte("invalid fixture CA"), "etc/veyport/tls/node_key.enc": []byte("preserved encrypted identity"), "etc/veyport/tls/node_transport.key": []byte("preserved transport identity"), "etc/veyport/tls/execution-journal/state.json": []byte("preserved execution journal")}
			if fault == "supervisor_requires_staging" {
				key, cert, ca := helperFixtureCertificates(t)
				identity["etc/veyport/tls/client.key"] = key
				identity["etc/veyport/tls/client.crt"] = cert
				identity["etc/veyport/tls/ca.crt"] = ca
			}
			if fault == "malformed_config" {
				identity["etc/veyport/agent.conf"] = []byte("malformed private fixture")
			}
			if fault == "missing_identity" {
				identity["etc/veyport/agent.conf"] = []byte(`{"hub_url":"127.0.0.1:1"}`)
			}
			for name, contents := range identity {
				if err := os.WriteFile(filepath.Join(fixture, name), contents, 0600); err != nil {
					t.Fatal(err)
				}
			}
			arguments := []string{"--update-bootstrap", ticket, "--update-hub", "https://127.0.0.1"}
			reason := "bootstrap requires existing enrolled mTLS"
			switch fault {
			case "alternate_config":
				arguments = append(arguments, "--config", "/tmp/other.conf")
				reason = "canonical existing enrolled configuration"
			case "alternate_cert_dir":
				arguments = append(arguments, "--cert-dir", "/tmp/other-tls")
				reason = "canonical existing enrolled configuration"
			case "insecure":
				arguments = append(arguments, "--insecure")
				reason = "canonical existing enrolled configuration"
			case "registration_token":
				arguments = append(arguments, "--token", "fixture-registration-token")
				reason = "canonical existing enrolled configuration"
			case "self_unregister":
				arguments = append(arguments, "--self-unregister")
				reason = "canonical existing enrolled configuration"
			case "mixed_helpers":
				arguments = append(arguments, "--update-supervisor", "fixture-operation")
				reason = "canonical existing enrolled configuration"
			case "symlink_config":
				if err := os.Rename(filepath.Join(fixture, "etc/veyport/agent.conf"), filepath.Join(fixture, "etc/veyport/config-backup")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("config-backup", filepath.Join(fixture, "etc/veyport/agent.conf")); err != nil {
					t.Fatal(err)
				}
				reason = "canonical enrolled identity is not protected"
			case "broad_key_mode":
				os.Chmod(filepath.Join(fixture, "etc/veyport/tls/client.key"), 0644)
				reason = "canonical enrolled identity is not protected"
			case "malformed_config", "missing_identity":
				reason = "requires an existing enrolled agent"
			case "different_hub":
				arguments = []string{"--update-bootstrap", ticket, "--update-hub", "https://different.example"}
				reason = "configured HTTPS Hub"
			case "supervisor_requires_staging":
				arguments = []string{"--update-supervisor", "fixture-operation"}
				reason = "private verified staging directory"
			}
			if output, err := rootCommand("chown", "-hR", "0:0", "--", fixture).CombinedOutput(); err != nil {
				t.Fatalf("protect isolated fixture: %v %s", err, output)
			}
			restoreOwner := func() {
				if output, err := rootCommand("chown", "-hR", strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid()), "--", fixture).CombinedOutput(); err != nil {
					t.Errorf("restore fixture ownership: %v %s", err, output)
				}
			}
			defer restoreOwner()
			command := rootCommand("env", "-i", "PATH=/usr/bin:/bin", "LANG=C", "HOME=/root", "GOCOVERDIR=/coverage", "timeout", "--signal=TERM", "--kill-after=2s", "15s", "unshare", "--mount", "--propagation", "private", "--root", fixture, "--mount-proc=/proc", "/usr/local/bin/veyport-agent")
			command.Args = append(command.Args, arguments...)
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), reason) {
				t.Fatalf("helper refusal=%v want=%q output=%s", err, reason, output)
			}
			if strings.Contains(string(output), ticket) || strings.Contains(string(output), configuration.UnregisterToken) || strings.Contains(string(output), "fixture-registration-token") {
				t.Fatal("helper exposed a fixture credential")
			}
			restoreOwner()
			for name, contents := range identity {
				current, err := os.ReadFile(filepath.Join(fixture, name))
				if err != nil || sha256.Sum256(current) != sha256.Sum256(contents) {
					t.Fatalf("helper altered enrolled file %s: %v", name, err)
				}
			}
			if testing.CoverMode() != "" {
				entries, err := os.ReadDir(filepath.Join(fixture, "coverage"))
				if err != nil || len(entries) == 0 {
					t.Fatalf("helper emitted no actual execution coverage: %v", err)
				}
				for _, entry := range entries {
					if entry.IsDir() {
						t.Fatal("unexpected coverage directory")
					}
					copyFile(filepath.Join(fixture, "coverage", entry.Name()), filepath.Join(helperCoverageDir, entry.Name()), 0600)
				}
			}
		})
	}
}

func helperFixtureCertificates(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "preserved-node"}, NotBefore: caTemplate.NotBefore, NotAfter: caTemplate.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	certDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
