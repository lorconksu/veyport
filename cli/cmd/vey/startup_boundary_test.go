package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

var entrypointCoverageDir string

// Include the actual process entrypoint in the standard Go test profile, using
// native atomic counters from the same unchanged source and toolchain.
func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "vey-entrypoint-coverage-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	entrypointCoverageDir = directory
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
				fmt.Fprintf(os.Stderr, "merge native entrypoint execution coverage: %v %s\n", err, output)
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

func TestNativeEntrypointVersionPreservesConfiguration(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "vey")
	buildArgs := []string{"build", "-o", binary, "-ldflags", "-X main.version=2.0.50-prototype.4"}
	if mode := testing.CoverMode(); mode != "" {
		buildArgs = append(buildArgs, "-cover", "-covermode="+mode, "-coverpkg=github.com/wyiu/veyport/cli/cmd/vey")
	}
	buildArgs = append(buildArgs, ".")
	if output, err := exec.Command("go", buildArgs...).CombinedOutput(); err != nil {
		t.Fatalf("build native CLI fixture: %v %s", err, output)
	}
	// The binary and config base use distinct paths; malformed configuration
	// must remain irrelevant to the process's global version flag.
	configDirectory := filepath.Join(directory, "config", "vey")
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDirectory, "config.json")
	before := []byte("invalid private configuration fixture")
	if err := os.WriteFile(configPath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "--version")
	command.Env = append(os.Environ(), "XDG_CONFIG_HOME="+filepath.Dir(configDirectory), "GOCOVERDIR="+entrypointCoverageDir)
	output, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "vey 2.0.50-prototype.4" {
		t.Fatalf("native version exit/output: %v %s", err, output)
	}
	after, err := os.ReadFile(configPath)
	if err != nil || string(after) != string(before) {
		t.Fatal("version process changed configuration")
	}
}

func TestStartupRefusalsDoNotDispatchOrChangeConfiguration(t *testing.T) {
	for _, fault := range []string{"invalid_flag", "missing_home", "malformed_config", "config_is_directory"} {
		t.Run(fault, func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", base)
			args := []string{"--hub", "https://hub.example", "--json", "update", "--check"}
			configDirectory := filepath.Join(base, "vey")
			if err := os.Mkdir(configDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(configDirectory, "config.json")
			before := []byte("invalid private configuration fixture")
			wantCode, diagnostic := cmdutil.ExitError, "config:"
			switch fault {
			case "invalid_flag":
				args, wantCode, diagnostic = []string{"--unrecognized-global-flag"}, cmdutil.ExitUsage, "usage:"
			case "missing_home":
				t.Setenv("XDG_CONFIG_HOME", "")
				t.Setenv("HOME", "")
				diagnostic = "HOME"
			case "malformed_config":
				if err := os.WriteFile(configPath, before, 0o600); err != nil {
					t.Fatal(err)
				}
			case "config_is_directory":
				if err := os.Mkdir(configPath, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			code := -1
			out, stderr := captureOutput(t, func() { code = run(args) })
			if code != wantCode || out != "" || !strings.Contains(stderr, diagnostic) || strings.Contains(stderr, string(before)) {
				t.Fatalf("startup error: code=%d out=%q stderr=%q", code, out, stderr)
			}
			if fault == "malformed_config" {
				after, err := os.ReadFile(configPath)
				if err != nil || string(after) != string(before) {
					t.Fatal("startup failure changed configuration")
				}
			}
		})
	}
}
