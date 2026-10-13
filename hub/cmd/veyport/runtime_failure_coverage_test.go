package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/testaudit"
)

func TestServerRuntimeWiringKeepsStandardIndependentOfEncryptedSpool(t *testing.T) {
	fixture := testaudit.New(t, nil)
	for _, tc := range []struct {
		name, runtime, want string
	}{
		{"missing-explicit-config", filepath.Join(t.TempDir(), "missing.json"), "load protected audit runtime"},
		{"valid-archive-without-protected-storage", fixture.ConfigFile(t), "missing port in address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			originalArgs, originalFlags := os.Args, flag.CommandLine
			defer func() { os.Args, flag.CommandLine = originalArgs, originalFlags }()
			directory := t.TempDir()
			// An invalid HTTP bind stops the complete real startup before serving
			// clients. Other listeners use ephemeral loopback ports and the
			// runServer shutdown context owns their cleanup on return.
			os.Args = []string{"veyport", "--db", filepath.Join(directory, "hub.db"), "--addr", "invalid-bind-address", "--grpc-addr", "127.0.0.1:0", "--ssh-addr", "127.0.0.1:0", "--audit-runtime-config", tc.runtime, "--execution-spool-dir", filepath.Join(directory, "unprovisioned-spool")}
			flag.CommandLine = flag.NewFlagSet(tc.name, flag.ContinueOnError)
			err := runServer()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("startup error=%v, want stage %q", err, tc.want)
			}
			if _, err = os.Stat(filepath.Join(directory, ".veyport-security", "installation-id")); err != nil {
				t.Fatal("runtime wiring skipped durable installation identity:", err)
			}
		})
	}
}
