package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/server"
)

func TestVersionReturnsBeforeDatabaseOrRuntimeConfiguration(t *testing.T) {
	args, flags, output := os.Args, flag.CommandLine, os.Stdout
	defer func() { os.Args, flag.CommandLine, os.Stdout = args, flags, output }()
	db := filepath.Join(t.TempDir(), "must-not-be-created.db")
	os.Args = []string{"veyport", "--version", "--db", db, "--audit-runtime-config", "/missing/private/config"}
	flag.CommandLine = flag.NewFlagSet("veyport", flag.ContinueOnError)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	os.Stdout = writer
	if err := runServer(); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil || strings.TrimSpace(string(raw)) != server.Version {
		t.Fatal("version unavailable before startup")
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatal("version opened a database")
	}
}
