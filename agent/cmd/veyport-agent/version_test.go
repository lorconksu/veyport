package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionFlagReturnsBeforeConfigurationAndRegistration(t *testing.T) {
	previousArgs, previousFlags, previousOutput, previousVersion := os.Args, flag.CommandLine, os.Stdout, version
	defer func() {
		os.Args, flag.CommandLine, os.Stdout, version = previousArgs, previousFlags, previousOutput, previousVersion
	}()
	config := filepath.Join(t.TempDir(), "must-not-exist", "agent.conf")
	os.Args = []string{"veyport-agent", "--version", "--config", config, "--token", "synthetic-not-used"}
	flag.CommandLine = flag.NewFlagSet("veyport-agent", flag.ContinueOnError)
	version = "2.0.50-prototype.1"
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	os.Stdout = writer
	main()
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil || strings.TrimSpace(string(raw)) != version {
		t.Fatal("version did not return the stamped value")
	}
	if _, err = os.Stat(filepath.Dir(config)); !os.IsNotExist(err) {
		t.Fatal("version created registration/configuration state")
	}
}
