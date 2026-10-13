// Command artifact-manifest writes metadata for the exact Docker build output.
// The release qualification script independently regenerates and checks it.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

type binaryRecord struct {
	Bytes  int64  `json:"bytes"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func writeManifest(directory, version, revision string) error {
	names := []string{"veyport"}
	for _, name := range []string{"veyport-agent", "veyport-audit-ingest", "veyport-audit-export"} {
		for _, arch := range []string{"amd64", "arm64"} {
			names = append(names, name+"-linux-"+arch)
		}
	}
	for _, system := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			names = append(names, "vey-"+system+"-"+arch)
		}
	}
	sort.Strings(names)
	records := make([]binaryRecord, 0, len(names))
	for _, name := range names {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
			return fmt.Errorf("invalid artifact %s", name)
		}
		if len(name) > 4 && name[:4] == "vey-" && info.Size() > 15<<20 {
			return fmt.Errorf("CLI artifact exceeds delivery size bound")
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		records = append(records, binaryRecord{Path: name, SHA256: fmt.Sprintf("%x", h.Sum(nil)), Bytes: info.Size()})
	}
	payload := struct {
		Binaries      []binaryRecord `json:"binaries"`
		Revision      string         `json:"revision"`
		SchemaVersion int            `json:"schema_version"`
		Version       string         `json:"version"`
	}{records, revision, 1, version}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "artifact-manifest.json"), append(data, '\n'), 0o644)
}

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("artifact-manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	directory := fs.String("directory", "", "build output directory")
	version := fs.String("version", "dev", "build version")
	revision := fs.String("revision", "unknown", "build source revision")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *directory == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "artifact output directory required")
		return 2
	}
	if err := writeManifest(*directory, *version, *revision); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }
