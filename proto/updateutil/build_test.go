package updateutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyBuildIdentityBeforeExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	version, revision := "1.2.3-prototype.1", strings.Repeat("a", 40)
	cmd := exec.Command("go", "build", "-ldflags", "-X main.version="+version+" -X main.revision="+revision, "-o", path, "./testdata/identity")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build identity fixture: %v: %s", err, output)
	}
	packagePath := "github.com/wyiu/veyport/proto/updateutil/testdata/identity"
	if err := VerifyBuildIdentity(path, packagePath, runtime.GOOS, runtime.GOARCH, version, revision); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, pack, os, arch, version, revision string }{
		{path + "-absent", packagePath, runtime.GOOS, runtime.GOARCH, version, revision},
		{path, "other/package", runtime.GOOS, runtime.GOARCH, version, revision},
		{path, packagePath, "windows", runtime.GOARCH, version, revision},
		{path, packagePath, runtime.GOOS, "arm32", version, revision},
		{path, packagePath, runtime.GOOS, runtime.GOARCH, "1.2.4", revision},
		{path, packagePath, runtime.GOOS, runtime.GOARCH, version, strings.Repeat("b", 40)},
	} {
		if err := VerifyBuildIdentity(tc.path, tc.pack, tc.os, tc.arch, tc.version, tc.revision); err == nil {
			t.Fatal("accepted mismatched build identity")
		}
	}
	if err := os.WriteFile(path, []byte("untrusted arbitrary executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBuildIdentity(path, packagePath, runtime.GOOS, runtime.GOARCH, version, revision); err == nil {
		t.Fatal("accepted binary without Go build identity")
	}
}
