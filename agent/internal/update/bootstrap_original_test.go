package update

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/proto/updateutil"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestPreservingBootstrapUnstampedOriginalRequiresExactOperatorAssertion(t *testing.T) {
	for _, fault := range []string{"asserted", "absent", "wrong_digest", "partial", "malformed", "stamped", "downgrade", "same_version", "multiple"} {
		t.Run(fault, func(t *testing.T) {
			p, entry := installation(t)
			originalBytes, original := unstampedBytes, unstampedMetadata
			if fault == "stamped" {
				originalBytes, original = oldBytes, oldMetadata
			}
			if err := os.WriteFile(p.binary, originalBytes, 0755); err != nil {
				t.Fatal(err)
			}
			assertions := []updateutil.BootstrapOriginal{{Version: original.Version, SHA256: original.SHA256}}
			switch fault {
			case "absent":
				assertions = nil
			case "wrong_digest":
				assertions[0].SHA256 = strings.Repeat("f", 64)
			case "partial":
				assertions[0].SHA256 = ""
			case "malformed":
				assertions[0].Version = "dev"
			case "downgrade":
				assertions[0].Version = "9.0.0"
			case "same_version":
				assertions[0].Version = newMetadata.Version
			case "multiple":
				assertions = append(assertions, assertions[0])
			}
			stage := filepath.Join(filepath.Dir(p.binary), ".veyport-agent-bootstrap-fixture")
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			executable := filepath.Join(stage, "candidate")
			if err := os.WriteFile(executable, newBytes, 0700); err != nil {
				t.Fatal(err)
			}
			identity := filepath.Join(p.journalDir, "client.key")
			if err := os.WriteFile(identity, []byte("preserved enrolled identity"), 0600); err != nil {
				t.Fatal(err)
			}
			service := &artifactService{bootstrapRequest: &pb.AgentUpdateRequest{OperationId: entry.Operation, Version: newMetadata.Version, Revision: newMetadata.Revision, Sha256: newMetadata.SHA256, Bytes: newMetadata.Bytes, ExpiresUnixMilli: entry.Expires}}
			launched := false
			err := bootstrap(context.Background(), p, strings.Repeat("x", 64), newMetadata.Version, newMetadata.Revision, service, executable, func(context.Context, string, ...string) error { launched = true; return nil }, assertions...)
			if fault == "asserted" {
				if err != nil || !launched {
					t.Fatalf("exact asserted unstamped bootstrap refused: %v", err)
				}
				journal, err := p.read()
				if err != nil || journal.Original != unstampedMetadata {
					t.Fatalf("original bytes/version binding lost: %+v %v", journal, err)
				}
				if service.bootstrapCaps == nil || service.bootstrapCaps.Version != "0.1.0" || service.bootstrapCaps.Sha256 != original.SHA256 || service.bootstrapCaps.Revision != "unknown" || !service.bootstrapAsserted {
					t.Fatal("original assertion was not sent to enrolled Hub")
				}
			} else {
				if err == nil || launched {
					t.Fatalf("unsafe assertion reached launcher: %v", err)
				}
				if fault != "downgrade" && fault != "same_version" && service.bootstrapCaps != nil {
					t.Fatal("invalid original assertion reached RPC")
				}
				if _, err := os.Stat(p.journal()); !os.IsNotExist(err) {
					t.Fatal("refused assertion changed journal")
				}
			}
			current, err := os.ReadFile(p.binary)
			if err != nil || string(current) != string(originalBytes) {
				t.Fatal("bootstrap replaced original")
			}
			key, err := os.ReadFile(identity)
			if err != nil || string(key) != "preserved enrolled identity" {
				t.Fatal("bootstrap changed enrolled identity")
			}
		})
	}
}

func TestOriginalAssertionCannotWeakenPackagePlatformStampsOrCandidateChecks(t *testing.T) {
	for _, fault := range []string{"wrong_package", "wrong_platform", "version_only", "revision_only", "empty_version", "duplicate_version", "duplicate_revision"} {
		t.Run(fault, func(t *testing.T) {
			p, _ := installation(t)
			args := []string{"build", "-o", p.binary, "./cmd/veyport-agent"}
			buildDir := "../.."
			flags := ""
			switch fault {
			case "wrong_package":
				args[len(args)-1] = "./updateutil/testdata/identity"
				buildDir = "../../../proto"
			case "version_only":
				flags = "-X main.version=0.1.0"
			case "revision_only":
				flags = "-X main.revision=unknown"
			case "empty_version":
				flags = "-X main.version="
			case "duplicate_version":
				flags = "-X main.version= -X main.version=0.1.0"
			case "duplicate_revision":
				flags = "-X main.revision=unknown -X main.revision=unknown"
			}
			if flags != "" {
				args = append(args[:1], append([]string{"-ldflags", flags}, args[1:]...)...)
			}
			cmd := exec.Command("go", args...)
			cmd.Dir = buildDir
			if fault == "wrong_platform" {
				arch := "arm64"
				if runtime.GOARCH == "arm64" {
					arch = "amd64"
				}
				cmd.Env = append(os.Environ(), "GOARCH="+arch, "CGO_ENABLED=0")
			}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("build original fault: %v %s", err, output)
			}
			if err := os.Chmod(p.binary, 0755); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(p.binary)
			if err != nil {
				t.Fatal(err)
			}
			hash, _, err := hashFile(f)
			_ = f.Close()
			if err != nil {
				t.Fatal(err)
			}
			want := "both release stamps absent"
			switch fault {
			case "wrong_package":
				want = "installed binary is not the agent"
			case "wrong_platform":
				want = "agent ELF platform mismatch"
			case "empty_version", "duplicate_version":
				want = "duplicate installed version"
			case "duplicate_revision":
				want = "duplicate installed revision"
			}
			if _, err := p.bootstrapMetadata(updateutil.BootstrapOriginal{Version: "0.1.0", SHA256: hash}); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("assertion did not refuse original identity fault %s: %v", fault, err)
			}
		})
	}
	p, _ := installation(t)
	if err := os.WriteFile(p.binary, unstampedBytes, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := p.installedMetadata(); err == nil {
		t.Fatal("native metadata accepted unstamped original")
	}
	if err := p.verify(p.binary, unstampedMetadata, true); err == nil {
		t.Fatal("candidate verification accepted unstamped release")
	}
}

func TestUnstampedOriginalRollbackRestoresExactBytesAndKeepsOutcomeUnconfirmed(t *testing.T) {
	p, entry := installation(t)
	entry.Original = unstampedMetadata
	if err := os.WriteFile(p.binary, unstampedBytes, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.stage(entry.Operation), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.candidate(entry.Operation), newBytes, 0700); err != nil {
		t.Fatal(err)
	}
	if err := p.write(entry); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(p.journalDir, "client.key")
	if err := os.WriteFile(identity, []byte("preserved enrolled identity"), 0600); err != nil {
		t.Fatal(err)
	}
	s := supervisor{paths: p, wait: time.Millisecond, rollbackWait: time.Millisecond, authorize: func(context.Context, string) (*pb.UpdateAuthorization, error) {
		return &pb.UpdateAuthorization{OperationId: entry.Operation, ExpiresUnixMilli: entry.Expires}, nil
	}, run: func(_ context.Context, _ string, args ...string) error {
		current, err := os.ReadFile(p.binary)
		if err != nil {
			return err
		}
		if args[0] == "start" && string(current) == string(newBytes) {
			return errors.New("candidate restart failed")
		}
		return nil
	}}
	err := s.runOperation(context.Background(), entry.Operation)
	if err == nil || !strings.Contains(err.Error(), "reconnection remains unconfirmed") {
		t.Fatalf("legacy rollback claimed confirmed outcome: %v", err)
	}
	for _, path := range []string{p.binary, p.backup(entry.Operation)} {
		current, err := os.ReadFile(path)
		if err != nil || string(current) != string(unstampedBytes) {
			t.Fatal("legacy original or backup changed", path, err)
		}
	}
	journal, err := p.read()
	if err != nil || journal.State != "rolled_back" || journal.Confirmed || journal.Original != unstampedMetadata {
		t.Fatal("rollback original binding/outcome changed", journal, err)
	}
	key, err := os.ReadFile(identity)
	if err != nil || string(key) != "preserved enrolled identity" {
		t.Fatal("rollback changed identity")
	}
}
