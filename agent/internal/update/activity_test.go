package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wyiu/veyport/agent/internal/dropzone"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestBeginRefusesRealPartialUploadWithoutDownloadOrSupervisor(t *testing.T) {
	p, entry := installation(t)
	r := runtimeFor(p, oldMetadata)
	dz := dropzone.NewWithBudget(t.TempDir(), r.budget)
	if ack := dz.HandleChunk("live", "data", []byte("first"), false); ack != nil {
		t.Fatal(ack)
	}
	if ack := dz.HandleChunk("live", "", []byte("second"), false); ack != nil {
		t.Fatal(ack)
	}
	service := &artifactService{stream: &artifactStream{chunks: chunks(newBytes)}}
	launched := false
	r.launch = func(context.Context, string, ...string) error { launched = true; return errors.New("fixture stop") }
	var failed *pb.AgentUpdateStatus
	r.Begin(context.Background(), &pb.AgentUpdateRequest{OperationId: entry.Operation, Version: entry.Target.Version, Revision: entry.Target.Revision, Sha256: entry.Target.SHA256, Bytes: entry.Target.Bytes, ExpiresUnixMilli: entry.Expires}, service, func(status *pb.AgentUpdateStatus) { failed = status })
	if launched || service.called || failed == nil || failed.State != "failed" || !strings.Contains(failed.Reason, "active work") {
		t.Fatal("partial upload admitted update", failed)
	}
	if _, err := os.Stat(p.journal()); !os.IsNotExist(err) {
		t.Fatal("busy refusal mutated journal", err)
	}
	if data, err := os.ReadFile(filepath.Join(dz.Dir(), ".upload-live")); err != nil || string(data) != "firstsecond" {
		t.Fatal("update corrupted partial", string(data), err)
	}
	if ack := dz.HandleChunk("live", "", nil, true); !ack.Success {
		t.Fatal(ack)
	}
	if data, err := os.ReadFile(filepath.Join(dz.Dir(), "data")); err != nil || string(data) != "firstsecond" {
		t.Fatal("upload did not survive refusal", string(data), err)
	}
	if !r.budget.TryMaintenance() {
		t.Fatal("completed upload did not become quiescent")
	}
	r.budget.EndMaintenance()
}
