package grpcserver

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAgentUpdateRejectedDurableCreationReleasesReservationWithoutDispatch(t *testing.T) {
	f := newUpdateFixture(t)
	if _, err := f.st.DB().Exec(`CREATE TRIGGER refuse_agent_update_creation BEFORE INSERT ON agent_updates BEGIN SELECT RAISE(ABORT,'durable update creation unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision); err == nil || ticket != "" {
		t.Fatal("failed durable creation yielded update authority", err)
	}
	var count int
	if err := f.st.DB().QueryRow("SELECT COUNT(*) FROM agent_updates").Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected creation left a partial durable operation", count, err)
	}
	f.u.mu.Lock()
	reserved := len(f.u.origins)
	f.u.mu.Unlock()
	if reserved != 0 || len(f.stream.sent) != 0 {
		t.Fatal("rejected creation leaked capacity or dispatched to agent", reserved, len(f.stream.sent))
	}
	if _, ok := f.u.terminals.Register("node", "safe-after-denial", "admin", ""); !ok {
		t.Fatal("rejected creation retained terminal maintenance")
	}
	f.u.terminals.Remove("node", "safe-after-denial")
	if _, err := f.st.DB().Exec("DROP TRIGGER refuse_agent_update_creation"); err != nil {
		t.Fatal(err)
	}
	f.start(t)
}

func TestAgentUpdatePreinstallFailureAndDelayedOldFailureCannotReleaseNewLease(t *testing.T) {
	f := newUpdateFixture(t)
	first := f.start(t)
	if err := f.u.ObserveStatus("node", f.stream, statusFor(first.ID, f.old, "failed")); err != nil {
		t.Fatal(err)
	}
	got, err := f.st.GetAgentUpdate(first.ID)
	if err != nil || got.State != "failed" || got.ObservedSHA256 != "" {
		t.Fatal("preinstall refusal fabricated completion evidence", got, err)
	}
	if _, ok := f.u.terminals.Register("node", "safe-after-failure", "admin", ""); !ok {
		t.Fatal("preinstall refusal retained its own maintenance")
	}
	f.u.terminals.Remove("node", "safe-after-failure")
	second := f.start(t)
	if err = f.u.ObserveStatus("node", f.stream, statusFor(first.ID, f.old, "failed")); err != nil {
		t.Fatal("duplicate terminal failure was not idempotent", err)
	}
	if _, ok := f.u.terminals.Register("node", "unsafe-late-failure", "admin", ""); ok {
		t.Fatal("late old failure released a newer terminal lease")
	}
	if err = f.h.connMgr.SendToAgent("node", &pb.HubMessage{Payload: &pb.HubMessage_ExecutionPrepare{ExecutionPrepare: &pb.ExecutionPrepare{ExecutionId: "unsafe-late-failure"}}}); err == nil {
		t.Fatal("late old failure released a newer control lease")
	}
	got, err = f.st.GetAgentUpdate(second.ID)
	if err != nil || got.State != "requested" {
		t.Fatal("late old failure changed the new operation", got, err)
	}
}

func TestAgentUpdateMissingDistributionRefusesWithoutTicketOrMaintenance(t *testing.T) {
	for _, phase := range []string{"not-configured", "manifest-unavailable"} {
		t.Run(phase, func(t *testing.T) {
			f := newUpdateFixture(t)
			f.u.EndConnection("node", f.stream)
			if phase == "not-configured" {
				f.u.SetArtifactResolver(nil)
			} else {
				f.u.SetArtifactResolver(func(string, string) (model.AgentArtifact, error) {
					return model.AgentArtifact{}, errors.New("matching distribution manifest unavailable")
				})
			}
			if _, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision); err == nil || ticket != "" {
				t.Fatal("missing verified distribution issued bootstrap authority", phase)
			}
			var count int
			if err := f.st.DB().QueryRow("SELECT COUNT(*) FROM agent_updates").Scan(&count); err != nil || count != 0 {
				t.Fatal("distribution refusal created a durable operation", count, err)
			}
			if _, ok := f.u.terminals.Register("node", "safe-no-distribution", "admin", ""); !ok {
				t.Fatal("distribution refusal reserved maintenance")
			}
		})
	}
}

func TestAgentUpdateDownloadRechecksRevocationAfterArtifactResolution(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	f.u.SetArtifactResolver(func(string, string) (model.AgentArtifact, error) {
		if _, err := f.st.EndSession("session", model.SessionEndRevokedAdmin, nil, time.Now()); err != nil {
			t.Fatal(err)
		}
		return f.target, nil
	})
	stream := &updateDownloadStream{ctx: enrolledUpdateContext("node")}
	err := f.h.DownloadUpdate(&pb.UpdateArtifactRequest{OperationId: op.ID}, stream)
	if status.Code(err) != codes.PermissionDenied || stream.body.Len() != 0 || len(f.u.transfers) != 0 {
		t.Fatal("revoked authority emitted an artifact frame or leaked transfer capacity", err, stream.body.Len())
	}
}

type updateGrowingArtifactStream struct {
	*updateDownloadStream
	path string
}

func (s *updateGrowingArtifactStream) Send(chunk *pb.UpdateArtifactChunk) error {
	if err := s.updateDownloadStream.Send(chunk); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString("unexpected trailing artifact data")
	return err
}
func TestAgentUpdateGrowthAfterFinalFrameCannotCompleteVerifiedDownload(t *testing.T) {
	f := newUpdateFixture(t)
	op := f.start(t)
	stream := &updateGrowingArtifactStream{updateDownloadStream: &updateDownloadStream{ctx: enrolledUpdateContext("node")}, path: f.target.BinaryPath}
	err := f.h.DownloadUpdate(&pb.UpdateArtifactRequest{OperationId: op.ID}, stream)
	if status.Code(err) != codes.DataLoss || !strings.Contains(err.Error(), "grew") || !bytes.Equal(stream.body.Bytes(), f.body) || len(f.u.transfers) != 0 {
		t.Fatal("late growth was accepted as completed download", err, stream.body.Len())
	}
	got, e := f.st.GetAgentUpdate(op.ID)
	if e != nil || got.State != "requested" {
		t.Fatal("failed download acquired installation authority", got, e)
	}
}
