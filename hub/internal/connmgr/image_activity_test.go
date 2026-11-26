package connmgr

import (
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func previewReadRequest(id string) *pb.HubMessage {
	return &pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{
		RequestId: id, Mode: pb.FileReadMode_FILE_READ_MODE_IMAGE, Path: "/fixture.png",
	}}}
}

func TestImageActivityRejectsMismatchedOrAbandonedDispatch(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	conn := cm.Register("node", stream)
	msg := previewReadRequest("original")
	activity, err := cm.BeginRequest(conn, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := activity.SendImageRead(t.Context(), previewReadRequest("different"), time.Second); err == nil {
		t.Error("mismatched request reached the agent")
	}
	activity.Abandon()
	if err := activity.SendImageRead(t.Context(), msg, time.Second); err == nil {
		t.Error("abandoned request reached the agent")
	}
	if len(stream.sent) != 0 {
		t.Fatalf("rejected requests wrote %d messages", len(stream.sent))
	}
	if err := cm.ReserveMaintenance(conn, "update", func() error { return nil }); err != nil {
		t.Fatalf("rejected requests left a reservation: %v", err)
	}
}

func TestImageActivityCancellationSkipsBusyGeneration(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	conn := cm.Register("node", stream)
	msg := previewReadRequest("preview")
	activity, err := cm.BeginRequest(conn, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := activity.SendImageRead(t.Context(), msg, time.Second); err != nil {
		t.Fatal(err)
	}
	conn.GenerationMu.Lock()
	activity.TryCancelFileRead(t.Context())
	conn.GenerationMu.Unlock()
	if len(stream.sent) != 1 || stream.sent[0].GetFileReadRequest().GetRequestId() != "preview" {
		t.Fatalf("cancel wrote while the generation was busy: %v", stream.sent)
	}
	if !conn.SendMu.TryLock() {
		t.Fatal("skipped cancel retained the control writer")
	}
	conn.SendMu.Unlock()
	activity.TryCancelFileRead(t.Context())
	if len(stream.sent) != 2 || stream.sent[1].GetFileReadCancel().GetRequestId() != "preview" {
		t.Fatalf("retry failed to stop the preview on the same connection: %v", stream.sent)
	}
}
