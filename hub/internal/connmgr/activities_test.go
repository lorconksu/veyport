package connmgr

import (
	"context"
	"errors"
	"fmt"
	"testing"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func listActivity(id string) *pb.HubMessage {
	return &pb.HubMessage{Payload: &pb.HubMessage_FileListRequest{FileListRequest: &pb.FileListRequest{RequestId: id, Path: "/tmp"}}}
}
func TestActivityAdmissionAndMaintenanceCannotRace(t *testing.T) {
	for range 100 {
		cm := New()
		conn := cm.Register("node", &mockStream{})
		start := make(chan struct{})
		admitted := make(chan *Activity, 1)
		reserved := make(chan error, 1)
		go func() { <-start; a, _ := cm.BeginActivity(conn, "request", ActivityRead); admitted <- a }()
		go func() { <-start; reserved <- cm.ReserveMaintenance(conn, "update", func() error { return nil }) }()
		close(start)
		a, err := <-admitted, <-reserved
		if (a != nil) == (err == nil) {
			t.Fatal("work and maintenance did not exclude each other", a, err)
		}
		if a != nil {
			a.Abandon()
			if err = cm.ReserveMaintenance(conn, "retry", func() error { return nil }); err != nil {
				t.Fatal("unsent work leaked reservation", err)
			}
		}
	}
}
func TestActivityLifetimeSurvivesAbandonAndOnlyTypedCompletionReleases(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	conn := cm.Register("node", stream)
	a, err := cm.BeginRequest(conn, listActivity("request"))
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Send(context.Background(), listActivity("request")); err != nil {
		t.Fatal(err)
	}
	a.Abandon()
	if err = cm.ReserveMaintenance(conn, "update", func() error { return nil }); !errors.Is(err, ErrActivityBusy) {
		t.Fatal("abandon manufactured remote completion", err)
	}
	if cm.CompleteResponse("node", stream, &pb.FileReadResponse{RequestId: "request"}) || cm.CompleteResponse("other", stream, &pb.FileListResponse{RequestId: "request"}) {
		t.Fatal("wrong kind/identity completed work")
	}
	if !cm.CompleteResponse("node", stream, &pb.FileListResponse{RequestId: "request"}) || cm.CompleteResponse("node", stream, &pb.FileListResponse{RequestId: "request"}) {
		t.Fatal("completion was not exactly once")
	}
	if err = cm.ReserveMaintenance(conn, "update", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, msg := range []*pb.HubMessage{listActivity("new"), {Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{RequestId: "read"}}}, {Payload: &pb.HubMessage_FileDeleteRequest{FileDeleteRequest: &pb.FileDeleteRequest{RequestId: "delete"}}}, {Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: "upload", Filename: "file"}}}, {Payload: &pb.HubMessage_LogStreamRequest{LogStreamRequest: &pb.LogStreamRequest{RequestId: "log"}}}} {
		if err = cm.SendToAgent("node", msg); err == nil {
			t.Fatal("new user work crossed maintenance", msg)
		}
	}
	for _, msg := range []*pb.HubMessage{{Payload: &pb.HubMessage_FileUploadAbort{FileUploadAbort: &pb.FileUploadAbort{RequestId: "upload"}}}, {Payload: &pb.HubMessage_LogStreamStop{LogStreamStop: &pb.LogStreamStop{RequestId: "log"}}}, {Payload: &pb.HubMessage_HeartbeatAck{HeartbeatAck: &pb.HeartbeatAck{}}}} {
		if err = cm.SendToAgent("node", msg); err != nil {
			t.Fatal("maintenance blocked cleanup/control", err)
		}
	}
}
func TestActivityReconnectCountAndStaleMessagesCannotClearCurrentWork(t *testing.T) {
	cm := New()
	oldStream := &mockStream{}
	old := cm.Register("node", oldStream)
	if err := cm.SendToAgent("node", listActivity("old")); err != nil {
		t.Fatal(err)
	}
	newStream := &mockStream{}
	conn := cm.Register("node", newStream)
	if err := cm.ReserveMaintenance(conn, "update", func() error { return nil }); !errors.Is(err, ErrActivityBusy) {
		t.Fatal("disconnect claimed idle", err)
	}
	if cm.CompleteResponse("node", oldStream, &pb.FileListResponse{RequestId: "old"}) {
		t.Fatal("old response cleared uncertainty")
	}
	if err := cm.ObserveActivityCapabilities("node", oldStream, 1, 0); err == nil {
		t.Fatal("stale zero accepted")
	}
	if err := cm.ObserveActivityCapabilities("node", newStream, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := cm.ReserveMaintenanceWithIdleAssertion(conn, "unsafe", true, func() error { return nil }); err == nil {
		t.Fatal("manual flag overrode known native activity")
	}
	if err := cm.SendToAgent("node", listActivity("current")); err != nil {
		t.Fatal(err)
	}
	if err := cm.ObserveActivityCapabilities("node", newStream, 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := cm.ReserveMaintenance(conn, "update", func() error { return nil }); !errors.Is(err, ErrActivityBusy) {
		t.Fatal("queued zero cleared current work", err)
	}
	if !cm.CompleteResponse("node", newStream, &pb.FileListResponse{RequestId: "current"}) {
		t.Fatal("current completion failed")
	}
	if err := cm.ReserveMaintenance(conn, "update", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if old.GenerationID == conn.GenerationID {
		t.Fatal("connection generation reused")
	}
}
func TestManualIdleAssertionCannotOverrideLiveOwnerOrRefusedAuthority(t *testing.T) {
	cm := New()
	conn := cm.Register("node", &mockStream{})
	a, err := cm.BeginRequest(conn, listActivity("request"))
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Send(context.Background(), listActivity("request")); err != nil {
		t.Fatal(err)
	}
	if err = cm.ReserveMaintenanceWithIdleAssertion(conn, "update", true, func() error { return nil }); err == nil {
		t.Fatal("manual assertion overrode active owner")
	}
	a.Abandon()
	denied := errors.New("revoked")
	if err = cm.ReserveMaintenanceWithIdleAssertion(conn, "update", true, func() error { return denied }); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if err = cm.ReserveMaintenance(conn, "update", func() error { return nil }); !errors.Is(err, ErrActivityBusy) {
		t.Fatal("refused assertion discarded unknown work", err)
	}
	if err = cm.ReserveMaintenanceWithIdleAssertion(conn, "update", true, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = a.Send(context.Background(), listActivity("request")); err == nil {
		t.Fatal("retired HTTP owner dispatched after assertion")
	}
}
func TestActivityUploadAbortAndLogStopAreRequestsNotCompletion(t *testing.T) {
	cm := New()
	s := &mockStream{}
	conn := cm.Register("node", s)
	upload := &pb.HubMessage{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: "upload", Filename: "file", Chunk: []byte("partial")}}}
	if err := cm.SendToAgent("node", upload); err != nil {
		t.Fatal(err)
	}
	if err := cm.SendToAgent("node", &pb.HubMessage{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: "upload", Done: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := cm.SendToAgent("node", &pb.HubMessage{Payload: &pb.HubMessage_LogStreamRequest{LogStreamRequest: &pb.LogStreamRequest{RequestId: "log"}}}); err != nil {
		t.Fatal(err)
	}
	for _, msg := range []*pb.HubMessage{{Payload: &pb.HubMessage_FileUploadAbort{FileUploadAbort: &pb.FileUploadAbort{RequestId: "upload"}}}, {Payload: &pb.HubMessage_LogStreamStop{LogStreamStop: &pb.LogStreamStop{RequestId: "log"}}}} {
		if err := cm.SendToAgent("node", msg); err != nil {
			t.Fatal(err)
		}
	}
	if err := cm.ReserveMaintenance(conn, "update", func() error { return nil }); err == nil {
		t.Fatal("cancellation request claimed completion")
	}
	if cm.CompleteResponse("node", s, &pb.LogStreamChunk{RequestId: "log", Data: []byte("data")}) {
		t.Fatal("data chunk ended log lifetime")
	}
	if !cm.CompleteResponse("node", s, &pb.FileUploadAck{RequestId: "upload", Success: false, Error: "aborted"}) {
		t.Fatal("abort acknowledgement did not finish upload")
	}
	if !cm.CompleteResponse("node", s, &pb.LogStreamChunk{RequestId: "log", Done: true}) {
		t.Fatal("terminal log did not finish")
	}
	if err := cm.ReserveMaintenance(conn, "update", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
func TestActivityCapsBoundRetainedCancellationState(t *testing.T) {
	cm := New()
	for n := range MaxActivities / MaxNodeActivities {
		node := fmt.Sprint(n)
		conn := cm.Register(node, &mockStream{})
		for r := range MaxNodeActivities {
			a, err := cm.BeginActivity(conn, fmt.Sprint(r), ActivityRead)
			if err != nil {
				t.Fatal(err)
			}
			if err = a.Send(context.Background(), &pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{RequestId: fmt.Sprint(r)}}}); err != nil {
				t.Fatal(err)
			}
			a.Abandon()
		}
		if _, err := cm.BeginActivity(conn, "over-node", ActivityRead); !errors.Is(err, ErrActivityCapacity) {
			t.Fatal("node cap not enforced", err)
		}
	}
	other := cm.Register("other", &mockStream{})
	if _, err := cm.BeginActivity(other, "over-global", ActivityRead); !errors.Is(err, ErrActivityCapacity) {
		t.Fatal("global cap not enforced", err)
	}
	if err := cm.ObserveActivityCapabilities("other", other.Stream, 1, 1); !errors.Is(err, ErrActivityCapacity) {
		t.Fatal("carried-work cap bypassed", err)
	}
	cm.Unregister("0")
	if len(cm.activities)+len(cm.uncertain) > MaxActivities || !cm.uncertain["0"] {
		t.Fatal("disconnect exceeded cap or lost uncertainty")
	}
	if _, err := cm.BeginActivity(other, "fits", ActivityRead); err != nil {
		t.Fatal("coalescing retained needless per-request state", err)
	}
}
func TestActivityInvalidBindingsAndUnsentCancellation(t *testing.T) {
	cm := New()
	s := &mockStream{}
	conn := cm.Register("node", s)
	for _, id := range []string{"", string(make([]byte, 129)), "bad\n"} {
		if _, err := cm.BeginActivity(conn, id, ActivityRead); err == nil {
			t.Fatal("invalid ID accepted")
		}
	}
	if _, err := cm.BeginActivity(nil, "id", ActivityRead); err == nil {
		t.Fatal("nil connection admitted")
	}
	if _, err := cm.BeginActivity(conn, "id", "unknown"); err == nil {
		t.Fatal("unknown kind admitted")
	}
	a, err := cm.BeginRequest(conn, listActivity("id"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cm.BeginRequest(conn, listActivity("id")); err == nil {
		t.Fatal("duplicate admitted")
	}
	if err = a.Send(context.Background(), listActivity("other")); err == nil {
		t.Fatal("binding changed")
	}
	a.Abandon()
	if a.Dispatched() {
		t.Fatal("unsent cancellation claimed dispatched")
	}
	if err := cm.ObserveActivityCapabilities("node", s, 2, 0); err == nil {
		t.Fatal("future capability accepted")
	}
	if err := cm.ObserveActivityCapabilities("node", s, 1, 129); err == nil {
		t.Fatal("oversized count accepted")
	}
	if err := cm.SendToAgent("node", &pb.HubMessage{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: "missing", Done: true}}}); err == nil {
		t.Fatal("unknown continuation started an upload")
	}
	if err := cm.ReserveMaintenance(conn, "update", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestFailedActivitySendRetainsUncertaintyAndRejectsReplacementLease(t *testing.T) {
	for _, checked := range []bool{false, true} {
		t.Run(fmt.Sprint(checked), func(t *testing.T) {
			cm := New()
			stream := &mockStream{sendErr: errors.New("ambiguous transport failure")}
			conn := cm.Register("node", stream)
			msg := listActivity("failed")
			var err error
			if checked {
				err = cm.SendToConnectionChecked(context.Background(), conn, msg, nil)
			} else {
				err = cm.SendToAgent("node", msg)
			}
			if err == nil {
				t.Fatal("send failure ignored")
			}
			if err = cm.ReserveMaintenance(conn, "update", func() error { return nil }); !errors.Is(err, ErrActivityBusy) {
				t.Fatal("ambiguous send claimed idle", err)
			}
			cm.UnregisterIfCurrent("node", stream)
			replacement := cm.Register("node", &mockStream{})
			if _, err = cm.BeginActivity(conn, "old", ActivityRead); err == nil {
				t.Fatal("replaced connection admitted work")
			}
			if err = cm.SendToConnectionChecked(context.Background(), conn, msg, nil); err == nil {
				t.Fatal("replaced sender dispatched")
			}
			if err = cm.ObserveActivityCapabilities("missing", stream, 1, 0); err == nil {
				t.Fatal("missing connection accepted idle proof")
			}
			if err = cm.ObserveActivityCapabilities("node", replacement.Stream, 1, 0); err != nil {
				t.Fatal(err)
			}
			replacement.Close()
			if _, err = cm.BeginActivity(replacement, "closed", ActivityRead); err == nil {
				t.Fatal("closed generation admitted work")
			}
			if err = cm.SendToAgent("node", listActivity("closed")); err == nil {
				t.Fatal("closed sender dispatched")
			}
		})
	}
}
func TestActivityPositiveInitialCountHasBoundedSlotUntilGenuineZero(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	conn := cm.Register("node", stream)
	if err := cm.ObserveActivityCapabilities("node", stream, 1, 1); err != nil {
		t.Fatal(err)
	}
	if cm.activityNodes["node"] != 1 || !cm.uncertain["node"] {
		t.Fatal("carried work lacked bounded recovery slot")
	}
	if err := cm.ObserveActivityCapabilities("node", stream, 1, 0); err != nil {
		t.Fatal(err)
	}
	if cm.activityNodes["node"] != 0 || len(cm.uncertain) != 0 {
		t.Fatal("genuine zero retained obsolete unknown slot")
	}
	if cm.CompleteResponse("node", stream, &pb.Heartbeat{}) {
		t.Fatal("unrelated response released work")
	}
	for _, entry := range []struct {
		kind     ActivityKind
		response interface{}
	}{{ActivityRead, &pb.FileReadResponse{RequestId: "read"}}, {ActivityDelete, &pb.FileDeleteResponse{RequestId: "delete"}}} {
		id := string(entry.kind)
		a, err := cm.BeginActivity(conn, id, entry.kind)
		if err != nil {
			t.Fatal(err)
		}
		if a.Connection() != conn {
			t.Fatal("activity did not retain exact connection")
		}
		var msg *pb.HubMessage
		if entry.kind == ActivityRead {
			msg = &pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{RequestId: id}}}
		} else {
			msg = &pb.HubMessage{Payload: &pb.HubMessage_FileDeleteRequest{FileDeleteRequest: &pb.FileDeleteRequest{RequestId: id}}}
		}
		if err = a.Send(context.Background(), msg); err != nil {
			t.Fatal(err)
		}
		if entry.kind == ActivityRead {
			if !cm.CompleteResponse("node", stream, &pb.FileReadResponse{RequestId: id}) {
				t.Fatal("read completion ignored")
			}
		} else {
			if !cm.CompleteResponse("node", stream, &pb.FileDeleteResponse{RequestId: id}) {
				t.Fatal("delete completion ignored")
			}
		}
	}
	if err := cm.SendToAgent("node", listActivity("")); err == nil {
		t.Fatal("invalid raw send admitted")
	}
}

func TestManualMaintenanceRejectsReplacementDuringDurableCallback(t *testing.T) {
	cm := New()
	oldStream := &mockStream{}
	old := cm.Register("node", oldStream)
	a, err := cm.BeginRequest(old, listActivity("abandoned"))
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Send(context.Background(), listActivity("abandoned")); err != nil {
		t.Fatal(err)
	}
	a.Abandon()
	replacement := &mockStream{}
	err = cm.ReserveMaintenanceWithIdleAssertion(old, "old-update", true, func() error {
		cm.Register("node", replacement)
		return cm.SendToAgent("node", listActivity("new-work"))
	})
	if err == nil {
		t.Fatal("old assertion reserved replacement generation")
	}
	if cm.maintenance["node"] != "" || !cm.uncertain["node"] {
		t.Fatal("refused old assertion changed replacement maintenance/uncertainty")
	}
	current := cm.GetConn("node")
	if cm.CompleteResponse("node", oldStream, &pb.FileListResponse{RequestId: "abandoned"}) {
		t.Fatal("old completion changed replacement work")
	}
	if err = cm.ReserveMaintenance(current, "new-update", func() error { return nil }); !errors.Is(err, ErrActivityBusy) {
		t.Fatal("replacement work lost lifetime", err)
	}
}

func TestQueuedCountAfterFinalResponseCannotCreateAnUnbudgetedReconnectMarker(t *testing.T) {
	cm := New()
	stream := &mockStream{}
	conn := cm.Register("finishing", stream)
	if err := cm.SendToAgent("finishing", listActivity("last")); err != nil {
		t.Fatal(err)
	}
	if err := cm.ObserveActivityCapabilities("finishing", stream, 1, 1); err != nil {
		t.Fatal(err)
	}
	if !cm.CompleteResponse("finishing", stream, &pb.FileListResponse{RequestId: "last"}) {
		t.Fatal("request did not complete")
	}
	if cm.activityNodes["finishing"] != 1 || !cm.uncertain["finishing"] {
		t.Fatal("positive queued count lost reserved slot")
	}
	for i := range MaxActivities - 1 {
		node := fmt.Sprint(i)
		other := cm.Register(node, &mockStream{})
		if _, err := cm.BeginActivity(other, "request", ActivityRead); err != nil {
			t.Fatal(err)
		}
	}
	cm.Register("finishing", &mockStream{})
	if got := len(cm.activities) + len(cm.uncertain); got != MaxActivities {
		t.Fatalf("reconnect changed full capacity to%d", got)
	}
	replacement := cm.GetConn("finishing")
	if err := cm.ObserveActivityCapabilities("finishing", replacement.Stream, 1, 0); err != nil {
		t.Fatal(err)
	}
	if cm.activityNodes["finishing"] != 0 {
		t.Fatal("genuine zero retained obsolete count slot")
	}
	if _, err := cm.BeginActivity(replacement, "fits", ActivityRead); err != nil {
		t.Fatal("genuine completion did not free exactly one slot", err)
	}
	_ = conn
}
