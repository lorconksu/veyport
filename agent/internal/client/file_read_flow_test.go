package client

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	"github.com/wyiu/veyport/proto/fileview"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestImageBulkBackpressureLeavesControlQueueFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.png")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0600); err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		c := activityClient(t)
		control := make(chan *pb.AgentMessage, 16)
		session := newActivitySession(t.Context(), c, control)
		defer session.close()
		req := &pb.FileReadRequest{RequestId: "preview", Path: path, Mode: pb.FileReadMode_FILE_READ_MODE_IMAGE}
		session.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: req}})

		// With the transport held, the active worker must wait independently
		// of the queue used by control and capability messages.
		synctest.Wait()
		if len(control) != 0 || c.budget.ActivityCount() != 1 {
			t.Fatalf("blocked preview queued %d control messages with %d active workers", len(control), c.budget.ActivityCount())
		}
		want := &pb.AgentMessage{Payload: &pb.AgentMessage_UpdateCapabilities{
			UpdateCapabilities: &pb.UpdateCapabilities{ActiveActivities: 1},
		}}
		session.sendCapability(want)
		if got := <-control; got != want || session.ctx.Err() != nil {
			t.Fatalf("control message could not enqueue under image backpressure: %v", got)
		}
	})
}

func TestImageAdmissionDistinguishesMaintenanceAndCapacity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(*testing.T, *Client)
		status pb.FileReadFailure
	}{
		{"capacity", func(t *testing.T, c *Client) {
			for range cap(c.imagePreviewSlots) {
				c.imagePreviewSlots <- struct{}{}
			}
		}, pb.FileReadFailure_FILE_READ_FAILURE_CAPACITY},
		{"activity capacity", func(t *testing.T, c *Client) {
			for range sessionlimit.MaxActivities {
				release, admitted := c.budget.AcquireActivity()
				if !admitted {
					t.Fatal("fixture could not fill the activity budget")
				}
				t.Cleanup(release)
			}
		}, pb.FileReadFailure_FILE_READ_FAILURE_CAPACITY},
		{"maintenance", func(t *testing.T, c *Client) {
			if !c.budget.TryMaintenance() {
				t.Fatal("fixture could not acquire maintenance")
			}
		}, pb.FileReadFailure_FILE_READ_FAILURE_MAINTENANCE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := activityClient(t)
			tc.setup(t, c)
			control := make(chan *pb.AgentMessage, 1)
			session := newActivitySession(context.Background(), c, control)
			defer session.close()
			req := &pb.FileReadRequest{RequestId: "preview", Path: "/unused.png", Mode: pb.FileReadMode_FILE_READ_MODE_IMAGE}
			session.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: req}})
			got := activityMessage(t, control).GetFileReadResponse()
			if !got.GetDone() || got.GetFailure() != tc.status || len(got.GetData()) != 0 {
				t.Fatalf("unexpected refusal: %v", got)
			}
		})
	}
}

func TestControlWriterSendsQueuedControlBeforeNextFileRecord(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		control := make(chan *pb.AgentMessage, 16)
		fileData := make(chan fileDataRecord)
		started := make(chan *pb.AgentMessage, 4)
		unblock := make(chan struct{})
		first := &pb.AgentMessage{Payload: &pb.AgentMessage_FileReadResponse{
			FileReadResponse: &pb.FileReadResponse{RequestId: "first", Data: []byte{1}},
		}}
		second := &pb.AgentMessage{Payload: &pb.AgentMessage_FileReadResponse{
			FileReadResponse: &pb.FileReadResponse{RequestId: "second", Data: []byte{2}},
		}}
		capabilities := &pb.AgentMessage{Payload: &pb.AgentMessage_UpdateCapabilities{
			UpdateCapabilities: &pb.UpdateCapabilities{ActiveActivities: 2},
		}}
		heartbeat := &pb.AgentMessage{Payload: &pb.AgentMessage_Heartbeat{Heartbeat: &pb.Heartbeat{}}}
		done := make(chan error, 1)
		go func() {
			done <- runControlWriter(ctx, cancel, func(message *pb.AgentMessage) error {
				started <- message
				if message == first {
					<-unblock
				}
				return nil
			}, control, fileData, nil, nil)
		}()
		t.Cleanup(func() {
			select {
			case <-unblock:
			default:
				close(unblock)
			}
			cancel()
			<-done
		})
		firstSent, secondSent := make(chan error, 1), make(chan error, 1)
		fileData <- fileDataRecord{ctx: ctx, message: first, sent: firstSent}
		if got := <-started; got != first {
			t.Fatalf("expected first file record, got %v", got)
		}
		go func() {
			select {
			case fileData <- fileDataRecord{ctx: ctx, message: second, sent: secondSent}:
			case <-ctx.Done():
			}
		}()
		synctest.Wait()
		control <- capabilities
		control <- heartbeat
		close(unblock)
		for _, want := range []*pb.AgentMessage{capabilities, heartbeat, second} {
			if got := <-started; got != want {
				t.Fatalf("want %v before another file record, got %v", want, got)
			}
		}
		if err := <-firstSent; err != nil {
			t.Fatal(err)
		}
		if err := <-secondSent; err != nil {
			t.Fatal(err)
		}
	})
}

func TestFileDataWriteHealthOnlyClosesStalledGeneration(t *testing.T) {
	for _, stall := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			stream, cancelStream := context.WithCancel(t.Context())
			defer cancelStream()
			read, cancelRead := context.WithCancel(stream)
			defer cancelRead()
			entered, release := make(chan struct{}), make(chan struct{})
			record := fileDataRecord{ctx: read, sent: make(chan error, 1)}
			go record.forward(func(*pb.AgentMessage) error {
				close(entered)
				select {
				case <-release:
					return nil
				case <-stream.Done():
					return stream.Err()
				}
			}, cancelStream)
			<-entered
			cancelRead()
			time.Sleep(fileview.FileDataIdleTimeout - time.Nanosecond)
			if stream.Err() != nil {
				t.Fatal("read cancellation or early watchdog closed a healthy stream")
			}
			if !stall {
				close(release)
				if err := <-record.sent; err != nil {
					t.Fatal(err)
				}
				time.Sleep(fileview.FileDataIdleTimeout)
				if stream.Err() != nil {
					t.Fatal("completed write left a live watchdog")
				}
				return
			}
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			if !errors.Is(stream.Err(), context.Canceled) {
				t.Fatal("stalled transport remained alive after the write health limit")
			}
			if err := <-record.sent; !errors.Is(err, context.Canceled) {
				t.Fatalf("stalled write returned %v", err)
			}
		})
	}
}
