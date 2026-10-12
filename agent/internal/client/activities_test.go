package client

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/sys/unix"
)

func activityClient(t *testing.T) *Client {
	t.Helper()
	return New(Config{CertDir: t.TempDir(), DropzoneDir: t.TempDir(), AgentVersion: "0.2.0-prototype.5", AgentRevision: strings.Repeat("a", 40)})
}

func waitActivityCount(t *testing.T, c *Client, want uint32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for c.budget.ActivityCount() != want {
		if time.Now().After(deadline) {
			t.Fatalf("activities=%d want%d", c.budget.ActivityCount(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func activityMessage(t *testing.T, send <-chan *pb.AgentMessage) *pb.AgentMessage {
	t.Helper()
	select {
	case message := <-send:
		return message
	case <-time.After(3 * time.Second):
		t.Fatal("missing activity response")
		return nil
	}
}

func TestFileWorkersReserveBeforeDispatchThroughResponse(t *testing.T) {
	for _, kind := range []string{"list", "read", "delete"} {
		t.Run(kind, func(t *testing.T) {
			c := activityClient(t)
			send := make(chan *pb.AgentMessage)
			s := newActivitySession(context.Background(), c, send)
			defer s.close()
			path := filepath.Join(c.dropzone.Dir(), "data.txt")
			os.WriteFile(path, []byte("preserve bytes"), 0600)
			message := &pb.HubMessage{}
			switch kind {
			case "list":
				message.Payload = &pb.HubMessage_FileListRequest{FileListRequest: &pb.FileListRequest{RequestId: kind, Path: c.dropzone.Dir()}}
			case "read":
				message.Payload = &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{RequestId: kind, Path: path, Limit: 32}}
			case "delete":
				message.Payload = &pb.HubMessage_FileDeleteRequest{FileDeleteRequest: &pb.FileDeleteRequest{RequestId: kind, Path: path}}
			}
			if !s.dispatch(message) || c.budget.ActivityCount() != 1 || c.budget.TryMaintenance() {
				t.Fatal("worker admitted asynchronously or released before response")
			}
			response := activityMessage(t, send)
			switch kind {
			case "list":
				if response.GetFileListResponse().RequestId != kind || len(response.GetFileListResponse().Files) != 1 {
					t.Fatal(response)
				}
			case "read":
				if string(response.GetFileReadResponse().Data) != "preserve bytes" {
					t.Fatal(response)
				}
			case "delete":
				if !response.GetFileDeleteResponse().Success {
					t.Fatal(response)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal(err)
				}
			}
			waitActivityCount(t, c, 0)
			if !c.budget.TryMaintenance() {
				t.Fatal("finished worker stayed busy")
			}
			c.budget.EndMaintenance()
		})
	}
}

func TestOldBlockedFilesystemWorkerRemainsBusyAcrossReconnect(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux FIFO fixture")
	}
	c := activityClient(t)
	first := make(chan *pb.AgentMessage, 8)
	old := newActivitySession(context.Background(), c, first)
	old.observe(c.updates.Capabilities(), nil)
	activityMessage(t, first)
	path := filepath.Join(t.TempDir(), "blocked-fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	old.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{RequestId: "old-read", Path: path, Limit: 1}}})
	if count := activityMessage(t, first).GetUpdateCapabilities().ActiveActivities; count != 1 {
		t.Fatal(count)
	}
	old.close()
	second := make(chan *pb.AgentMessage, 8)
	current := newActivitySession(context.Background(), c, second)
	defer current.close()
	current.observe(c.updates.Capabilities(), nil)
	if capability := activityMessage(t, second).GetUpdateCapabilities(); capability.ActiveActivities != 1 || capability.ActivityQuiescenceVersion != 1 {
		t.Fatal("reconnect fabricated idle", capability)
	}
	if c.budget.TryMaintenance() {
		t.Fatal("disconnect released blocked filesystem worker")
	}
	old.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: "late", Filename: "late.txt", Chunk: []byte("late")}}})
	if _, err := os.Stat(filepath.Join(c.dropzone.Dir(), ".upload-late")); !os.IsNotExist(err) {
		t.Fatal("closed session reopened upload", err)
	}
	writer, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0600)
	if err != nil {
		// Admission precedes goroutine scheduling. Wait for the actual open.
		deadline := time.Now().Add(3 * time.Second)
		for err != nil && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
			writer, err = os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0600)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte("x"))
	writer.Close()
	if capability := activityMessage(t, second).GetUpdateCapabilities(); capability.ActiveActivities != 0 {
		t.Fatal("actual old exit not observed", capability)
	}
	if !c.budget.TryMaintenance() {
		t.Fatal("actual worker exit stayed busy")
	}
	c.budget.EndMaintenance()
}

func TestCapabilityMutationOrderAndConfirmationPrelude(t *testing.T) {
	c := activityClient(t)
	send := make(chan *pb.AgentMessage, 32)
	s := newActivitySession(context.Background(), c, send)
	defer s.close()
	s.observe(c.updates.Capabilities(), &pb.AgentUpdateStatus{OperationId: "confirmed-op", State: "confirmed"})
	if message := activityMessage(t, send); message.GetUpdateCapabilities().ActiveActivities != 0 {
		t.Fatal(message)
	}
	if message := activityMessage(t, send); message.GetUpdateStatus().OperationId != "confirmed-op" {
		t.Fatal("status preceded capabilities", message)
	}
	first, _ := c.budget.AcquireActivity()
	first()
	second, _ := c.budget.AcquireActivity()
	second()
	for _, count := range []uint32{1, 0, 1, 0} {
		if message := activityMessage(t, send); message.GetUpdateCapabilities().ActiveActivities != count {
			t.Fatal("capability reordered", message, count)
		}
	}
}

func TestLogDuplicateAndStopDoNotAcknowledgeAnActiveWorker(t *testing.T) {
	c := activityClient(t)
	send := make(chan *pb.AgentMessage, 1)
	s := newActivitySession(context.Background(), c, send)
	defer s.close()
	path := filepath.Join(t.TempDir(), "tail.log")
	os.WriteFile(path, []byte("existing\n"), 0600)
	request := &pb.HubMessage{Payload: &pb.HubMessage_LogStreamRequest{LogStreamRequest: &pb.LogStreamRequest{RequestId: "tail", Path: path}}}
	s.dispatch(request)
	s.dispatch(request)
	if response := activityMessage(t, send).GetLogStreamChunk(); response.Done || response.Error != "duplicate log stream request" {
		t.Fatal("duplicate completed original", response)
	}
	// Occupy output so stop completion cannot finish its worker yet.
	send <- &pb.AgentMessage{}
	s.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_LogStreamStop{LogStreamStop: &pb.LogStreamStop{RequestId: "tail"}}})
	if c.budget.ActivityCount() != 1 || c.budget.TryMaintenance() {
		t.Fatal("stop request prematurely released worker")
	}
	activityMessage(t, send)
	if response := activityMessage(t, send).GetLogStreamChunk(); !response.Done || response.RequestId != "tail" || response.Error != "" {
		t.Fatal(response)
	}
	waitActivityCount(t, c, 0)
}

func TestActivityRefusalsAndUploadAbortDuringMaintenance(t *testing.T) {
	for _, reason := range []string{"maintenance", "capacity"} {
		t.Run(reason, func(t *testing.T) {
			c := activityClient(t)
			send := make(chan *pb.AgentMessage, 32)
			s := newActivitySession(context.Background(), c, send)
			defer s.close()
			var releases []func()
			if reason == "maintenance" {
				c.budget.TryMaintenance()
				defer c.budget.EndMaintenance()
			} else {
				for i := 0; i < sessionlimit.MaxActivities; i++ {
					release, _ := c.budget.AcquireActivity()
					releases = append(releases, release)
				}
				defer func() {
					for _, release := range releases {
						release()
					}
				}()
			}
			requests := []*pb.HubMessage{
				{Payload: &pb.HubMessage_FileListRequest{FileListRequest: &pb.FileListRequest{RequestId: "list", Path: t.TempDir()}}},
				{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{RequestId: "read", Path: "/nonexistent"}}},
				{Payload: &pb.HubMessage_FileDeleteRequest{FileDeleteRequest: &pb.FileDeleteRequest{RequestId: "delete", Path: "veyport://dropzone/file"}}},
				{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: "upload", Filename: "file", Chunk: []byte("data")}}},
				{Payload: &pb.HubMessage_LogStreamRequest{LogStreamRequest: &pb.LogStreamRequest{RequestId: "log", Path: "/nonexistent"}}},
			}
			for _, request := range requests {
				if !s.dispatch(request) {
					t.Fatal("not dispatched")
				}
				response := activityMessage(t, send)
				if !strings.Contains(response.String(), errActivityAdmission) {
					t.Fatal(response)
				}
			}
			s.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileUploadAbort{FileUploadAbort: &pb.FileUploadAbort{RequestId: "unknown"}}})
			if response := activityMessage(t, send).GetFileUploadAck(); response.Success || response.Error != "upload aborted" {
				t.Fatal(response)
			}
			if s.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_HeartbeatAck{HeartbeatAck: &pb.HeartbeatAck{}}}) {
				t.Fatal("activity gate consumed background health")
			}
			entries, _ := os.ReadDir(c.dropzone.Dir())
			if len(entries) != 0 {
				t.Fatal("refusal wrote data")
			}
		})
	}
}

func TestUploadSessionAbortAndDisconnectNeverCommitPartialData(t *testing.T) {
	for _, finish := range []string{"abort", "disconnect"} {
		t.Run(finish, func(t *testing.T) {
			c := activityClient(t)
			send := make(chan *pb.AgentMessage, 8)
			s := newActivitySession(context.Background(), c, send)
			defer s.close()
			s.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: "partial", Filename: "file", Chunk: []byte("first")}}})
			if c.budget.ActivityCount() != 1 || c.budget.TryMaintenance() {
				t.Fatal("partial upload idle")
			}
			if finish == "abort" {
				s.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileUploadAbort{FileUploadAbort: &pb.FileUploadAbort{RequestId: "partial"}}})
				if ack := activityMessage(t, send).GetFileUploadAck(); ack.Success {
					t.Fatal(ack)
				}
			} else {
				s.close()
			}
			if c.budget.ActivityCount() != 0 {
				t.Fatal("cleanup did not release")
			}
			entries, _ := os.ReadDir(c.dropzone.Dir())
			if len(entries) != 0 {
				t.Fatal("partial committed", entries)
			}
		})
	}
}

func TestOldUploadCleanupCannotDeleteOrTruncateReplacementSession(t *testing.T) {
	c := activityClient(t)
	send := make(chan *pb.AgentMessage, 16)
	old := newActivitySession(context.Background(), c, send)
	defer old.close()
	current := newActivitySession(context.Background(), c, send)
	defer current.close()
	chunk := func(id, name, data string) *pb.HubMessage {
		return &pb.HubMessage{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: id, Filename: name, Chunk: []byte(data)}}}
	}
	old.dispatch(chunk("old", "old.txt", "preserve old"))
	current.dispatch(chunk("old", "collision.txt", "must not truncate"))
	if ack := activityMessage(t, send).GetFileUploadAck(); ack.Success || ack.Error == "" {
		t.Fatal("replacement overwrote old partial", ack)
	}
	if data, err := os.ReadFile(filepath.Join(c.dropzone.Dir(), ".upload-old")); err != nil || string(data) != "preserve old" {
		t.Fatal(string(data), err)
	}
	current.dispatch(chunk("new", "new.txt", "preserve new"))
	old.close()
	if data, err := os.ReadFile(filepath.Join(c.dropzone.Dir(), ".upload-new")); err != nil || string(data) != "preserve new" {
		t.Fatal("old cleanup deleted new upload", string(data), err)
	}
	if c.budget.ActivityCount() != 1 {
		t.Fatal("old cleanup released replacement lease")
	}
	current.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: "new", Done: true}}})
	if ack := activityMessage(t, send).GetFileUploadAck(); !ack.Success {
		t.Fatal(ack)
	}
	if c.budget.ActivityCount() != 0 {
		t.Fatal("replacement completion leaked")
	}
}

func TestCancellationUnblocksCapabilityAndResponseQueues(t *testing.T) {
	c := activityClient(t)
	send := make(chan *pb.AgentMessage, 2)
	s := newActivitySession(context.Background(), c, send)
	s.observe(c.updates.Capabilities(), nil)
	send <- &pb.AgentMessage{}
	admitted := make(chan func(), 1)
	go func() { release, _ := c.budget.AcquireActivity(); admitted <- release }()
	done := make(chan struct{})
	go func() { s.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnect deadlocked with capability backpressure")
	}
	select {
	case release := <-admitted:
		release()
	case <-time.After(3 * time.Second):
		t.Fatal("capability callback leaked")
	}
	if c.budget.ActivityCount() != 0 {
		t.Fatal("cancellation corrupted reservations")
	}
	blocked := newActivitySession(context.Background(), c, make(chan *pb.AgentMessage))
	blocked.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{RequestId: "read", Path: "/nonexistent"}}})
	blocked.close()
	waitActivityCount(t, c, 0)
}

func TestCapabilityBackpressureForcesReconnectWithoutClaimingWorkerExit(t *testing.T) {
	for _, control := range []bool{false, true} {
		t.Run(map[bool]string{false: "notification", true: "stream_cancellation"}[control], func(t *testing.T) {
			c := activityClient(t)
			send := make(chan *pb.AgentMessage, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var s *activitySession
			if control {
				s = newActivitySession(ctx, c, send, cancel)
			} else {
				s = newActivitySession(ctx, c, send)
			}
			defer s.close()
			s.capabilityTimeout = 10 * time.Millisecond
			s.observe(c.updates.Capabilities(), nil)
			release, ok := c.budget.AcquireActivity()
			if !ok {
				t.Fatal("activity refused")
			}
			defer release()
			if control {
				if ctx.Err() == nil {
					t.Fatal("blocked gRPC Send was not canceled")
				}
			} else {
				select {
				case <-c.reconnectCh:
				case <-time.After(time.Second):
					t.Fatal("missing bounded reconnect")
				}
			}
			if s.ctx.Err() == nil || c.budget.ActivityCount() != 1 || c.budget.TryMaintenance() {
				t.Fatal("reporting failure fabricated quiescence")
			}
			s.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: "late", Filename: "late"}}})
			entries, _ := os.ReadDir(c.dropzone.Dir())
			if len(entries) != 0 {
				t.Fatal("failed reporter continued admission")
			}
		})
	}
}

func TestLogStartupFailuresAndCapacityReportTerminalCompletion(t *testing.T) {
	for _, fault := range []string{"denied", "missing", "seek", "limit"} {
		t.Run(fault, func(t *testing.T) {
			c := activityClient(t)
			send := make(chan *pb.AgentMessage, 128)
			s := newActivitySession(context.Background(), c, send)
			defer s.close()
			path := "/nonexistent/file"
			switch fault {
			case "denied":
				c.allowedPaths = []string{t.TempDir()}
			case "seek":
				path = t.TempDir()
			case "limit":
				for i := 0; i < maxTailSessions; i++ {
					c.tailSessions[string(rune(i))] = make(chan struct{})
				}
			}
			s.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_LogStreamRequest{LogStreamRequest: &pb.LogStreamRequest{RequestId: "failed", Path: path}}})
			if response := activityMessage(t, send).GetLogStreamChunk(); !response.Done || response.Error == "" {
				t.Fatal(response)
			}
			waitActivityCount(t, c, 0)
		})
	}
}
