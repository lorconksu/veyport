package integration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/agentclient"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestAgentActivityUploadAbortAndLogCompletionThroughGRPC(t *testing.T) {
	h := StartHarness(t)
	token := h.SetupAdmin(t)
	node, enrollment := h.CreateServer(t, token, "activity-node")
	dropzone := t.TempDir()
	client := agentclient.New(agentclient.Config{HubAddr: h.GRPCAddr, Token: enrollment, CertDir: t.TempDir(), DropzoneDir: dropzone, Hostname: "activity-host", OS: "linux", AgentVersion: "0.0.0-test", HubCAPin: h.HubCAPin})
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- client.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("agent did not join after cancellation")
		}
	})
	if !waitForAgentConnect(h, node, 5*time.Second) {
		t.Fatal("agent did not connect")
	}
	conn := h.ConnMgr.GetConn(node)
	if conn == nil {
		t.Fatal("no enrolled connection")
	}
	uploadID := "activity-upload"
	acknowledgements := h.Pending.Register(node, uploadID)
	defer h.Pending.Remove(node, uploadID)
	if err := h.ConnMgr.SendToAgent(node, &pb.HubMessage{Payload: &pb.HubMessage_FileUploadRequest{FileUploadRequest: &pb.FileUploadRequest{RequestId: uploadID, Filename: "partial.txt", Chunk: []byte("unfinished")}}}); err != nil {
		t.Fatal(err)
	}
	if err := h.ConnMgr.ReserveMaintenance(conn, "too-early", func() error { return nil }); !errors.Is(err, connmgr.ErrActivityBusy) {
		t.Fatal("active upload admitted update", err)
	}
	if err := h.ConnMgr.SendToAgent(node, &pb.HubMessage{Payload: &pb.HubMessage_FileUploadAbort{FileUploadAbort: &pb.FileUploadAbort{RequestId: uploadID}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-acknowledgements:
		ack, ok := response.(*pb.FileUploadAck)
		if !ok || ack.Success || ack.Error != "upload aborted" {
			t.Fatal("abort was not terminal cleanup acknowledgement", response)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("abort acknowledgement missing")
	}
	entries, err := os.ReadDir(dropzone)
	if err != nil || len(entries) != 0 {
		t.Fatal("abort committed or retained partial data", entries, err)
	}
	if err = h.ConnMgr.ReserveMaintenance(conn, "after-abort", func() error { return nil }); err != nil {
		t.Fatal("actual cleanup did not release Hub reservation", err)
	}
	h.ConnMgr.ReleaseMaintenance(node, "after-abort")
	logPath := filepath.Join(t.TempDir(), "tail.log")
	if err = os.WriteFile(logPath, []byte("seed log line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	logID := "activity-tail"
	lines := h.LogSessions.Register(node, logID)
	if err = h.ConnMgr.SendToAgent(node, &pb.HubMessage{Payload: &pb.HubMessage_LogStreamRequest{LogStreamRequest: &pb.LogStreamRequest{RequestId: logID, Path: logPath, Offset: 1}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case line, ok := <-lines:
		if !ok || len(line) == 0 {
			t.Fatal("tail ended before admission was exercised")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tail worker did not start")
	}
	if err = h.ConnMgr.ReserveMaintenance(conn, "active-tail", func() error { return nil }); !errors.Is(err, connmgr.ErrActivityBusy) {
		t.Fatal("active tail admitted update", err)
	}
	if err = h.ConnMgr.SendToAgent(node, &pb.HubMessage{Payload: &pb.HubMessage_LogStreamStop{LogStreamStop: &pb.LogStreamStop{RequestId: logID}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-lines:
		if ok {
			t.Fatal("stop did not produce terminal stream completion")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal log completion missing")
	}
	if err = h.ConnMgr.ReserveMaintenance(conn, "idle", func() error { return nil }); err != nil {
		t.Fatal("actual tail exit did not release Hub reservation", err)
	}
}
