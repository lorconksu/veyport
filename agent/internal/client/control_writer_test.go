package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestControlWriterReportsTransportExit(t *testing.T) {
	closedTransport := errors.New("transport closed")
	for _, tc := range []struct {
		name   string
		cause  error
		prefix string
	}{
		{"receive", closedTransport, "receive error: "},
		{"control send", closedTransport, "send: "},
		{"file send", closedTransport, "send file data: "},
		{"reconnect", errReconnectWithMTLS, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				control := make(chan *pb.AgentMessage, 1)
				fileData := make(chan fileDataRecord, 1)
				recvErr := make(chan error, 1)
				reconnect := make(chan struct{}, 1)
				sent := make(chan error, 1)

				var wantMessage *pb.AgentMessage
				switch tc.name {
				case "receive":
					recvErr <- closedTransport
				case "control send":
					wantMessage = &pb.AgentMessage{Payload: &pb.AgentMessage_Heartbeat{Heartbeat: &pb.Heartbeat{}}}
					control <- wantMessage
				case "file send":
					wantMessage = &pb.AgentMessage{Payload: &pb.AgentMessage_FileReadResponse{
						FileReadResponse: &pb.FileReadResponse{RequestId: "bulk", Data: []byte("chunk")},
					}}
					fileData <- fileDataRecord{ctx: ctx, message: wantMessage, sent: sent}
				case "reconnect":
					reconnect <- struct{}{}
				}

				var gotMessage *pb.AgentMessage
				err := runControlWriter(ctx, cancel, func(message *pb.AgentMessage) error {
					gotMessage = message
					return closedTransport
				}, control, fileData, recvErr, reconnect)
				if !errors.Is(err, tc.cause) || !strings.HasPrefix(err.Error(), tc.prefix) {
					t.Fatalf("writer returned %v, want %q wrapping %v", err, tc.prefix, tc.cause)
				}
				if gotMessage != wantMessage {
					t.Fatalf("writer sent %v, want %v", gotMessage, wantMessage)
				}
				if tc.name == "file send" {
					select {
					case err := <-sent:
						if !errors.Is(err, closedTransport) {
							t.Fatalf("bulk sender received %v, want %v", err, closedTransport)
						}
					default:
						t.Fatal("writer exited without reporting the failed data send to the worker")
					}
				}
			})
		})
	}
}

func TestControlWriterSkipsCanceledFileRecordAndKeepsStreamOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		read, cancelRead := context.WithCancel(ctx)
		cancelRead()

		control := make(chan *pb.AgentMessage, 1)
		fileData := make(chan fileDataRecord, 1)
		messages := make(chan *pb.AgentMessage, 2)
		writerDone := make(chan error, 1)
		go func() {
			writerDone <- runControlWriter(ctx, cancel, func(message *pb.AgentMessage) error {
				messages <- message
				return nil
			}, control, fileData, nil, nil)
		}()

		sent := make(chan error, 1)
		fileData <- fileDataRecord{ctx: read, sent: sent, message: &pb.AgentMessage{
			Payload: &pb.AgentMessage_FileReadResponse{FileReadResponse: &pb.FileReadResponse{RequestId: "canceled", Data: []byte("stale")}},
		}}
		if err := <-sent; !errors.Is(err, context.Canceled) {
			t.Fatalf("discarded record reported %v, want read cancellation", err)
		}

		heartbeat := &pb.AgentMessage{Payload: &pb.AgentMessage_Heartbeat{Heartbeat: &pb.Heartbeat{}}}
		control <- heartbeat
		if got := <-messages; got != heartbeat || ctx.Err() != nil {
			t.Fatalf("writer sent %v with generation error %v, want heartbeat on live stream", got, ctx.Err())
		}
		cancel()
		if err := <-writerDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("writer returned %v after disconnect", err)
		}
	})
}
