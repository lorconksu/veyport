package client

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"

	"github.com/wyiu/veyport/proto/fileview"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func dispatchRead(t *testing.T, session *activitySession, req *pb.FileReadRequest) {
	t.Helper()
	if !session.dispatch(&pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: req}}) {
		t.Fatal("file read request was not handled")
	}
}

func nextFileData(t *testing.T, session *activitySession) fileDataRecord {
	t.Helper()
	synctest.Wait()
	select {
	case record := <-session.fileData:
		return record
	default:
		t.Fatal("file read did not produce its next data record")
		return fileDataRecord{}
	}
}

func writeReadFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestChunkedTailReadStreamsBoundedTail(t *testing.T) {
	entry := []byte("recent log entries\n")
	tail := bytes.Repeat(entry, fileview.MaxTailSize/len(entry)+1)[:fileview.MaxTailSize]
	contents := append([]byte("discarded log entry\n"), tail...)
	path := writeReadFile(t, t.TempDir(), "logs.txt", contents)

	synctest.Test(t, func(t *testing.T) {
		c := activityClient(t)
		control := make(chan *pb.AgentMessage, 1)
		session := newActivitySession(t.Context(), c, control)
		defer session.close()
		req := &pb.FileReadRequest{RequestId: "tail", Path: path, Mode: pb.FileReadMode_FILE_READ_MODE_CHUNKED_TAIL}
		dispatchRead(t, session, req)

		for offset := 0; offset < len(tail); offset += fileview.MaxChunkSize {
			record := nextFileData(t, session)
			if len(control) != 0 {
				t.Fatalf("tail announced completion before sending the chunk at %d", offset)
			}
			got := record.message.GetFileReadResponse()
			want := &pb.FileReadResponse{
				RequestId: "tail", ChunkOffset: proto.Int64(int64(offset)), TotalSize: int64(len(contents)),
				Data: tail[offset:min(offset+fileview.MaxChunkSize, len(tail))],
			}
			if !proto.Equal(got, want) {
				t.Fatalf("wrong tail record at %d: got offset %v, %d bytes, done %v, error %q",
					offset, got.GetChunkOffset(), len(got.GetData()), got.GetDone(), got.GetError())
			}
			record.sent <- nil
		}
		got := activityMessage(t, control).GetFileReadResponse()
		want := &pb.FileReadResponse{
			RequestId: "tail", ChunkOffset: proto.Int64(int64(len(tail))), TotalSize: int64(len(contents)),
			MimeType: "text/plain", Done: true,
		}
		if !proto.Equal(got, want) {
			t.Fatalf("terminal tail record = %v, want %v", got, want)
		}
		synctest.Wait()
		if count := c.budget.ActivityCount(); count != 0 {
			t.Fatalf("completed tail left %d active workers", count)
		}
	})
}

func TestFileReadFailuresKeepWireContract(t *testing.T) {
	allowed := t.TempDir()
	allowedFile := writeReadFile(t, allowed, "data.txt", []byte("contents"))
	outside := writeReadFile(t, t.TempDir(), "outside.txt", []byte("outside allowed root"))
	large := writeReadFile(t, allowed, "large.png", nil)
	if err := os.Truncate(large, fileview.MaxFileSize+1); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		mode    pb.FileReadMode
		path    string
		failure pb.FileReadFailure
	}{
		{"legacy denied", pb.FileReadMode_FILE_READ_MODE_LEGACY, outside, pb.FileReadFailure_FILE_READ_FAILURE_UNSPECIFIED},
		{"unsupported mode", pb.FileReadMode(99), allowedFile, pb.FileReadFailure_FILE_READ_FAILURE_UNSPECIFIED},
		{"tail denied", pb.FileReadMode_FILE_READ_MODE_CHUNKED_TAIL, outside, pb.FileReadFailure_FILE_READ_FAILURE_ACCESS_DENIED},
		{"tail directory", pb.FileReadMode_FILE_READ_MODE_CHUNKED_TAIL, allowed, pb.FileReadFailure_FILE_READ_FAILURE_UNSPECIFIED},
		{"tail too large", pb.FileReadMode_FILE_READ_MODE_CHUNKED_TAIL, large, pb.FileReadFailure_FILE_READ_FAILURE_TOO_LARGE},
		{"image denied", pb.FileReadMode_FILE_READ_MODE_IMAGE, outside, pb.FileReadFailure_FILE_READ_FAILURE_ACCESS_DENIED},
		{"image missing", pb.FileReadMode_FILE_READ_MODE_IMAGE, filepath.Join(allowed, "missing.png"), pb.FileReadFailure_FILE_READ_FAILURE_UNSPECIFIED},
		{"image too large", pb.FileReadMode_FILE_READ_MODE_IMAGE, large, pb.FileReadFailure_FILE_READ_FAILURE_TOO_LARGE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := activityClient(t)
				c.allowedPaths = []string{allowed}
				control := make(chan *pb.AgentMessage, 1)
				session := newActivitySession(t.Context(), c, control)
				defer session.close()
				dispatchRead(t, session, &pb.FileReadRequest{RequestId: "read", Path: tc.path, Mode: tc.mode})

				got := activityMessage(t, control).GetFileReadResponse()
				if got.GetRequestId() != "read" || got.GetError() == "" || len(got.GetData()) != 0 || got.GetFailure() != tc.failure {
					t.Fatalf("failure response = %v, want %s for request read", got, tc.failure)
				}
				if tc.mode == pb.FileReadMode_FILE_READ_MODE_LEGACY {
					if got.GetDone() || got.ChunkOffset != nil {
						t.Fatalf("legacy failure used stream framing: %v", got)
					}
				} else if !got.GetDone() || got.ChunkOffset == nil || got.GetChunkOffset() != 0 {
					t.Fatalf("stream failure did not terminate the read: %v", got)
				}
				synctest.Wait()
				if count := c.budget.ActivityCount(); count != 0 {
					t.Fatalf("failed read left %d active workers", count)
				}
			})
		})
	}
}

func TestFileReadTimesOutWaitingForDataAcknowledgment(t *testing.T) {
	path := writeReadFile(t, t.TempDir(), "data.png", []byte("preview payload"))
	for _, mode := range []pb.FileReadMode{pb.FileReadMode_FILE_READ_MODE_CHUNKED_TAIL, pb.FileReadMode_FILE_READ_MODE_IMAGE} {
		t.Run(mode.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := activityClient(t)
				control := make(chan *pb.AgentMessage, 1)
				session := newActivitySession(t.Context(), c, control)
				defer session.close()
				dispatchRead(t, session, &pb.FileReadRequest{RequestId: "stalled", Path: path, Mode: mode})

				record := nextFileData(t, session)
				if len(control) != 0 || c.budget.ActivityCount() != 1 {
					t.Fatal("read finished while the data record was still unacknowledged")
				}
				// Leave the bulk record unacknowledged while the virtual clock advances.
				<-record.ctx.Done()
				if !errors.Is(record.ctx.Err(), context.DeadlineExceeded) {
					t.Fatalf("unacknowledged data ended with %v", record.ctx.Err())
				}
				got := activityMessage(t, control).GetFileReadResponse()
				if got.GetRequestId() != "stalled" || !got.GetDone() || got.ChunkOffset == nil || got.GetChunkOffset() != 0 ||
					got.GetFailure() != pb.FileReadFailure_FILE_READ_FAILURE_TIMEOUT || len(got.GetData()) != 0 {
					t.Fatalf("read did not report terminal timeout: %v", got)
				}
				synctest.Wait()
				if session.ctx.Err() != nil || c.budget.ActivityCount() != 0 {
					t.Fatalf("timed-out read left session error %v with %d active workers", session.ctx.Err(), c.budget.ActivityCount())
				}
			})
		})
	}
}

func TestImageReadAlreadyInProgressStreamsOnce(t *testing.T) {
	data := append(bytes.Repeat([]byte{0x42}, fileview.MaxChunkSize), 0x43)
	path := writeReadFile(t, t.TempDir(), "image.png", data)

	synctest.Test(t, func(t *testing.T) {
		c := activityClient(t)
		control := make(chan *pb.AgentMessage, 1)
		session := newActivitySession(t.Context(), c, control)
		defer session.close()
		req := &pb.FileReadRequest{RequestId: "image", Path: path, Mode: pb.FileReadMode_FILE_READ_MODE_IMAGE}
		dispatchRead(t, session, req)
		first := nextFileData(t, session)

		dispatchRead(t, session, req)
		synctest.Wait()
		if c.budget.ActivityCount() != 1 || len(control) != 0 {
			t.Fatal("duplicate request started another worker or returned an early terminal response")
		}
		wantFirst := &pb.FileReadResponse{
			RequestId: "image", ChunkOffset: proto.Int64(0), TotalSize: int64(len(data)), Data: data[:fileview.MaxChunkSize],
		}
		if got := first.message.GetFileReadResponse(); !proto.Equal(got, wantFirst) {
			t.Fatalf("wrong first image record: offset %d, size %d, %d bytes", got.GetChunkOffset(), got.GetTotalSize(), len(got.GetData()))
		}
		first.sent <- nil

		last := nextFileData(t, session)
		wantLast := &pb.FileReadResponse{
			RequestId: "image", ChunkOffset: proto.Int64(fileview.MaxChunkSize), TotalSize: int64(len(data)), Data: []byte{0x43},
		}
		if got := last.message.GetFileReadResponse(); !proto.Equal(got, wantLast) {
			t.Fatalf("final image data record = %v, want %v", got, wantLast)
		}
		last.sent <- nil
		got := activityMessage(t, control).GetFileReadResponse()
		want := &pb.FileReadResponse{RequestId: "image", ChunkOffset: proto.Int64(int64(len(data))), TotalSize: int64(len(data)), Done: true}
		if !proto.Equal(got, want) {
			t.Fatalf("terminal image record = %v, want %v", got, want)
		}
		synctest.Wait()
		if c.budget.ActivityCount() != 0 || len(control) != 0 {
			t.Fatal("completed image left an active worker or additional response")
		}
	})
}

func TestImageReadCanceledBeforeStartReportsCancellation(t *testing.T) {
	c := activityClient(t)
	c.allowedPaths = []string{t.TempDir()}
	// A read canceled before the worker starts should report cancellation even
	// when the requested file would otherwise be denied.
	path := writeReadFile(t, t.TempDir(), "image.png", []byte("preview payload"))
	control := make(chan *pb.AgentMessage, 1)
	session := newActivitySession(t.Context(), c, control)
	defer session.close()
	ctx, cancel := context.WithCancel(session.ctx)
	cancel()

	session.readImage(ctx, &pb.FileReadRequest{RequestId: "canceled", Path: path, Mode: pb.FileReadMode_FILE_READ_MODE_IMAGE})

	got := activityMessage(t, control).GetFileReadResponse()
	want := &pb.FileReadResponse{
		RequestId: "canceled", ChunkOffset: proto.Int64(0), Done: true, Error: "image read canceled",
	}
	if !proto.Equal(got, want) || session.ctx.Err() != nil {
		t.Fatalf("read returned %v with session error %v, want %v on live session", got, session.ctx.Err(), want)
	}
}

func TestFileReadDisconnectReleasesBlockedTerminalResponse(t *testing.T) {
	path := writeReadFile(t, t.TempDir(), "empty.txt", nil)
	synctest.Test(t, func(t *testing.T) {
		c := activityClient(t)
		session := newActivitySession(t.Context(), c, make(chan *pb.AgentMessage))
		defer session.close()
		dispatchRead(t, session, &pb.FileReadRequest{RequestId: "tail", Path: path, Mode: pb.FileReadMode_FILE_READ_MODE_CHUNKED_TAIL})

		synctest.Wait()
		if c.budget.ActivityCount() != 1 {
			t.Fatal("read did not hold its reservation while the terminal response was blocked")
		}
		session.close()
		synctest.Wait()
		if count := c.budget.ActivityCount(); count != 0 {
			t.Fatalf("disconnect left %d active read workers", count)
		}
	})
}
