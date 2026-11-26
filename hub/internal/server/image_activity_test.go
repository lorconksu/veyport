package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/proto/fileview"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

type pausedImageStream struct {
	heldActivityStream
	read    chan string
	resume  chan struct{}
	stopped chan string
}

func (s *pausedImageStream) Send(msg *pb.HubMessage) error {
	if req := msg.GetFileReadRequest(); req != nil {
		s.read <- req.GetRequestId()
		<-s.resume
	}
	if stop := msg.GetFileReadCancel(); stop != nil {
		s.stopped <- stop.GetRequestId()
	}
	return nil
}

func TestImageHTTPCancelDoesNotCloseAgentOrClaimRemoteCompletion(t *testing.T) {
	srv, token, node := updateHTTPFixture(t)
	stream := &pausedImageStream{read: make(chan string, 1), resume: make(chan struct{}), stopped: make(chan string, 1)}
	conn := srv.connMgr.Register(node, stream)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/servers/"+node+"/files/image?path=/fixture.png", nil).WithContext(ctx)
	req.Header.Set("Authorization", testBearerPrefix+token)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		srv.routes().ServeHTTP(httptest.NewRecorder(), req)
	}()
	var id string
	select {
	case id = <-stream.read:
	case <-time.After(3 * time.Second):
		close(stream.resume)
		t.Fatal("image request never reached stream")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		close(stream.resume)
		t.Fatal("canceled HTTP request waited for the admitted transport write")
	}
	if len(srv.imagePreviewSlots) != 0 {
		close(stream.resume)
		t.Fatal("canceled request held its response slot during the transport write")
	}
	close(stream.resume)
	select {
	case stopped := <-stream.stopped:
		if stopped != id {
			t.Fatalf("cancellation stopped the wrong request, got %s, want %s", stopped, id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("recovering image writer did not send the best-effort stop")
	}

	if srv.connMgr.GetConn(node) != conn {
		t.Fatal("browser cancellation disconnected the control stream")
	}
	if srv.connMgr.CompleteResponse(node, stream, &pb.FileReadResponse{RequestId: id, ChunkOffset: proto.Int64(0), Data: []byte{1}}) {
		t.Fatal("provisional chunk released a dispatched image worker")
	}
	if srv.connMgr.CompleteResponse(node, stream, &pb.FileReadResponse{
		RequestId: id, ChunkOffset: proto.Int64(0), Data: []byte{1}, Done: true,
	}) {
		t.Fatal("data-bearing terminal chunk released the read reservation")
	}
	if err := srv.connMgr.ReserveMaintenance(conn, "early", func() error { return nil }); !errors.Is(err, connmgr.ErrActivityBusy) {
		t.Fatal("browser cancellation claimed remote completion", err)
	}
	if !srv.connMgr.CompleteResponse(node, stream, &pb.FileReadResponse{RequestId: id, ChunkOffset: proto.Int64(0), Done: true, Error: "image read canceled"}) {
		t.Fatal("terminal response did not release read reservation")
	}
	if err := srv.connMgr.ReserveMaintenance(conn, "after", func() error { return nil }); err != nil {
		t.Fatal("maintenance could not proceed after remote completion", err)
	}
}

func TestImageHTTPCancelSkipsCongestedControlSend(t *testing.T) {
	srv, token, node := updateHTTPFixture(t)
	stream := &pausedImageStream{read: make(chan string, 1), resume: make(chan struct{}), stopped: make(chan string, 1)}
	conn := srv.connMgr.Register(node, stream)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/servers/"+node+"/files/image?path=/fixture.png", nil).WithContext(ctx)
	req.Header.Set("Authorization", testBearerPrefix+token)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		srv.routes().ServeHTTP(httptest.NewRecorder(), req)
	}()
	select {
	case <-stream.read:
		close(stream.resume)
	case <-time.After(3 * time.Second):
		close(stream.resume)
		t.Fatal("image request never reached stream")
	}
	conn.SendMu.Lock()
	defer conn.SendMu.Unlock()
	cancel()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled request waited behind a shared control send")
	}
	if srv.connMgr.GetConn(node) != conn {
		t.Fatal("queued best-effort image cancellation disconnected a healthy control stream")
	}
	select {
	case <-stream.stopped:
		t.Fatal("stop sent while another sender owned the connection")
	default:
	}
}

const (
	testImageNode = "node"
	testImageID   = "wire-image"
)

func startImageResponseFixture(t *testing.T) (*Server, *pausedImageStream, *httptest.ResponseRecorder, <-chan interface{}) {
	t.Helper()
	stream := &pausedImageStream{read: make(chan string, 1), resume: make(chan struct{}), stopped: make(chan string, 1)}
	close(stream.resume)
	srv := &Server{connMgr: connmgr.New(), pending: grpcserver.NewPendingRequests()}
	srv.connMgr.Register(testImageNode, stream)
	rec := httptest.NewRecorder()
	reply := make(chan interface{}, 1)
	go func() {
		reply <- srv.sendAgentRequestContext(t.Context(), rec, testImageNode, testImageID, func(string) *pb.HubMessage {
			return &pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{
				FileReadRequest: &pb.FileReadRequest{RequestId: testImageID, Mode: pb.FileReadMode_FILE_READ_MODE_IMAGE},
			}}
		}, 10*time.Second)
	}()
	if got := <-stream.read; got != testImageID {
		t.Fatal("wrong request", got)
	}
	synctest.Wait()
	return srv, stream, rec, reply
}

func deliverImageFixtureChunk(srv *Server, stream *pausedImageStream, offset, size int64) {
	srv.pending.DeliverFileRead(testImageNode, stream, &pb.FileReadResponse{
		RequestId: testImageID, ChunkOffset: proto.Int64(offset), TotalSize: size, Data: make([]byte, fileview.MaxChunkSize),
	})
	synctest.Wait()
}

func TestImageReadAllowsProgressBeyondControlSendTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv, stream, rec, reply := startImageResponseFixture(t)
		const size = 3 * fileview.MaxChunkSize
		for offset := int64(0); offset < size; offset += fileview.MaxChunkSize {
			time.Sleep(9 * time.Second)
			deliverImageFixtureChunk(srv, stream, offset, size)
			select {
			case <-reply:
				t.Fatalf("progressing transfer ended early, HTTP %d", rec.Code)
			default:
			}
		}
		srv.pending.DeliverFileRead(testImageNode, stream, &pb.FileReadResponse{
			RequestId: testImageID, ChunkOffset: proto.Int64(size), TotalSize: size, Done: true,
		})
		if resp, _ := (<-reply).(*pb.FileReadResponse); len(resp.GetData()) != size {
			t.Fatalf("incomplete file after regular progress, HTTP %d", rec.Code)
		}
	})
}

func TestImageReadTimesOutWithoutProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv, stream, rec, reply := startImageResponseFixture(t)
		time.Sleep(9 * time.Second)
		deliverImageFixtureChunk(srv, stream, 0, 2*fileview.MaxChunkSize)
		time.Sleep(14 * time.Second)
		select {
		case <-reply:
			t.Fatal("idle window did not start at the last valid chunk")
		default:
		}
		time.Sleep(2 * time.Second)
		if result := <-reply; result != nil || rec.Code != http.StatusGatewayTimeout {
			t.Fatalf("idle transfer returned %v, HTTP %d", result, rec.Code)
		}
	})
}

func TestImageReadHardTimeoutBoundsContinuedProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv, stream, rec, reply := startImageResponseFixture(t)
		for i := int64(0); i < 13; i++ {
			time.Sleep(9 * time.Second)
			deliverImageFixtureChunk(srv, stream, i*fileview.MaxChunkSize, 20*fileview.MaxChunkSize)
		}
		time.Sleep(4 * time.Second)
		select {
		case result := <-reply:
			if result != nil || rec.Code != http.StatusGatewayTimeout {
				t.Fatalf("long transfer returned %v, HTTP %d", result, rec.Code)
			}
		default:
			t.Fatal("ongoing progress defeated absolute transfer limit")
		}
	})
}

type imageDeadlineRecorder struct {
	*httptest.ResponseRecorder
	writeDeadline time.Time
}

func (w *imageDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.writeDeadline = deadline
	return nil
}

func TestImageReadSurfacesAgentAdmissionFailures(t *testing.T) {
	srv, token, node := updateHTTPFixture(t)
	for _, tc := range []struct {
		failure pb.FileReadFailure
		status  int
	}{
		{pb.FileReadFailure_FILE_READ_FAILURE_CAPACITY, http.StatusServiceUnavailable},
		{pb.FileReadFailure_FILE_READ_FAILURE_MAINTENANCE, http.StatusConflict},
		{pb.FileReadFailure_FILE_READ_FAILURE_TIMEOUT, http.StatusGatewayTimeout},
	} {
		stream := &pausedImageStream{read: make(chan string, 1), resume: make(chan struct{}), stopped: make(chan string, 1)}
		close(stream.resume)
		srv.connMgr.Register(node, stream)
		req := httptest.NewRequest(http.MethodGet, "/api/servers/"+node+"/files/image?path=/fixture.png", nil)
		req.Header.Set("Authorization", testBearerPrefix+token)
		rec := &imageDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		started := time.Now()
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			srv.routes().ServeHTTP(rec, req)
		}()
		select {
		case id := <-stream.read:
			srv.pending.DeliverFileRead(node, stream, &pb.FileReadResponse{
				RequestId: id, ChunkOffset: proto.Int64(0), Error: "fixture refusal", Failure: tc.failure, Done: true,
			})
		case <-time.After(3 * time.Second):
			t.Fatal("image request did not reach the agent")
		}
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Fatal("image refusal did not reach the HTTP waiter")
		}
		if rec.Code != tc.status {
			t.Errorf("failure %d returned HTTP %d, want %d", tc.failure, rec.Code, tc.status)
		}
		const writeWindow = 155 * time.Second
		if rec.writeDeadline.Before(started.Add(writeWindow)) || rec.writeDeadline.After(time.Now().Add(writeWindow)) {
			t.Error("image route write deadline does not cover the bounded transfer", rec.writeDeadline)
		}
	}
}

func TestTextFileReadHubAdmissionStatus(t *testing.T) {
	srv, token, node := updateHTTPFixture(t)
	for _, capacity := range []bool{true, false} {
		conn := srv.connMgr.Register(node, &heldActivityStream{})
		want := http.StatusConflict
		if capacity {
			want = http.StatusServiceUnavailable
			for i := range connmgr.MaxNodeActivities {
				if _, err := srv.connMgr.BeginActivity(conn, fmt.Sprint(i), connmgr.ActivityRead); err != nil {
					t.Fatal(err)
				}
			}
		} else if err := srv.connMgr.ReserveMaintenance(conn, "fixture", func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/servers/"+node+"/files/read?path=/fixture.txt", nil)
		req.Header.Set("Authorization", testBearerPrefix+token)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("capacity=%v returned %d, want %d", capacity, rec.Code, want)
		}
	}
}

func TestTextFileReadAgentAdmissionStatus(t *testing.T) {
	srv, token, node := updateHTTPFixture(t)
	stream := &pausedImageStream{read: make(chan string, 1), resume: make(chan struct{})}
	close(stream.resume)
	srv.connMgr.Register(node, stream)
	for _, tc := range []struct {
		failure pb.FileReadFailure
		status  int
	}{
		{pb.FileReadFailure_FILE_READ_FAILURE_CAPACITY, http.StatusServiceUnavailable},
		{pb.FileReadFailure_FILE_READ_FAILURE_MAINTENANCE, http.StatusConflict},
		{pb.FileReadFailure_FILE_READ_FAILURE_UNSPECIFIED, http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/servers/"+node+"/files/read?path=/fixture.txt", nil)
		req.Header.Set("Authorization", testBearerPrefix+token)
		rec := httptest.NewRecorder()
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			srv.routes().ServeHTTP(rec, req)
		}()
		select {
		case id := <-stream.read:
			resp := &pb.FileReadResponse{RequestId: id, Error: "fixture refusal", Failure: tc.failure}
			if tc.failure != pb.FileReadFailure_FILE_READ_FAILURE_UNSPECIFIED {
				resp.ChunkOffset, resp.Done = proto.Int64(0), true
			}
			srv.pending.DeliverFileRead(node, stream, resp)
		case <-time.After(3 * time.Second):
			t.Fatal("text request did not reach the agent")
		}
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Fatal("text refusal did not reach the HTTP waiter")
		}
		if rec.Code != tc.status {
			t.Errorf("failure %d returned HTTP %d, want %d", tc.failure, rec.Code, tc.status)
		}
	}
}

func TestImageValidationWaitsOnlyForSlotAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := &Server{imageDecodeSlot: make(chan struct{}, 1)}
		srv.imageDecodeSlot <- struct{}{}
		errs := make(chan error, 1)
		go func() {
			_, err := srv.validatePreview(t.Context(), nil, "image/png")
			errs <- err
		}()
		time.Sleep(10*time.Second - time.Nanosecond)
		select {
		case err := <-errs:
			t.Fatalf("decoder wait returned early: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		if err := <-errs; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("decoder slot wait: %v", err)
		}
		if len(srv.imageDecodeSlot) != 1 {
			t.Fatal("the waiter released another request's decoder slot")
		}
		<-srv.imageDecodeSlot

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := srv.validatePreview(ctx, nil, "image/png"); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled job entered validation: %v", err)
		}
		if valid, err := srv.validatePreview(t.Context(), nil, "image/png"); valid || err != nil || len(srv.imageDecodeSlot) != 0 {
			t.Fatalf("admitted invalid job did not return its slot: (%v, %v)", valid, err)
		}
	})
}

func TestImageSetupReleasesBusyAdmissionSlots(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelRequest), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				srv := &Server{
					connMgr: connmgr.New(), pending: grpcserver.NewPendingRequests(),
					imagePreviewSlots: make(chan struct{}, 8),
				}
				stream := &pausedImageStream{
					read: make(chan string, 8), resume: make(chan struct{}), stopped: make(chan string, 8),
				}
				close(stream.resume)
				conn := srv.connMgr.Register(testImageNode, stream)
				conn.SendMu.Lock()
				defer conn.SendMu.Unlock()
				original, cancel := context.WithCancel(context.WithValue(t.Context(), ctxUserRole, "admin"))
				defer cancel()
				finished := make(chan int, cap(srv.imagePreviewSlots))
				for range cap(finished) {
					go func() {
						req := httptest.NewRequest(http.MethodGet, "/files/image?path=/fixture.png", nil).WithContext(original)
						req.SetPathValue("id", testImageNode)
						rec := httptest.NewRecorder()
						srv.handleImagePreview(rec, req)
						finished <- rec.Code
					}()
				}
				synctest.Wait()
				if len(srv.imagePreviewSlots) != cap(finished) {
					t.Fatal("fixture did not cover the image response limit")
				}
				if cancelRequest {
					cancel()
				} else {
					time.Sleep(10 * time.Second)
				}
				synctest.Wait()
				if len(finished) != cap(finished) || len(srv.imagePreviewSlots) != 0 {
					t.Fatal("image setup retained response slots behind a busy control writer")
				}
				if !cancelRequest {
					for range cap(finished) {
						if code := <-finished; code != http.StatusGatewayTimeout {
							t.Fatalf("expired setup: HTTP %d", code)
						}
					}
				}
				if len(stream.read) != 0 || srv.connMgr.GetConn(testImageNode) != conn {
					t.Fatal("abandoned setup dispatched remote work or closed the connection")
				}
			})
		})
	}
}
