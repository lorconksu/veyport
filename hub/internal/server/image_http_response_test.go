package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

type previewReplyStream struct {
	heldActivityStream
	requests chan *pb.FileReadRequest
	reply    func(*pb.FileReadRequest)
}

func (s *previewReplyStream) Send(msg *pb.HubMessage) error {
	if req := msg.GetFileReadRequest(); req != nil {
		s.requests <- req
		s.reply(req)
	}
	return nil
}

func registerPreviewReply(s *Server, node string, data []byte, size int64) *previewReplyStream {
	stream := &previewReplyStream{requests: make(chan *pb.FileReadRequest, 2)}
	stream.reply = func(req *pb.FileReadRequest) {
		chunk := &pb.FileReadResponse{
			RequestId: req.GetRequestId(), ChunkOffset: proto.Int64(0), TotalSize: size, Data: data,
		}
		s.pending.DeliverFileRead(node, stream, chunk)
		done := &pb.FileReadResponse{
			RequestId: req.GetRequestId(), ChunkOffset: proto.Int64(int64(len(data))), TotalSize: size,
			Done: true, MimeType: "application/octet-stream",
		}
		s.connMgr.CompleteResponse(node, stream, done)
		s.pending.DeliverFileRead(node, stream, done)
	}
	s.connMgr.Register(node, stream)
	return stream
}

func TestPreviewHTTPStreamsOriginalImageAndAuditsSuccess(t *testing.T) {
	s, token, node := testServerWithAgent(t)
	data := decodePreviewFixture(t, translucentAnimatedWebP)
	const path = "/photos/summer trip.WEBP"
	for _, tc := range []struct {
		name   string
		size   int64
		status int
	}{
		{"incomplete transfer", int64(len(data)) + 1, http.StatusBadGateway},
		{"complete transfer", int64(len(data)), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := registerPreviewReply(s, node, data, tc.size)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/servers/"+node+"/files/image?path="+url.QueryEscape(path), nil)
			req.Header.Set("Authorization", testBearerPrefix+token)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("HTTP %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			select {
			case read := <-stream.requests:
				if read.GetPath() != path || read.GetMode() != pb.FileReadMode_FILE_READ_MODE_IMAGE || read.GetOffset() != 0 || read.GetLimit() != 1 {
					t.Fatalf("wrong agent request: %v", read)
				}
			default:
				t.Fatal("image request did not reach the agent")
			}

			audit, _, err := s.store.ListAuditLogs(model.AuditFilter{Action: proto.String(model.AuditFileRead)})
			if err != nil {
				t.Fatal(err)
			}
			if tc.status != http.StatusOK {
				if len(audit) != 0 || rec.Header().Get("Content-Disposition") != "" {
					t.Fatal("incomplete image was reported as a successful preview")
				}
				return
			}
			for header, want := range map[string]string{
				"Content-Type":                 "image/webp",
				"Content-Length":               strconv.Itoa(len(data)),
				"Content-Disposition":          `attachment; filename="summer trip.WEBP"`,
				"Cross-Origin-Resource-Policy": "same-origin",
			} {
				if got := rec.Header().Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}
			if !bytes.Equal(rec.Body.Bytes(), data) {
				t.Error("preview changed the original image")
			}
			if len(audit) != 1 || audit[0].Target == nil || *audit[0].Target != node || audit[0].Detail == nil || *audit[0].Detail != path {
				t.Fatalf("expected a file read audit entry for %s on %s, got %#v", path, node, audit)
			}
		})
	}
}

func TestFileReadHTTPReturnsBusyBeforeSendingToAgent(t *testing.T) {
	s, token, node := testServerWithAgent(t)
	stream := registerPreviewReply(s, node, nil, 0)
	for _, tc := range []struct {
		name  string
		path  string
		slots chan struct{}
	}{
		{"image", "/files/image?path=/fixture.png", s.imagePreviewSlots},
		{"text", "/files/read?path=/fixture.txt", s.fileTailSlots},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range cap(tc.slots) {
				tc.slots <- struct{}{}
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/servers/"+node+tc.path, nil)
			req.Header.Set("Authorization", testBearerPrefix+token)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("HTTP %d, want 503: %s", rec.Code, rec.Body.String())
			}
			if len(stream.requests) != 0 || len(tc.slots) != cap(tc.slots) {
				t.Error("busy request reached the agent or released another request's slot")
			}
		})
	}
}

func TestPreviewHTTPWhileDecoderBusy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
	}{
		{"decoder admission timeout", false},
		{"client disconnect", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := &Server{
					connMgr: connmgr.New(), pending: grpcserver.NewPendingRequests(),
					imagePreviewSlots: make(chan struct{}, 1), imageDecodeSlot: make(chan struct{}, 1),
				}
				s.imageDecodeSlot <- struct{}{}
				data := decodePreviewFixture(t, translucentStillWebP)
				stream := registerPreviewReply(s, testImageNode, data, int64(len(data)))
				ctx, cancel := context.WithCancel(context.WithValue(t.Context(), ctxUserRole, "admin"))
				defer cancel()
				req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/files/image?path=/fixture.webp", nil)
				req.SetPathValue("id", testImageNode)
				rec := httptest.NewRecorder()
				go s.handleImagePreview(rec, req)
				synctest.Wait()
				if len(stream.requests) != 1 || len(s.imagePreviewSlots) != 1 {
					t.Fatal("fixture did not reach decoder admission")
				}
				if tc.cancel {
					cancel()
				} else {
					time.Sleep(10 * time.Second)
				}
				synctest.Wait()
				if len(s.imageDecodeSlot) != 1 || len(s.imagePreviewSlots) != 0 {
					t.Fatal("decoder waiter failed to release only its own preview slot")
				}
				if tc.cancel {
					if rec.Body.Len() != 0 || len(rec.Header()) != 0 {
						t.Fatalf("canceled preview wrote an HTTP response: %v %s", rec.Header(), rec.Body.String())
					}
				} else if rec.Code != http.StatusServiceUnavailable {
					t.Fatalf("busy decoder returned HTTP %d, want 503: %s", rec.Code, rec.Body.String())
				}
			})
		})
	}
}
