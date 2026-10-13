package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

type heldActivityStream struct {
	pb.AgentService_ConnectServer
	upload, abort, stop, request chan string
}

func (s *heldActivityStream) Context() context.Context { return context.Background() }
func (s *heldActivityStream) Send(m *pb.HubMessage) error {
	send := func(ch chan string, id string) {
		if ch != nil {
			select {
			case ch <- id:
			default:
			}
		}
	}
	switch p := m.Payload.(type) {
	case *pb.HubMessage_FileUploadRequest:
		if len(p.FileUploadRequest.Chunk) > 0 {
			send(s.upload, p.FileUploadRequest.RequestId)
		}
	case *pb.HubMessage_FileUploadAbort:
		send(s.abort, p.FileUploadAbort.RequestId)
	case *pb.HubMessage_LogStreamStop:
		send(s.stop, p.LogStreamStop.RequestId)
	case *pb.HubMessage_FileListRequest:
		send(s.request, p.FileListRequest.RequestId)
	}
	return nil
}
func waitActivityBusy(t *testing.T, cm *connmgr.ConnManager, conn *connmgr.AgentConn) {
	t.Helper()
	limit := time.Now().Add(3 * time.Second)
	notBusy := errors.New("not busy")
	for time.Now().Before(limit) {
		err := cm.ReserveMaintenance(conn, "probe", func() error { return notBusy })
		if errors.Is(err, connmgr.ErrActivityBusy) {
			return
		}
		if !errors.Is(err, notBusy) {
			t.Fatal("unexpected maintenance probe", err)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("request never reserved activity")
}
func TestUploadReservesBeforeMultipartHeadersAndRetainsPartialUntilAbortAck(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			s, token, node := updateHTTPFixture(t)
			stream := &heldActivityStream{upload: make(chan string, 2), abort: make(chan string, 2)}
			generation := s.connMgr.Register(node, stream)
			server := httptest.NewServer(s.routes())
			defer server.Close()
			sock, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer sock.Close()
			_ = sock.SetWriteDeadline(time.Now().Add(3 * time.Second))
			_, err = fmt.Fprintf(sock, "POST /api/servers/%s/upload HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer %s\r\nContent-Type: multipart/form-data; boundary=held\r\nContent-Length: 1000000\r\n\r\n", node, token)
			if err != nil {
				t.Fatal(err)
			}
			waitActivityBusy(t, s.connMgr, generation)
			user, err := s.store.GetUserByUsername("admin")
			if err != nil {
				t.Fatal(err)
			}
			if _, ticket, err := s.agentUpdates.Start(context.Background(), user.ID, sessionIDForToken(t, s, token), node, "2.0.1-prototype.4", strings.Repeat("f", 40), grpcserver.BootstrapIdleAssertion{Confirmed: true, ConnectionID: generation.GenerationID}); !errors.Is(err, connmgr.ErrActivityBusy) || ticket != "" {
				t.Fatal("held multipart headers admitted update or hit unrelated refusal", err)
			}
			if partial {
				_, err = fmt.Fprintf(sock, "--held\r\nContent-Disposition: form-data; name=\"file\"; filename=\"held.txt\"\r\nContent-Type: application/octet-stream\r\n\r\n%s", strings.Repeat("x", 80*1024))
				if err != nil {
					t.Fatal(err)
				}
				select {
				case <-stream.upload:
				case <-time.After(3 * time.Second):
					t.Fatal("partial upload did not reach agent")
				}
			}
			sock.Close()
			if partial {
				var id string
				select {
				case id = <-stream.abort:
				case <-time.After(3 * time.Second):
					t.Fatal("canceled partial upload omitted abort")
				}
				waitActivityBusy(t, s.connMgr, generation)
				if !s.connMgr.CompleteResponse(node, stream, &pb.FileUploadAck{RequestId: id, Success: false, Error: "upload aborted"}) {
					t.Fatal("cleanup acknowledgement did not release lifetime")
				}
			}
			limit := time.Now().Add(3 * time.Second)
			for {
				err = s.connMgr.ReserveMaintenance(generation, "finished", func() error { return nil })
				if err == nil {
					break
				}
				if time.Now().After(limit) {
					t.Fatal("completed/unsent canceled request retained activity", err)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
func sessionIDForToken(t *testing.T, s *Server, token string) string {
	t.Helper()
	claims, err := auth.ValidateToken(s.jwtSecret, token)
	if err != nil {
		t.Fatal(err)
	}
	return claims.SessionID
}
func TestFileResponseTimeoutDoesNotPretendRemoteWorkerFinished(t *testing.T) {
	s, _, node := updateHTTPFixture(t)
	stream := &heldActivityStream{request: make(chan string, 1)}
	conn := s.connMgr.Register(node, stream)
	rec := httptest.NewRecorder()
	result := s.sendAgentRequestContext(context.Background(), rec, node, "file-request", func(id string) *pb.HubMessage {
		return &pb.HubMessage{Payload: &pb.HubMessage_FileListRequest{FileListRequest: &pb.FileListRequest{RequestId: id, Path: "/tmp"}}}
	}, 5*time.Millisecond)
	if result != nil || rec.Code != http.StatusGatewayTimeout {
		t.Fatal(result, rec.Code)
	}
	if err := s.connMgr.ReserveMaintenance(conn, "too-soon", func() error { return nil }); !errors.Is(err, connmgr.ErrActivityBusy) {
		t.Fatal("HTTP timeout released remote lifetime", err)
	}
	if !s.connMgr.CompleteResponse(node, stream, &pb.FileListResponse{RequestId: "file-request"}) {
		t.Fatal("late response lost correlation lifetime")
	}
	if err := s.connMgr.ReserveMaintenance(conn, "finished", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
func TestManualBootstrapRESTAssertionIsFreshAndClosedToUnassertedInputs(t *testing.T) {
	s, token, node := updateHTTPFixture(t)
	checkRec := updateHTTPRequest(s, token, node, "GET", "", "")
	var check grpcserver.AgentUpdateCheck
	if err := json.Unmarshal(checkRec.Body.Bytes(), &check); err != nil || !check.BootstrapIdleConfirmationRequired || check.ConnectionID == "" {
		t.Fatal(check, err)
	}
	base := `{"expected_version":"2.0.1-prototype.4","expected_revision":"` + strings.Repeat("f", 40) + `"`
	for _, extra := range []string{`}`, `,"bootstrap_idle_confirmed":true}`, `,"bootstrap_idle_confirmed":true,"expected_connection_id":"stale"}`} {
		rec := updateHTTPRequest(s, token, node, "POST", "", base+extra)
		if rec.Code != http.StatusConflict {
			t.Fatal("unasserted/stale request issued authority", rec.Code, rec.Body.String())
		}
	}
	s.connMgr.Register(node, &heldActivityStream{})
	rec := updateHTTPRequest(s, token, node, "POST", "", base+`,"bootstrap_idle_confirmed":true,"expected_connection_id":"`+check.ConnectionID+`"}`)
	if rec.Code != http.StatusConflict {
		t.Fatal("replaced connection accepted old assertion", rec.Code)
	}
	var count int
	if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM agent_updates").Scan(&count); err != nil || count != 0 {
		t.Fatal("refusals created operation", count, err)
	}
}
