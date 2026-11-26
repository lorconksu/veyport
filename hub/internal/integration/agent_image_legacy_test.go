package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestImagePreviewLegacyAgentKeepsControlStream(t *testing.T) {
	h := StartHarness(t)
	token := h.SetupAdmin(t)
	node, registration := h.CreateServer(t, token, "legacy-file-read-test")
	certDir := t.TempDir()
	agent := newTestAgentClient(h, registration, certDir)
	agentCtx, stopAgent := context.WithCancel(context.Background())
	defer stopAgent()
	finished := runAgentInBackground(agent, agentCtx)
	if !waitForAgentConnect(h, node, 5*time.Second) {
		t.Fatal("agent did not enroll")
	}
	stopAgent()
	waitForAgentExit(t, finished, 3*time.Second)
	if !waitForAgentDisconnect(h, node, 3*time.Second) {
		t.Fatal("agent connection did not close")
	}

	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "client.crt"), filepath.Join(certDir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(pem) {
		t.Fatal("enrollment CA is not PEM")
	}
	conn, err := grpc.NewClient(h.GRPCAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs: ca, Certificates: []tls.Certificate{cert}, ServerName: "localhost", MinVersion: tls.VersionTLS12,
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := pb.NewAgentServiceClient(conn).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.AgentMessage{Payload: &pb.AgentMessage_Heartbeat{Heartbeat: &pb.Heartbeat{ServerId: node}}}); err != nil {
		t.Fatal(err)
	}
	if ack, err := stream.Recv(); err != nil || ack.GetHeartbeatAck() == nil {
		t.Fatal("legacy stream handshake failed", err)
	}
	if !waitForAgentConnect(h, node, 3*time.Second) {
		t.Fatal("legacy stream not registered")
	}
	generation := h.ConnMgr.GetConn(node)

	// Model a pre-chunking agent on the real enrolled gRPC stream. It
	// ignores Mode and serializes the requested tail as one legacy record.
	legacyDone := make(chan error, 1)
	go func() {
		for range 2 {
			msg, err := stream.Recv()
			if err != nil {
				legacyDone <- err
				return
			}
			req := msg.GetFileReadRequest()
			totalSize := int64(3)
			if req.GetPath() == "/large.png" {
				totalSize = 2 << 20
			}
			data := bytes.Repeat([]byte("z"), int(min(totalSize, req.GetLimit())))
			if err := stream.Send(&pb.AgentMessage{Payload: &pb.AgentMessage_FileReadResponse{
				FileReadResponse: &pb.FileReadResponse{RequestId: req.GetRequestId(), TotalSize: totalSize, Data: data},
			}}); err != nil {
				legacyDone <- err
				return
			}
		}
		legacyDone <- nil
	}()

	resp := h.HTTPGet(t, "/api/servers/"+node+"/files/image?path=/large.png", token)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || h.ConnMgr.GetConn(node) != generation {
		t.Fatalf("legacy preview status=%d, same connection=%v", resp.StatusCode, h.ConnMgr.GetConn(node) == generation)
	}
	resp = h.HTTPGet(t, "/api/servers/"+node+"/files/read?path=/log.txt", token)
	defer resp.Body.Close()
	var result model.FileReadResult
	if err := json.NewDecoder(resp.Body).Decode(&result); resp.StatusCode != http.StatusOK || err != nil || result.Data != "enp6" {
		t.Fatalf("legacy text response status=%d, result=%+v, err=%v", resp.StatusCode, result, err)
	}
	if err := <-legacyDone; err != nil {
		t.Fatal("legacy agent could not finish on shared stream", err)
	}
}
