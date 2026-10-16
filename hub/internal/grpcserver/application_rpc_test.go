package grpcserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/applicationtransport"
	"github.com/wyiu/veyport/hub/internal/ca"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type applicationControlFixture struct {
	mockStream
	messages chan *pb.HubMessage
}

func (c *applicationControlFixture) Send(message *pb.HubMessage) error {
	select {
	case c.messages <- message:
		return nil
	case <-c.Context().Done():
		return c.Context().Err()
	}
}

func TestApplicationActualRPCRejectsBootstrapAndStreamsBytes(t *testing.T) {
	h, st := testHandler(t)
	if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "node"}}, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := ca.SignCSR(h.caCert, h.caKey, csr, "node", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey, err := ca.GenerateServerCert(h.caCert, h.caKey, "hub", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(h.caCert)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	control := &applicationControlFixture{mockStream: mockStream{ctx: applicationPeer(clientCert, true)}, messages: make(chan *pb.HubMessage, 32)}
	connection := h.connMgr.Register("node", control)
	tunnels := NewApplicationTunnels(st, h.connMgr, func(context.Context, applicationtransport.Target) error { return nil })
	defer tunnels.Close()
	h.applications = tunnels
	if err := tunnels.ObserveCapabilities("node", control, &pb.ApplicationCapabilities{ProtocolVersion: 1, RawTcp: true, BootId: "1234567890123456"}); err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool, Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw, h.caCert.Raw}, PrivateKey: serverKey}}}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	pb.RegisterAgentServiceServer(server, h)
	go server.Serve(lis)
	defer server.Stop()
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "127.0.0.1"}
	bootstrapConn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrapConn.Close()
	bootstrap, err := pb.NewAgentServiceClient(bootstrapConn).ApplicationProxy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bootstrap.Recv()
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bootstrap listener exception authorized app RPC: %v", err)
	}
	clientTLS = clientTLS.Clone()
	clientTLS.Certificates = []tls.Certificate{{Certificate: [][]byte{clientCert.Raw, h.caCert.Raw}, PrivateKey: clientKey}}
	dataConn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	defer dataConn.Close()
	client := pb.NewAgentServiceClient(dataConn)
	target := applicationtransport.Target{ApplicationID: "app", ConfigVersion: 1, NodeID: "node", Scheme: "http", Hostname: "127.0.0.1", Port: 8080, AllowedCIDRs: []string{"127.0.0.0/8"}}
	type dialResult struct {
		conn net.Conn
		err  error
	}
	dialed := make(chan dialResult, 1)
	go func() { c, err := tunnels.DialApplication(ctx, target); dialed <- dialResult{c, err} }()
	var open *pb.ApplicationOpen
	select {
	case command := <-control.messages:
		open = command.GetApplicationOpen()
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if open == nil {
		t.Fatal("open command missing")
	}
	stream, err := client.ApplicationProxy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	attach := &pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Attach{Attach: &pb.ApplicationAttach{Binding: open.Binding, Ticket: open.AttachTicket}}}
	if err := stream.Send(attach); err != nil {
		t.Fatal(err)
	}
	if message, err := stream.Recv(); err != nil || message.GetAttached() == nil {
		t.Fatalf("attach failed: %v", err)
	}
	replay, err := client.ApplicationProxy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := replay.Send(attach); err != nil {
		t.Fatal(err)
	}
	if _, err := replay.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ticket replay accepted: %v", err)
	}
	if err := stream.Send(&pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Opened{Opened: &pb.ApplicationOpened{Binding: open.Binding}}}); err != nil {
		t.Fatal(err)
	}
	var result dialResult
	select {
	case result = <-dialed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.conn.Close()
	if err := h.connMgr.ReserveMaintenance(connection, "update", func() error { return nil }); err == nil {
		t.Fatal("active socket allowed update maintenance")
	}
	agentDone := make(chan error, 1)
	go func() {
		for {
			message, err := stream.Recv()
			if err != nil {
				agentDone <- err
				return
			}
			data := message.GetData()
			if data != nil {
				err = stream.Send(&pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Data{Data: &pb.ApplicationData{Sequence: data.Sequence, Data: data.Data}}})
			} else if eof := message.GetEof(); eof != nil {
				err = stream.Send(&pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Eof{Eof: eof}})
			} else {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				agentDone <- err
				return
			}
		}
	}()
	want := bytes.Repeat([]byte("application-byte-integrity"), 10000)
	written := make(chan error, 1)
	go func() { _, err := result.conn.Write(want); written <- err }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(result.conn, got); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("RPC byte stream changed")
	}
	result.conn.Close()
	select {
	case <-agentDone:
	case <-time.After(time.Second):
		t.Fatal("RPC did not cancel with Conn.Close")
	}
	if err := tunnels.ObserveClosed("node", control, &pb.ApplicationClosed{Binding: open.Binding, ReasonCode: "cancelled"}); err != nil {
		t.Fatal(err)
	}
	if err := h.connMgr.ReserveMaintenance(connection, "update", func() error { return nil }); err != nil {
		t.Fatalf("actual closure did not release update admission: %v", err)
	}
}
