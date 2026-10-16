package client

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	"github.com/wyiu/veyport/proto/applicationproxy"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type applicationFixtureHub struct {
	pb.UnimplementedAgentServiceServer
	opened   chan struct{}
	done     chan error
	transfer int
}

func (h *applicationFixtureHub) ApplicationProxy(stream pb.AgentService_ApplicationProxyServer) (returnErr error) {
	defer func() { h.done <- returnErr }()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	attach := first.GetAttach()
	if attach == nil {
		return errors.New("missing attachment")
	}
	if err := stream.Send(&pb.ApplicationHubMessage{Payload: &pb.ApplicationHubMessage_Attached{Attached: &pb.ApplicationAttached{Binding: attach.Binding}}}); err != nil {
		return err
	}
	first, err = stream.Recv()
	if err != nil {
		return err
	}
	if first.GetOpened() == nil {
		return errors.New("missing backend open")
	}
	close(h.opened)
	sent := make(chan error, 1)
	go func() {
		buffer := make([]byte, applicationproxy.MaxFrameBytes)
		for sequence := uint64(0); int(sequence)*len(buffer) < h.transfer; sequence++ {
			if err := stream.Send(&pb.ApplicationHubMessage{Payload: &pb.ApplicationHubMessage_Data{Data: &pb.ApplicationData{Sequence: sequence, Data: buffer}}}); err != nil {
				sent <- err
				return
			}
		}
		sent <- nil
	}()
	count := 0
	sequence := uint64(0)
	for count < h.transfer {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		data := message.GetData()
		if data == nil || data.Sequence != sequence {
			return errors.New("byte sequence changed")
		}
		sequence++
		for _, value := range data.Data {
			if value != 0 {
				return errors.New("binary bytes changed")
			}
		}
		count += len(data.Data)
	}
	if count != h.transfer {
		return errors.New("transfer length changed")
	}
	if err := <-sent; err != nil {
		return err
	}
	return nil
}

func TestApplicationActualMTLSStreams64MiBAndReleasesMaintenance(t *testing.T) {
	tlsCfg, certStore := executionTestTLS(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	fixture := &applicationFixtureHub{opened: make(chan struct{}), done: make(chan error, 1), transfer: 64 << 20}
	pb.RegisterAgentServiceServer(server, fixture)
	go server.Serve(lis)
	t.Cleanup(server.Stop)
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := New(Config{HubAddr: lis.Addr().String(), ServerID: "node", CertDir: t.TempDir(), DropzoneDir: t.TempDir()})
	c.certStore = certStore
	budget := sessionlimit.New(8)
	send := make(chan *pb.AgentMessage, 8)
	e, err := c.newApplicationTransport(ctx, budget, send, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	open := testApplicationOpen()
	open.Binding.BootId = e.bootID
	open.Target.Port = uint32(backend.Addr().(*net.TCPAddr).Port)
	e.handle(&pb.HubMessage{Payload: &pb.HubMessage_ApplicationOpen{ApplicationOpen: open}})
	select {
	case <-fixture.opened:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if budget.ActivityCount() != 1 || budget.TryMaintenance() {
		t.Fatal("active application omitted from update quiescence")
	}
	select {
	case err := <-fixture.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case ack := <-send:
		if ack.GetApplicationClosed() == nil {
			t.Fatal("actual cleanup acknowledgement missing")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if budget.ActivityCount() != 0 || !budget.TryMaintenance() {
		t.Fatal("closed application retained maintenance reservation")
	}
	select {
	case <-backendDone:
	case <-time.After(time.Second):
		t.Fatal("backend socket leaked after RPC closure")
	}
}

func TestApplicationNeverFallsBackToBootstrapOrInsecure(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		c := New(Config{HubAddr: "127.0.0.1:1", CertDir: t.TempDir(), Insecure: insecure})
		if e, err := c.newApplicationTransport(context.Background(), sessionlimit.New(8), make(chan *pb.AgentMessage, 1), func() {}); err == nil {
			e.close()
			t.Fatal("missing enrolled certificate admitted application transport")
		}
	}
}
