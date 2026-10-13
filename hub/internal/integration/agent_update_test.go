package integration

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestAgentUpdateMigrationRestartAndEnrollmentRPCBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	st, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	op := model.AgentUpdate{ID: "durable-update", NodeID: "node", ActorID: "admin", SessionID: "session", State: "installing", ExpiresAt: now + 120000, CreatedAt: now, UpdatedAt: now, PreviousBootID: "boot-nonce"}
	if err = st.CreateAgentUpdate(op); err != nil {
		t.Fatal(err)
	}
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cm := connmgr.New()
	ts := grpcserver.NewTerminalSessions()
	updates, err := grpcserver.NewAgentUpdates(st, cm, ts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAgentUpdate(op.ID)
	if err != nil || got.State != "unknown" {
		t.Fatal("migration/restart lost uncertain update", got, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpcserver.New(grpcserver.Config{Listener: listener, Store: st, ConnMgr: cm, TerminalSessions: ts, AgentUpdates: updates})
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Start() }()
	defer func() {
		server.Stop()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("gRPC server shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("gRPC server did not stop")
		}
	}()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := pb.NewAgentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.DownloadUpdate(ctx, &pb.UpdateArtifactRequest{OperationId: op.ID})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatal("enrollment listener authorized artifact RPC", err)
	}
	if _, err = client.AuthorizeUpdate(ctx, &pb.UpdateArtifactRequest{OperationId: op.ID}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("enrollment listener authorized installation RPC", err)
	}
	if _, err = client.BootstrapUpdate(ctx, &pb.UpdateBootstrapRequest{Ticket: "never-authorized"}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("enrollment listener authorized bootstrap RPC", err)
	}
}
