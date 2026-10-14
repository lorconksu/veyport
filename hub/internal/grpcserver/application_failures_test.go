package grpcserver

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/applicationtransport"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/proto/applicationproxy"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc"
)

func applicationAdmissionFixture(t *testing.T) (*Handler, *ApplicationTunnels, *applicationControlFixture, applicationtransport.Target) {
	t.Helper()
	h, st := testHandler(t)
	if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	control := &applicationControlFixture{messages: make(chan *pb.HubMessage, 64)}
	h.connMgr.Register("node", control)
	tunnels := NewApplicationTunnels(st, h.connMgr, func(context.Context, applicationtransport.Target) error { return nil })
	t.Cleanup(tunnels.Close)
	h.applications = tunnels
	if err := tunnels.ObserveCapabilities("node", control, &pb.ApplicationCapabilities{ProtocolVersion: 1, RawTcp: true, BootId: "1234567890123456"}); err != nil {
		t.Fatal(err)
	}
	return h, tunnels, control, applicationtransport.Target{ApplicationID: "app", ConfigVersion: 1, NodeID: "node", Scheme: "http", Hostname: "127.0.0.1", Port: 8080, AllowedCIDRs: []string{"127.0.0.0/8"}}
}

func TestApplicationNodeAdmissionRefusesMissingOfflineLegacyMaintenanceAndChangedConfig(t *testing.T) {
	for _, kind := range []string{"missing", "offline", "legacy", "closed-control", "maintenance", "changed-config", "closed-registry"} {
		t.Run(kind, func(t *testing.T) {
			h, tunnels, control, target := applicationAdmissionFixture(t)
			switch kind {
			case "missing":
				target.NodeID = "unknown"
			case "offline":
				if err := h.store.UpdateServerStatus("node", "offline"); err != nil {
					t.Fatal(err)
				}
			case "legacy":
				tunnels.capabilities = make(map[string]applicationCapability)
			case "closed-control":
				h.connMgr.GetConn("node").Close()
			case "maintenance":
				if err := h.connMgr.ReserveMaintenance(h.connMgr.GetConn("node"), "update", func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			case "changed-config":
				calls := 0
				tunnels.validate = func(context.Context, applicationtransport.Target) error {
					calls++
					if calls > 1 {
						return errors.New("configuration changed")
					}
					return nil
				}
			case "closed-registry":
				tunnels.Close()
			}
			if _, err := tunnels.DialApplication(context.Background(), target); err == nil {
				t.Fatalf("%s admission accepted", kind)
			}
			if len(control.messages) != 0 {
				t.Fatalf("%s sent a backend-opening command", kind)
			}
			if len(tunnels.nodes) != 0 {
				t.Fatalf("%s leaked pending slot", kind)
			}
		})
	}
}

func TestApplicationPendingCancellationAndControlLossEndExactGeneration(t *testing.T) {
	for _, kind := range []string{"cancel", "disconnect"} {
		t.Run(kind, func(t *testing.T) {
			h, tunnels, control, target := applicationAdmissionFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := tunnels.DialApplication(ctx, target); result <- err }()
			var open *pb.ApplicationOpen
			select {
			case message := <-control.messages:
				open = message.GetApplicationOpen()
			case <-time.After(time.Second):
				t.Fatal("open admission missing")
			}
			if kind == "cancel" {
				cancel()
			} else {
				tunnels.EndConnection("node", control)
				h.connMgr.Unregister("node")
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("lost admission succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("pending admission leaked")
			}
			if kind == "cancel" {
				if err := tunnels.ObserveClosed("node", control, &pb.ApplicationClosed{Binding: open.Binding}); err != nil {
					t.Fatal(err)
				}
			}
			tunnels.mu.Lock()
			left := len(tunnels.nodes)
			tunnels.mu.Unlock()
			if left != 0 {
				t.Fatal("ended pending slot retained")
			}
			if kind == "disconnect" {
				if supported, _ := tunnels.ApplicationAvailability("node"); supported {
					t.Fatal("disconnected capability retained")
				}
			}
		})
	}
}

type applicationScriptedStream struct {
	grpc.ServerStream
	ctx      context.Context
	messages []*pb.ApplicationAgentMessage
}

func (s *applicationScriptedStream) Context() context.Context { return s.ctx }
func (s *applicationScriptedStream) Recv() (*pb.ApplicationAgentMessage, error) {
	if len(s.messages) == 0 {
		return nil, io.EOF
	}
	message := s.messages[0]
	s.messages = s.messages[1:]
	return message, nil
}
func (s *applicationScriptedStream) Send(*pb.ApplicationHubMessage) error { return nil }

func TestApplicationRPCOpeningAndByteFramesFailClosed(t *testing.T) {
	for _, kind := range []string{"backend-failure", "forged-ready", "nil-frame", "duplicate-ready", "bad-sequence", "half-close"} {
		t.Run(kind, func(t *testing.T) {
			h, tunnels, _, target := applicationAdmissionFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &applicationTunnel{ctx: ctx, cancel: cancel, control: h.connMgr.GetConn("node"), target: target, binding: &pb.ApplicationBinding{ConnectionId: "connection", ApplicationId: "app", ConfigVersion: 1, NodeId: "node", ExpiresUnixMilli: time.Now().Add(time.Second).UnixMilli()}, ready: make(chan error, 1)}
			conn := applicationproxy.NewConn(ctx, func(applicationproxy.Frame) error { return nil }, cancel)
			defer conn.Close()
			ready := &pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Opened{Opened: &pb.ApplicationOpened{Binding: s.binding}}}
			stream := &applicationScriptedStream{ctx: ctx, messages: []*pb.ApplicationAgentMessage{ready}}
			switch kind {
			case "backend-failure":
				stream.messages = []*pb.ApplicationAgentMessage{{Payload: &pb.ApplicationAgentMessage_OpenFailed{OpenFailed: &pb.ApplicationOpenFailed{Binding: s.binding, ReasonCode: "backend_unavailable"}}}}
			case "forged-ready":
				stream.messages = []*pb.ApplicationAgentMessage{{Payload: &pb.ApplicationAgentMessage_Opened{Opened: &pb.ApplicationOpened{Binding: &pb.ApplicationBinding{ConnectionId: "other"}}}}}
			case "nil-frame":
				stream.messages = append(stream.messages, nil)
			case "duplicate-ready":
				stream.messages = append(stream.messages, ready)
			case "bad-sequence":
				stream.messages = append(stream.messages, &pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Data{Data: &pb.ApplicationData{Sequence: 2, Data: []byte("forged")}}})
			case "half-close":
				stream.messages = append(stream.messages, &pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Eof{Eof: &pb.ApplicationEOF{}}})
			}
			if err := tunnels.receiveApplication(stream, s, conn); err == nil {
				t.Fatal("invalid/incomplete stream accepted")
			}
			if kind == "half-close" {
				if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("half close changed: %v", err)
				}
			}
		})
	}
}
