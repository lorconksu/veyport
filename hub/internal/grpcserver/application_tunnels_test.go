package grpcserver

import (
	"context"
	"github.com/wyiu/veyport/hub/internal/model"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/applicationtransport"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/proto/applicationproxy"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestApplicationTransportRequiresPersistedTargetValidator(t *testing.T) {
	tunnels := NewApplicationTunnels(nil, connmgr.New(), nil)
	target := applicationtransport.Target{ApplicationID: "app", ConfigVersion: 1, Scheme: "http", Hostname: "127.0.0.1", Port: 8080, AllowedCIDRs: []string{"127.0.0.0/8"}}
	if _, err := tunnels.DialApplication(context.Background(), target); err == nil {
		t.Fatal("missing persisted authority validator allowed dial")
	}
}

func TestApplicationDirectCapacityAndShutdownBoundPendingDial(t *testing.T) {
	tunnels := NewApplicationTunnels(nil, connmgr.New(), func(context.Context, applicationtransport.Target) error { return nil })
	tunnels.dial = applicationproxy.Dialer{Dial: func(context.Context, string, string) (net.Conn, error) { a, b := net.Pipe(); b.Close(); return a, nil }}
	target := applicationtransport.Target{ApplicationID: "app", ConfigVersion: 1, Scheme: "http", Hostname: "127.0.0.1", Port: 8080, AllowedCIDRs: []string{"127.0.0.0/8"}}
	var conns []net.Conn
	for range MaxApplicationTunnels {
		c, err := tunnels.DialApplication(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	if _, err := tunnels.DialApplication(context.Background(), target); err != ErrApplicationCapacity {
		t.Fatalf("global limit ignored: %v", err)
	}
	conns[0].Close()
	c, err := tunnels.DialApplication(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	tunnels.Close()
	tunnels = NewApplicationTunnels(nil, connmgr.New(), func(context.Context, applicationtransport.Target) error { return nil })
	started := make(chan struct{})
	tunnels.dial = applicationproxy.Dialer{Dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	result := make(chan error, 1)
	go func() { _, err := tunnels.DialApplication(context.Background(), target); result <- err }()
	<-started
	tunnels.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("closed registry completed dial")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel pending direct dial")
	}
}

func TestApplicationDirectConfiguredControlListenerNeverDialed(t *testing.T) {
	tunnels := NewApplicationTunnels(nil, connmgr.New(), func(context.Context, applicationtransport.Target) error { return nil })
	defer tunnels.Close()
	tunnels.SetForbiddenEndpoints([]netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:8080")})
	target := applicationtransport.Target{ApplicationID: "app", ConfigVersion: 1, Scheme: "http", Hostname: "127.0.0.1", Port: 8080, AllowedCIDRs: []string{"127.0.0.0/8"}}
	if _, err := tunnels.DialApplication(context.Background(), target); err == nil {
		t.Fatal("configured control listener allowed")
	}
}

func TestApplicationIdleAttachCapacityCannotStarveOtherNodes(t *testing.T) {
	tunnels := NewApplicationTunnels(nil, connmgr.New(), nil)
	defer tunnels.Close()
	for range MaxNodeApplicationTunnels {
		if !tunnels.reserveRPC("node") {
			t.Fatal("node admission refused early")
		}
	}
	if tunnels.reserveRPC("node") {
		t.Fatal("idle node attachments exceeded node quota")
	}
	for _, node := range []string{"second", "third", "fourth"} {
		for range MaxNodeApplicationTunnels {
			if !tunnels.reserveRPC(node) {
				t.Fatal("one node consumed another node's capacity")
			}
		}
	}
	if tunnels.reserveRPC("fifth") {
		t.Fatal("idle RPC global quota exceeded")
	}
	tunnels.releaseRPC("node")
	if !tunnels.reserveRPC("fifth") {
		t.Fatal("released RPC slot unavailable")
	}
	for _, node := range []string{"second", "third", "fourth"} {
		for range MaxNodeApplicationTunnels {
			tunnels.releaseRPC(node)
		}
	}
	for range MaxNodeApplicationTunnels - 1 {
		tunnels.releaseRPC("node")
	}
	tunnels.releaseRPC("fifth")
}

func TestApplicationDirectRouteStreamsAndCancellationClosesSocket(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	peer := make(chan net.Conn, 1)
	go func() {
		c, e := lis.Accept()
		if e == nil {
			peer <- c
		}
	}()
	tunnels := NewApplicationTunnels(nil, connmgr.New(), func(context.Context, applicationtransport.Target) error { return nil })
	defer tunnels.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := applicationtransport.Target{ApplicationID: "app", ConfigVersion: 1, Scheme: "http", Hostname: "127.0.0.1", Port: uint16(lis.Addr().(*net.TCPAddr).Port), AllowedCIDRs: []string{"127.0.0.0/8"}}
	c, err := tunnels.DialApplication(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := <-peer
	defer p.Close()
	cancel()
	p.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := p.Read(make([]byte, 1)); err == nil {
		t.Fatal("cancelled direct socket still open")
	}
	if supported, online := tunnels.ApplicationAvailability(""); !supported || !online {
		t.Fatal("direct route unavailable")
	}
}

func TestApplicationCapabilitiesCannotSurviveControlReplacement(t *testing.T) {
	cm := connmgr.New()
	stream := &mockStream{}
	cm.Register("node", stream)
	tunnels := NewApplicationTunnels(nil, cm, func(context.Context, applicationtransport.Target) error { return nil })
	defer tunnels.Close()
	if err := tunnels.ObserveCapabilities("node", stream, &pb.ApplicationCapabilities{ProtocolVersion: 1, RawTcp: true, BootId: "1234567890123456"}); err != nil {
		t.Fatal(err)
	}
	if supported, online := tunnels.ApplicationAvailability("node"); !supported || !online {
		t.Fatal("current capability ignored")
	}
	cm.Register("node", &mockStream{})
	if supported, _ := tunnels.ApplicationAvailability("node"); supported {
		t.Fatal("old control capability retained")
	}
}
func TestApplicationNodeDoesNotInheritHubLoopbackDenyEndpoints(t *testing.T) {
	_, st := testHandler(t)
	if e := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); e != nil {
		t.Fatal(e)
	}
	cm := connmgr.New()
	control := &applicationControlFixture{messages: make(chan *pb.HubMessage, 2)}
	cm.Register("node", control)
	tunnels := NewApplicationTunnels(st, cm, func(context.Context, applicationtransport.Target) error { return nil })
	defer tunnels.Close()
	tunnels.SetForbiddenEndpoints([]netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:8081"), netip.MustParseAddrPort("[::1]:9090"), netip.MustParseAddrPort("10.10.1.96:8081")})
	tunnels.SetForbiddenAuthorities([]string{"127.0.0.1:8081", "localhost:9090", "hub.example.test:9090"})
	if e := tunnels.ObserveCapabilities("node", control, &pb.ApplicationCapabilities{ProtocolVersion: 1, RawTcp: true, BootId: "1234567890123456"}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := applicationtransport.Target{ApplicationID: "app", ConfigVersion: 1, NodeID: "node", Scheme: "http", Hostname: "127.0.0.1", Port: 8081, AllowedCIDRs: []string{"127.0.0.0/8"}}
	result := make(chan error, 1)
	go func() { _, e := tunnels.DialApplication(ctx, target); result <- e }()
	var open *pb.ApplicationOpen
	select {
	case message := <-control.messages:
		open = message.GetApplicationOpen()
	case <-time.After(time.Second):
		t.Fatal("node open not dispatched")
	}
	if open == nil {
		t.Fatal("missing appopen")
	}
	for _, authority := range open.Target.ForbiddenAuthorities {
		if strings.Contains(authority, "127.0.0.1") || strings.Contains(authority, "localhost") || strings.Contains(authority, "::1") {
			t.Fatal("Hub local identity leaked into node destination policy")
		}
	}
	dial := applicationproxy.Dialer{ForbiddenAuthorities: open.Target.ForbiddenAuthorities, Dial: func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}}
	conn, e := dial.DialTarget(ctx, target)
	if e != nil {
		t.Fatal("node own-loopback backend refused", e)
	}
	conn.Close()
	target.Hostname = "10.10.1.96"
	target.AllowedCIDRs = []string{"10.10.1.0/24"}
	if _, e = dial.DialTarget(ctx, target); e == nil {
		t.Fatal("real Hub published endpoint allowed")
	}
	cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("pending node admission not canceled")
	}
}
