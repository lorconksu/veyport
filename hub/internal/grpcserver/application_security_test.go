package grpcserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/applicationtransport"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

func applicationPeer(cert *x509.Certificate, verified bool) context.Context {
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if verified {
		state.VerifiedChains = [][]*x509.Certificate{{cert}}
	}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
}
func TestApplicationCertificateMustMatchExactLiveControlIdentity(t *testing.T) {
	h, st := testHandler(t)
	if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{Raw: []byte("active-certificate"), Subject: pkix.Name{CommonName: "node"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	h.connMgr.Register("node", &mockStream{ctx: applicationPeer(cert, true)})
	if _, _, err := h.applicationNode(applicationPeer(cert, true)); err != nil {
		t.Fatal(err)
	}
	other := *cert
	other.Raw = []byte("other-same-CN-certificate")
	for _, ctx := range []context.Context{context.Background(), applicationPeer(cert, false), applicationPeer(&other, true)} {
		if _, _, err := h.applicationNode(ctx); err == nil {
			t.Fatal("unverified/missing/replaced certificate accepted")
		}
	}
	h.connMgr.GetConn("node").Close()
	if _, _, err := h.applicationNode(applicationPeer(cert, true)); err == nil {
		t.Fatal("closed control identity accepted")
	}
}

func TestApplicationAttachRejectsReplayMutationAndReplacement(t *testing.T) {
	for _, kind := range []string{"replay", "node", "binding", "ticket", "expired", "replacement"} {
		t.Run(kind, func(t *testing.T) {
			cm := connmgrForExecutionTest()
			control := cm.GetConn("node")
			tunnels := NewApplicationTunnels(nil, cm, func(context.Context, applicationtransport.Target) error { return nil })
			defer tunnels.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ticket := make([]byte, 32)
			binding := &pb.ApplicationBinding{ConnectionId: "connection", ApplicationId: "app", ConfigVersion: 1, NodeId: "node", ControlGeneration: control.GenerationID, BootId: "1234567890123456", ExpiresUnixMilli: time.Now().Add(time.Second).UnixMilli()}
			s := &applicationTunnel{ctx: ctx, cancel: cancel, control: control, binding: binding, target: applicationtransport.Target{NodeID: "node"}, ticket: sha256.Sum256(ticket), ready: make(chan error, 1)}
			tunnels.nodes[binding.ConnectionId] = s
			tunnels.nodeCounts["node"] = 1
			attach := &pb.ApplicationAttach{Binding: proto.Clone(binding).(*pb.ApplicationBinding), Ticket: append([]byte(nil), ticket...)}
			node := "node"
			switch kind {
			case "replay":
				if _, err := tunnels.attach(node, attach); err != nil {
					t.Fatal(err)
				}
			case "node":
				node = "other"
			case "binding":
				attach.Binding.ConfigVersion++
			case "ticket":
				attach.Ticket[0] = 1
			case "expired":
				binding.ExpiresUnixMilli = time.Now().Add(-time.Second).UnixMilli()
				attach.Binding.ExpiresUnixMilli = binding.ExpiresUnixMilli
			case "replacement":
				cm.Register("node", &mockStream{})
			}
			if _, err := tunnels.attach(node, attach); err == nil {
				t.Fatalf("%s attack accepted", kind)
			}
		})
	}
}
