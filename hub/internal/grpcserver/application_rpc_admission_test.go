package grpcserver

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestApplicationRPCAdmissionRejectsBeforeReadingOrReleasesCapacity(t *testing.T) {
	for _, kind := range []string{"disabled", "capacity", "eof", "nil-first", "data-first", "malformed-attach"} {
		t.Run(kind, func(t *testing.T) {
			h, tunnels, _, _ := applicationAdmissionFixture(t)
			cert := &x509.Certificate{Raw: []byte("active-certificate"), Subject: pkix.Name{CommonName: "node"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			ctx := applicationPeer(cert, true)
			h.connMgr.Register("node", &mockStream{ctx: ctx})
			stream := &applicationScriptedStream{ctx: ctx, messages: []*pb.ApplicationAgentMessage{nil}}
			want := codes.InvalidArgument
			switch kind {
			case "disabled":
				h.applications = nil
				want = codes.Unavailable
			case "capacity":
				for range MaxNodeApplicationTunnels {
					if !tunnels.reserveRPC("node") {
						t.Fatal("capacity setup failed")
					}
				}
				want = codes.ResourceExhausted
			case "eof":
				stream.messages = nil
				want = codes.Unknown
			case "data-first":
				stream.messages[0] = &pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Data{Data: &pb.ApplicationData{Data: []byte("unadmitted")}}}
			case "malformed-attach":
				stream.messages[0] = &pb.ApplicationAgentMessage{Payload: &pb.ApplicationAgentMessage_Attach{Attach: &pb.ApplicationAttach{}}}
				want = codes.PermissionDenied
			}
			err := h.ApplicationProxy(stream)
			if status.Code(err) != want {
				t.Fatalf("unexpected admission result: %v", err)
			}
			if kind == "eof" && err != io.EOF {
				t.Fatalf("receive failure changed: %v", err)
			}
			if kind == "disabled" || kind == "capacity" {
				if len(stream.messages) != 1 {
					t.Fatal("rejected admission consumed a frame")
				}
			}
			if kind == "capacity" {
				for range MaxNodeApplicationTunnels {
					tunnels.releaseRPC("node")
				}
			}
			if len(tunnels.rpcNodes) != 0 || len(tunnels.rpcSlots) != 0 {
				t.Fatal("rejected RPC leaked capacity")
			}
		})
	}
}

func TestApplicationVerifiedCertificateCannotUseUnidentifiedControl(t *testing.T) {
	for _, ctx := range []context.Context{context.Background(), peer.NewContext(context.Background(), &peer.Peer{})} {
		h, _, _, _ := applicationAdmissionFixture(t)
		h.connMgr.Register("node", &mockStream{ctx: ctx})
		cert := &x509.Certificate{Raw: []byte("active-certificate"), Subject: pkix.Name{CommonName: "node"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		if _, _, err := h.applicationNode(applicationPeer(cert, true)); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("unidentified control accepted: %v", err)
		}
	}
}
