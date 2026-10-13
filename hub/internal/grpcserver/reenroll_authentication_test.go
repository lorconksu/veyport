package grpcserver

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// This stream runs only in memory. Cancellation releases any pending I/O.
type reEnrollTestStream struct {
	mockStream
	incoming chan *pb.AgentMessage
	outgoing chan *pb.HubMessage
}

func newReEnrollTestStream(t *testing.T) *reEnrollTestStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return &reEnrollTestStream{mockStream: mockStream{ctx: ctx}, incoming: make(chan *pb.AgentMessage, 2), outgoing: make(chan *pb.HubMessage, 3)}
}
func (s *reEnrollTestStream) Recv() (*pb.AgentMessage, error) {
	select {
	case msg, ok := <-s.incoming:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-s.Context().Done():
		return nil, s.Context().Err()
	}
}
func (s *reEnrollTestStream) Send(msg *pb.HubMessage) error {
	select {
	case s.outgoing <- msg:
		return nil
	case <-s.Context().Done():
		return s.Context().Err()
	}
}
func receiveReEnrollTestMessage(t *testing.T, stream *reEnrollTestStream) *pb.HubMessage {
	t.Helper()
	select {
	case msg := <-stream.outgoing:
		return msg
	case <-stream.Context().Done():
		t.Fatal("re-enrollment response deadline")
		return nil
	}
}
func awaitReEnrollTestResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("re-enrollment did not finish promptly")
		return nil
	}
}
func seedReEnrollIdentity(t *testing.T, h *Handler, serverID string) ed25519.PrivateKey {
	t.Helper()
	seedServer(t, h, serverID)
	h.storageKey = "unit-test-storage-key"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := h.sealKEK(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetNodeCrypto(serverID, base64.StdEncoding.EncodeToString(pub), kek, "fp"); err != nil {
		t.Fatal(err)
	}
	transport, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetNodeTransportPub(serverID, base64.StdEncoding.EncodeToString(transport.PublicKey().Bytes())); err != nil {
		t.Fatal(err)
	}
	return priv
}
func startReEnrollConnect(t *testing.T, h *Handler, serverID string) (*reEnrollTestStream, *reEnrollSession, <-chan error) {
	t.Helper()
	stream := newReEnrollTestStream(t)
	stream.incoming <- &pb.AgentMessage{Payload: &pb.AgentMessage_ReenrollRequest{ReenrollRequest: &pb.ReEnrollRequest{ServerId: serverID, Csr: testRegistrationCSR(t), Fingerprint: "fp"}}}
	result := make(chan error, 1)
	go func() { result <- h.Connect(stream) }()
	sess, err := waitForReEnrollSessionForTest(stream.Context(), h, serverID)
	if err != nil {
		t.Fatal(err)
	}
	return stream, sess, result
}
func approvedTestSession(t *testing.T, h *Handler, serverID string, stream pb.AgentService_ConnectServer) *reEnrollSession {
	t.Helper()
	sess := registerReEnrollForTest(t, h, serverID, testRegistrationCSR(t), "fp")
	h.reEnrollMu.Lock()
	sess.stream, sess.state, sess.challenge, sess.decidedBy = stream, reEnrollAwaitingProof, make([]byte, 32), "admin"
	sess.proofUntil = time.Now().Add(time.Second)
	h.reEnrollMu.Unlock()
	return sess
}
func requireNoReEnrollCertificate(t *testing.T, stream *mockStream) {
	t.Helper()
	for _, msg := range stream.sent {
		if resp := msg.GetCertRenewResponse(); resp != nil && len(resp.ClientCert) != 0 {
			t.Fatal("unexpected certificate on refused request")
		}
	}
}

func TestReEnrollBootstrapValidProofRequiresVerifiedReconnect(t *testing.T) {
	h, _ := testHandler(t)
	priv := seedReEnrollIdentity(t, h, "bootstrap-proof")
	previousStream := streamWithPeerCert("bootstrap-proof")
	previous := h.connMgr.Register("bootstrap-proof", previousStream)
	stream, sess, connected := startReEnrollConnect(t, h, "bootstrap-proof")
	released := make(chan error, 1)
	go func() { released <- h.ReleaseKEK(sess.serverID, sess.requestID, "admin") }()
	approved := receiveReEnrollTestMessage(t, stream).GetReenrollApproved()
	if approved == nil {
		t.Fatal("expected approval")
	}
	if h.connMgr.GetConn(sess.serverID) != previous {
		t.Fatal("bootstrap approval changed normal connection")
	}
	stream.incoming <- &pb.AgentMessage{Payload: &pb.AgentMessage_ReenrollProof{ReenrollProof: &pb.ReEnrollProof{Signature: ed25519.Sign(priv, approved.Challenge)}}}
	response := receiveReEnrollTestMessage(t, stream).GetCertRenewResponse()
	if response == nil || len(response.ClientCert) == 0 {
		t.Fatal("valid approved proof did not receive certificate")
	}
	if err := awaitReEnrollTestResult(t, connected); err != nil {
		t.Fatal(err)
	}
	if err := awaitReEnrollTestResult(t, released); err != nil {
		t.Fatal(err)
	}
	if h.connMgr.GetConn(sess.serverID) != previous {
		t.Fatal("bootstrap completion changed normal connection")
	}
	srv, err := h.store.GetServerByID(sess.serverID)
	if err != nil || srv.Status != "offline" {
		t.Fatalf("bootstrap changed server status: %+v, %v", srv, err)
	}
	cert, err := x509.ParseCertificate(response.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(h.caCert)
	chains, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	reconnect := newReEnrollTestStream(t)
	reconnect.ctx = peer.NewContext(reconnect.Context(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}, AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: chains}}})
	reconnect.incoming <- &pb.AgentMessage{Payload: &pb.AgentMessage_Heartbeat{Heartbeat: &pb.Heartbeat{ServerId: sess.serverID}}}
	reconnected := make(chan error, 1)
	go func() { reconnected <- h.Connect(reconnect) }()
	if receiveReEnrollTestMessage(t, reconnect).GetHeartbeatAck() == nil {
		t.Fatal("verified reconnect was rejected")
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for h.connMgr.GetConn(sess.serverID) == previous {
		select {
		case <-deadline.C:
			t.Fatal("verified reconnect was not registered")
		case <-time.After(time.Millisecond):
		}
	}
	if current := h.connMgr.GetConn(sess.serverID); current == nil || current.Stream != reconnect {
		t.Fatal("reconnect did not become current")
	}
	close(reconnect.incoming)
	if err := awaitReEnrollTestResult(t, reconnected); err != nil {
		t.Fatal(err)
	}
}

func TestReEnrollBootstrapRefusesOtherMessagesAndDuplicateDecisions(t *testing.T) {
	h, _ := testHandler(t)
	seedReEnrollIdentity(t, h, "proof-only")
	stream, sess, connected := startReEnrollConnect(t, h, "proof-only")
	released := make(chan error, 1)
	go func() { released <- h.ReleaseKEK(sess.serverID, sess.requestID, "admin") }()
	if receiveReEnrollTestMessage(t, stream).GetReenrollApproved() == nil {
		t.Fatal("expected approval")
	}
	if err := h.ReleaseKEK(sess.serverID, sess.requestID, "another-admin"); err == nil {
		t.Fatal("duplicate approval accepted")
	}
	if err := h.DenyReEnroll(sess.serverID, sess.requestID, "another-admin"); err == nil {
		t.Fatal("conflicting decision accepted")
	}
	stream.incoming <- &pb.AgentMessage{Payload: &pb.AgentMessage_Heartbeat{Heartbeat: &pb.Heartbeat{ServerId: sess.serverID}}}
	if receiveReEnrollTestMessage(t, stream).GetReenrollDenied() == nil {
		t.Fatal("non-proof bootstrap message was not denied")
	}
	if err := awaitReEnrollTestResult(t, connected); err != nil {
		t.Fatal(err)
	}
	if err := awaitReEnrollTestResult(t, released); err == nil {
		t.Fatal("approval succeeded without proof")
	}
	if h.connMgr.GetConn(sess.serverID) != nil {
		t.Fatal("proof-only stream entered normal registry")
	}
	row, err := h.store.GetReEnrollRequest(sess.requestID)
	if err != nil || row.Status != "denied" {
		t.Fatalf("decision: %+v %v", row, err)
	}
}

func TestReEnrollReplacementRefusesStaleApprovalDenialAndProof(t *testing.T) {
	h, _ := testHandler(t)
	seedReEnrollIdentity(t, h, "replacement")
	oldStream, old, oldDone := startReEnrollConnect(t, h, "replacement")
	newStream := newReEnrollTestStream(t)
	newStream.incoming <- &pb.AgentMessage{Payload: &pb.AgentMessage_ReenrollRequest{ReenrollRequest: &pb.ReEnrollRequest{ServerId: old.serverID, Csr: testRegistrationCSR(t), Fingerprint: "new-fp"}}}
	newDone := make(chan error, 1)
	go func() { newDone <- h.Connect(newStream) }()
	var replacement *reEnrollSession
	for replacement == nil || replacement == old {
		select {
		case <-newStream.Context().Done():
			t.Fatal("replacement registration deadline")
		default:
		}
		replacement, _ = h.lookupReEnroll(old.serverID)
		if replacement == nil || replacement == old {
			time.Sleep(time.Millisecond)
		}
	}
	if err := h.ReleaseKEK(old.serverID, old.requestID, "admin"); !errors.Is(err, ErrNoPendingReEnroll) {
		t.Fatalf("stale approval: %v", err)
	}
	if err := h.DenyReEnroll(old.serverID, old.requestID, "admin"); !errors.Is(err, ErrNoPendingReEnroll) {
		t.Fatalf("stale denial: %v", err)
	}
	if err := h.handleReEnrollProof(oldStream, old.serverID, &pb.ReEnrollProof{Signature: []byte("invalid")}); err != nil {
		t.Fatal(err)
	}
	if err := awaitReEnrollTestResult(t, oldDone); err != nil {
		t.Fatal(err)
	}
	if row, err := h.store.GetReEnrollRequest(old.requestID); err != nil || row.Status != "expired" {
		t.Fatalf("old request: %+v %v", row, err)
	}
	if row, err := h.store.GetReEnrollRequest(replacement.requestID); err != nil || row.Status != "pending" {
		t.Fatalf("replacement request: %+v %v", row, err)
	}
	if err := h.DenyReEnroll(replacement.serverID, replacement.requestID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := awaitReEnrollTestResult(t, newDone); err != nil {
		t.Fatal(err)
	}
	if msg := receiveReEnrollTestMessage(t, newStream); msg.GetReenrollDenied() == nil {
		t.Fatal("denial did not wake replacement stream")
	}
}

func TestReEnrollProofRequiresExactApprovedStreamAndLiveChallenge(t *testing.T) {
	for _, reason := range []string{"different-stream", "unapproved", "expired", "empty-challenge", "duplicate"} {
		t.Run(reason, func(t *testing.T) {
			h, _ := testHandler(t)
			seedReEnrollIdentity(t, h, "binding")
			stream := &mockStream{}
			sess := approvedTestSession(t, h, "binding", stream)
			switch reason {
			case "different-stream":
				stream = &mockStream{}
			case "unapproved":
				sess.state = reEnrollPending
			case "expired":
				sess.proofUntil = time.Now().Add(-time.Second)
			case "empty-challenge":
				sess.challenge = nil
			case "duplicate":
				h.clearReEnroll(sess.serverID, sess)
			}
			if err := h.handleReEnrollProof(stream, sess.serverID, &pb.ReEnrollProof{Signature: []byte("invalid")}); err != nil {
				t.Fatal(err)
			}
			requireNoReEnrollCertificate(t, stream)
			if len(stream.sent) == 0 || stream.sent[0].GetReenrollDenied() == nil {
				t.Fatal("invalid proof binding was not denied")
			}
			if reason != "duplicate" {
				if current, _ := h.lookupReEnroll(sess.serverID); current != sess {
					t.Fatal("unrelated proof changed session")
				}
			}
		})
	}
}

func TestReEnrollDecisionPersistenceFailuresFailClosed(t *testing.T) {
	for _, decision := range []string{"approve", "deny", "proof"} {
		t.Run(decision, func(t *testing.T) {
			h, st := testHandler(t)
			priv := seedReEnrollIdentity(t, h, "persistence")
			stream := &mockStream{}
			sess := approvedTestSession(t, h, "persistence", stream)
			if decision != "proof" {
				sess.state = reEnrollPending
			}
			if _, err := st.DB().Exec(`CREATE TRIGGER refuse_reenroll_decision BEFORE UPDATE ON reenroll_requests BEGIN SELECT RAISE(FAIL,'decision unavailable'); END`); err != nil {
				t.Fatal(err)
			}
			switch decision {
			case "approve":
				if err := h.ReleaseKEK(sess.serverID, sess.requestID, "admin"); err == nil {
					t.Fatal("approval accepted failed durable reservation")
				}
			case "deny":
				if err := h.DenyReEnroll(sess.serverID, sess.requestID, "admin"); err == nil {
					t.Fatal("denial accepted failed durable decision")
				}
			case "proof":
				if err := h.handleReEnrollProof(stream, sess.serverID, &pb.ReEnrollProof{Signature: ed25519.Sign(priv, sess.challenge)}); err != nil {
					t.Fatal(err)
				}
			}
			requireNoReEnrollCertificate(t, stream)
			select {
			case <-sess.approve:
				t.Fatal("failed durable decision released approval")
			default:
			}
		})
	}
}

func TestCertificateRenewalRefusesUnauthenticatedOrStaleStreams(t *testing.T) {
	for _, reason := range []string{"missing-cert", "unverified-cert", "wrong-node", "expired-cert", "pending-enrollment", "stale-stream"} {
		t.Run(reason, func(t *testing.T) {
			h, st := testHandler(t)
			if err := st.CreateServer(&model.Server{ID: "renew-auth", Name: "renew-auth", Status: "online", Labels: "{}"}); err != nil {
				t.Fatal(err)
			}
			stream := streamWithPeerCert("renew-auth")
			switch reason {
			case "missing-cert":
				stream = &mockStream{}
			case "unverified-cert":
				p, _ := peer.FromContext(stream.Context())
				info := p.AuthInfo.(credentials.TLSInfo)
				info.State.VerifiedChains = nil
				p.AuthInfo = info
			case "wrong-node":
				stream = streamWithPeerCert("different-node")
			case "expired-cert":
				p, _ := peer.FromContext(stream.Context())
				info := p.AuthInfo.(credentials.TLSInfo)
				info.State.PeerCertificates[0].NotAfter = time.Now().Add(-time.Second)
				p.AuthInfo = info
			case "pending-enrollment":
				if _, err := st.DB().Exec(`UPDATE servers SET registration_token='pending' WHERE id='renew-auth'`); err != nil {
					t.Fatal(err)
				}
			}
			h.connMgr.Register("renew-auth", stream)
			if reason == "stale-stream" {
				h.connMgr.Register("renew-auth", streamWithPeerCert("renew-auth"))
			}
			h.handleCertRenewal("renew-auth", stream, &pb.CertRenewRequest{Csr: []byte("unused-on-denied-request")})
			requireNoReEnrollCertificate(t, stream)
			if reason != "stale-stream" && (len(stream.sent) == 0 || stream.sent[0].GetCertRenewResponse().Error == "") {
				t.Fatal("renewal authentication failure was not reported")
			}
		})
	}
}

func TestReEnrollProofReceiveEndsOnTimeoutDisconnectAndSupersession(t *testing.T) {
	for _, reason := range []string{"timeout", "disconnect", "supersession", "eof", "no-session"} {
		t.Run(reason, func(t *testing.T) {
			h, _ := testHandler(t)
			stream := newReEnrollTestStream(t)
			sess := approvedTestSession(t, h, "receive-end", stream)
			var replacement *reEnrollSession
			switch reason {
			case "timeout":
				sess.proofUntil = time.Now().Add(20 * time.Millisecond)
			case "disconnect":
				ctx, cancel := context.WithCancel(context.Background())
				stream.ctx = ctx
				cancel()
			case "eof":
				close(stream.incoming)
			case "no-session":
				h.clearReEnroll(sess.serverID, sess)
			}
			result := make(chan error, 1)
			go func() { result <- h.receiveReEnrollProof(stream, sess.serverID) }()
			if reason == "supersession" {
				replacement = registerReEnrollForTest(t, h, sess.serverID, nil, "new")
			}
			err := awaitReEnrollTestResult(t, result)
			if reason == "eof" && !errors.Is(err, io.EOF) {
				t.Fatalf("expected EOF: %v", err)
			}
			if reason == "disconnect" && !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation: %v", err)
			}
			if replacement != nil {
				if current, _ := h.lookupReEnroll(sess.serverID); current != replacement {
					t.Fatal("late cleanup removed replacement")
				}
			}
			if reason == "timeout" || reason == "eof" || reason == "disconnect" {
				if row, err := h.store.GetReEnrollRequest(sess.requestID); err != nil || row.Status != "expired" {
					t.Fatalf("ended request: %+v %v", row, err)
				}
			}
		})
	}
}

type reEnrollBlockedSendStream struct {
	mockStream
	entered chan struct{}
	release chan struct{}
}

func (s *reEnrollBlockedSendStream) Send(*pb.HubMessage) error {
	close(s.entered)
	<-s.release
	return nil
}

func TestReEnrollTransportSendIsBounded(t *testing.T) {
	for _, reason := range []string{"timeout", "disconnect", "supersession", "already-expired", "already-disconnected", "already-ended"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &reEnrollBlockedSendStream{mockStream: mockStream{ctx: ctx}, entered: make(chan struct{}), release: make(chan struct{})}
			defer close(stream.release)
			done := make(chan struct{})
			until := time.Now().Add(time.Second)
			switch reason {
			case "timeout":
				until = time.Now().Add(20 * time.Millisecond)
			case "already-expired":
				until = time.Now().Add(-time.Second)
			case "already-disconnected":
				cancel()
			case "already-ended":
				close(done)
			}
			result := make(chan error, 1)
			go func() { result <- sendReEnrollMessage(stream, done, until, &pb.HubMessage{}) }()
			if reason == "disconnect" || reason == "supersession" {
				select {
				case <-stream.entered:
				case <-time.After(time.Second):
					t.Fatal("send did not start")
				}
				if reason == "disconnect" {
					cancel()
				} else {
					close(done)
				}
			}
			if err := awaitReEnrollTestResult(t, result); err == nil {
				t.Fatal("bounded send unexpectedly succeeded")
			}
		})
	}
}

func TestReEnrollCompletionRemainsNonblockingAndPreservesTerminalDecision(t *testing.T) {
	h, st := testHandler(t)
	sess := registerReEnrollForTest(t, h, "completion", nil, "fp")
	sess.result <- errors.New("abandoned-result")
	h.clearReEnroll(sess.serverID, sess)
	h.clearReEnroll(sess.serverID, sess)
	select {
	case <-sess.done:
	default:
		t.Fatal("completion did not signal session end")
	}
	if err := h.endReEnroll(sess, errors.New("late timeout"), "expired"); !errors.Is(err, ErrNoPendingReEnroll) {
		t.Fatalf("late completion replaced outcome: %v", err)
	}
	sess = registerReEnrollForTest(t, h, "failed-expiry", nil, "fp")
	if _, err := st.DB().Exec(`CREATE TRIGGER refuse_expiry BEFORE UPDATE ON reenroll_requests BEGIN SELECT RAISE(FAIL,'expiry unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	h.endReEnroll(sess, errors.New("timeout"), "expired")
	if _, ok := h.lookupReEnroll(sess.serverID); ok {
		t.Fatal("failed expiry left live session")
	}
}

func TestReEnrollRequestPersistenceFailureKeepsExistingSession(t *testing.T) {
	h, st := testHandler(t)
	seedReEnrollIdentity(t, h, "request-persistence")
	sess := registerReEnrollForTest(t, h, "request-persistence", nil, "fp")
	if _, err := st.DB().Exec(`CREATE TRIGGER refuse_request_insert BEFORE INSERT ON reenroll_requests BEGIN SELECT RAISE(FAIL,'insert unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	stream := &mockStream{}
	if approved, err := h.handleReEnrollRequest(stream, &pb.ReEnrollRequest{ServerId: sess.serverID}); err != nil || approved {
		t.Fatalf("failed request accepted: %v %v", approved, err)
	}
	if current, _ := h.lookupReEnroll(sess.serverID); current != sess {
		t.Fatal("failed request replaced live session")
	}
	if row, err := st.GetReEnrollRequest(sess.requestID); err != nil || row.Status != "pending" {
		t.Fatalf("failed insert expired old request: %+v %v", row, err)
	}
	if approved, err := h.handleReEnrollRequest(stream, nil); err != nil || approved {
		t.Fatalf("nil request accepted: %v %v", approved, err)
	}
}

func TestReEnrollReleaseCanceledStreamFailsPromptly(t *testing.T) {
	h, _ := testHandler(t)
	seedReEnrollIdentity(t, h, "canceled-release")
	sess := registerReEnrollForTest(t, h, "canceled-release", nil, "fp")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sess.stream = &mockStream{ctx: ctx}
	if err := h.ReleaseKEK(sess.serverID, sess.requestID, "admin"); !errors.Is(err, ErrNoPendingReEnroll) {
		t.Fatalf("canceled release: %v", err)
	}
	if _, ok := h.lookupReEnroll(sess.serverID); ok {
		t.Fatal("canceled release left a live session")
	}
	select {
	case <-sess.approve:
		t.Fatal("canceled stream received approval")
	default:
	}
}
