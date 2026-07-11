package integration

// End-to-end integration test for the Human-Approved Re-Enrollment loop (P2.T8).
//
// Strategy: simulate the agent over a real gRPC Connect stream.  The test
// controls the node keypair and KEK directly so it can produce a valid proof
// without running a real agent subprocess or forcing real cert expiry.
//
// Happy path (TestReEnrollHappyPath):
//  1. Seed node crypto for a server directly via the store.
//  2. Open a bootstrap (CA-pinned, no client cert) gRPC stream; send ReEnrollRequest.
//  3. Discover the pending request via GET /api/servers/reenroll/pending.
//  4. In a goroutine, approve via POST /api/servers/{id}/reenroll/approve (valid TOTP).
//  5. Read ReEnrollApproved{Kek, Challenge} from the stream.
//  6. Sign the challenge with the node private key; send ReEnrollProof.
//  7. Assert: stream yields CertRenewResponse; parsed cert CN == serverID;
//     HTTP approve returned 200; DB status is "approved".
//
// Deny path (TestReEnrollDenyPath):
//  1–3. Same as above.
//  4. Deny via POST /api/servers/{id}/reenroll/deny.
//  5. Assert: DB status is "denied"; no cert arrives on the stream.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

// enrolledServer holds the node crypto state for a seeded server.
type enrolledServer struct {
	serverID    string
	priv        ed25519.PrivateKey
	fingerprint string
}

// ─────────────────────────────────────────────────────────────────────────────
// Seeding helpers
// ─────────────────────────────────────────────────────────────────────────────

// sealKEKForHub mirrors grpcserver.sealKEK:
//
//	hex( auth.Encrypt(kek, auth.DeriveKey(storageKey)) )
func sealKEKForHub(kek []byte, storageKey string) (string, error) {
	enc, err := auth.Encrypt(kek, auth.DeriveKey(storageKey))
	if err != nil {
		return "", fmt.Errorf("encrypt KEK: %w", err)
	}
	return hex.EncodeToString(enc), nil
}

// seedEnrolledServer creates a server record and populates its node crypto
// directly via the store, simulating a prior normal enrollment.
func seedEnrolledServer(t *testing.T, h *TestHarness, adminToken, name string) *enrolledServer {
	t.Helper()

	// Use the HTTP API to create the server record (gives it a proper UUID).
	serverID, _ := h.CreateServer(t, adminToken, name)

	// Generate a node Ed25519 keypair (mirrors agent/internal/nodekey.Generate).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("seedEnrolledServer: generate ed25519 key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	// Generate a random 32-byte KEK.
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("seedEnrolledServer: generate KEK: %v", err)
	}

	// Seal the KEK at rest using the hub storage key (mirrors grpcserver.sealKEK).
	kekEncHex, err := sealKEKForHub(kek, h.StorageKey)
	if err != nil {
		t.Fatalf("seedEnrolledServer: seal KEK for hub: %v", err)
	}

	const fp = "test-fingerprint-abc123"
	if err := h.Store.SetNodeCrypto(serverID, pubB64, kekEncHex, fp); err != nil {
		t.Fatalf("seedEnrolledServer: SetNodeCrypto: %v", err)
	}

	return &enrolledServer{
		serverID:    serverID,
		priv:        priv,
		fingerprint: fp,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// gRPC bootstrap dial
// ─────────────────────────────────────────────────────────────────────────────

// buildBootstrapTLS returns a TLS config that pins the hub's CA by SHA-256
// without presenting a client certificate — the same trust model the real
// agent uses during re-enrollment.
//
// InsecureSkipVerify is intentionally set to true: hostname verification is
// disabled because the ephemeral test CA cert uses 127.0.0.1 as a SAN.
// Authenticity is enforced via VerifyPeerCertificate which checks the
// SHA-256 pin of every cert in the chain, providing equivalent security for
// the test environment.
func buildBootstrapTLS(hubCAPin string) (*tls.Config, error) {
	expectedPin, err := hex.DecodeString(hubCAPin)
	if err != nil {
		return nil, fmt.Errorf("decode hub CA pin: %w", err)
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // hostname check replaced by CA-pin in VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("hub presented empty TLS chain")
			}
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					continue
				}
				pin := sha256.Sum256(cert.Raw)
				if bytes.Equal(pin[:], expectedPin) {
					return nil
				}
			}
			return fmt.Errorf("hub TLS chain did not contain the pinned CA")
		},
	}, nil
}

// openReEnrollStream dials the hub gRPC server with bootstrap (CA-pinned) TLS
// and returns an open Connect stream and the underlying connection.
// Callers must defer conn.Close().
func openReEnrollStream(t *testing.T, h *TestHarness) (pb.AgentService_ConnectClient, *grpc.ClientConn) {
	t.Helper()
	tlsCfg, err := buildBootstrapTLS(h.HubCAPin)
	if err != nil {
		t.Fatalf("build bootstrap TLS: %v", err)
	}
	conn, err := grpc.NewClient(h.GRPCAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		t.Fatalf("dial hub gRPC: %v", err)
	}
	stream, err := pb.NewAgentServiceClient(conn).Connect(context.Background())
	if err != nil {
		conn.Close()
		t.Fatalf("open gRPC Connect stream: %v", err)
	}
	return stream, conn
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP helpers
// ─────────────────────────────────────────────────────────────────────────────

// listPendingReEnroll calls GET /api/servers/reenroll/pending and decodes the
// JSON response.
func listPendingReEnroll(t *testing.T, h *TestHarness, adminToken string) []model.ReEnrollRequest {
	t.Helper()
	resp := h.HTTPGet(t, "/api/servers/reenroll/pending", adminToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("list pending re-enroll: status=%d body=%s", resp.StatusCode, body)
	}
	var reqs []model.ReEnrollRequest
	if err := json.NewDecoder(resp.Body).Decode(&reqs); err != nil {
		t.Fatalf("decode pending re-enroll list: %v", err)
	}
	return reqs
}

// waitForPendingReEnroll polls until a pending re-enroll appears for serverID.
func waitForPendingReEnroll(t *testing.T, h *TestHarness, serverID, adminToken string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, r := range listPendingReEnroll(t, h, adminToken) {
			if r.ServerID == serverID {
				return r.ID
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no pending re-enroll appeared for server %s within %v", serverID, timeout)
	return ""
}

// approveReEnroll fires POST /api/servers/{id}/reenroll/approve in a goroutine
// and returns a channel that receives the HTTP status code when the call
// completes.  The call blocks inside ReleaseKEK until the agent proof arrives.
//
// The TOTP replay cache is cleared before generating the code: the enable step
// (in SetupAdminWithTOTP) consumes the code for the current 30s window, so
// without clearing the cache the approve call would fail with "invalid TOTP code"
// when called within the same window.
func approveReEnroll(t *testing.T, h *TestHarness, adminToken, totpSecret, serverID, requestID string) <-chan int {
	t.Helper()
	// Clear the replay cache so the approve code is accepted regardless of how
	// recently the enable code was used.
	h.HTTPServer.ClearTOTPCache()

	ch := make(chan int, 1)
	go func() {
		code, err := auth.GenerateValidCode(totpSecret)
		if err != nil {
			t.Errorf("approveReEnroll: GenerateValidCode: %v", err)
			ch <- 0
			return
		}
		path := fmt.Sprintf("/api/servers/%s/reenroll/approve", serverID)
		resp := h.HTTPPost(t, path, map[string]string{
			"request_id": requestID,
			"totp_code":  code,
		}, adminToken)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Logf("approve response: status=%d body=%s", resp.StatusCode, b)
		}
		ch <- resp.StatusCode
	}()
	return ch
}

// denyReEnroll calls POST /api/servers/{id}/reenroll/deny synchronously.
func denyReEnroll(t *testing.T, h *TestHarness, adminToken, serverID, requestID string) {
	t.Helper()
	path := fmt.Sprintf("/api/servers/%s/reenroll/deny", serverID)
	resp := h.HTTPPost(t, path, map[string]string{"request_id": requestID}, adminToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("deny re-enroll: status=%d body=%s", resp.StatusCode, b)
	}
}

// assertReEnrollStatus checks the DB row for the given requestID.
func assertReEnrollStatus(t *testing.T, h *TestHarness, requestID, want string) {
	t.Helper()
	r, err := h.Store.GetReEnrollRequest(requestID)
	if err != nil {
		t.Fatalf("GetReEnrollRequest %s: %v", requestID, err)
	}
	if r.Status != want {
		t.Fatalf("re-enroll status: got %q, want %q", r.Status, want)
	}
}

// generateCSR creates a fresh ECDSA P-256 CSR with the given serverID as CN.
// Mirrors agent/internal/certs.Store.GenerateCSR without importing that package
// (which is internal to the agent module).
func generateCSR(t *testing.T, serverID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateCSR: generate ECDSA key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: serverID},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("generateCSR: create CSR: %v", err)
	}
	return csrDER
}

// recvHubMessage receives one message from the stream in a goroutine.
// Returns buffered channels for the message and any error.
func recvHubMessage(stream pb.AgentService_ConnectClient) (<-chan *pb.HubMessage, <-chan error) {
	msgCh := make(chan *pb.HubMessage, 1)
	errCh := make(chan error, 1)
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			errCh <- err
		} else {
			msgCh <- msg
		}
	}()
	return msgCh, errCh
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

// TestReEnrollHappyPath drives the complete approve path end-to-end.
func TestReEnrollHappyPath(t *testing.T) {
	h := StartHarness(t)
	adminToken, totpSecret := h.SetupAdminWithTOTP(t)

	srv := seedEnrolledServer(t, h, adminToken, "reenroll-happy-server")
	t.Logf("seeded server id=%s", srv.serverID)

	csrDER := generateCSR(t, srv.serverID)

	stream, conn := openReEnrollStream(t, h)
	defer conn.Close()
	defer stream.CloseSend()

	// Send ReEnrollRequest.
	if err := stream.Send(&pb.AgentMessage{
		Payload: &pb.AgentMessage_ReenrollRequest{
			ReenrollRequest: &pb.ReEnrollRequest{
				ServerId:    srv.serverID,
				Csr:         csrDER,
				Fingerprint: srv.fingerprint,
			},
		},
	}); err != nil {
		t.Fatalf("send ReEnrollRequest: %v", err)
	}
	t.Log("ReEnrollRequest sent")

	// Wait for the pending DB row (created synchronously by the gRPC handler
	// before it blocks on the approve channel).
	requestID := waitForPendingReEnroll(t, h, srv.serverID, adminToken, 5*time.Second)
	t.Logf("pending request id=%s", requestID)

	// Start approve in a goroutine — blocks inside ReleaseKEK until the proof
	// is received by the stream goroutine.
	approveCh := approveReEnroll(t, h, adminToken, totpSecret, srv.serverID, requestID)

	// Read ReEnrollApproved from the stream.
	msgCh, errCh := recvHubMessage(stream)
	var approved *pb.ReEnrollApproved
	select {
	case msg := <-msgCh:
		p, ok := msg.Payload.(*pb.HubMessage_ReenrollApproved)
		if !ok {
			t.Fatalf("expected ReEnrollApproved, got %T", msg.Payload)
		}
		approved = p.ReenrollApproved
		t.Logf("received ReEnrollApproved kek_len=%d challenge_len=%d",
			len(approved.Kek), len(approved.Challenge))
	case err := <-errCh:
		t.Fatalf("stream error waiting for ReEnrollApproved: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for ReEnrollApproved")
	}

	// Sign the challenge with our ed25519 private key and send the proof.
	// Mirrors agent/internal/nodekey.Sign — ed25519.Sign(priv, challenge).
	sig := ed25519.Sign(srv.priv, approved.Challenge)
	if err := stream.Send(&pb.AgentMessage{
		Payload: &pb.AgentMessage_ReenrollProof{
			ReenrollProof: &pb.ReEnrollProof{Signature: sig},
		},
	}); err != nil {
		t.Fatalf("send ReEnrollProof: %v", err)
	}
	t.Log("ReEnrollProof sent")

	// Read CertRenewResponse.
	msgCh2, errCh2 := recvHubMessage(stream)
	var certResp *pb.CertRenewResponse
	select {
	case msg := <-msgCh2:
		p, ok := msg.Payload.(*pb.HubMessage_CertRenewResponse)
		if !ok {
			t.Fatalf("expected CertRenewResponse, got %T", msg.Payload)
		}
		certResp = p.CertRenewResponse
		t.Logf("received CertRenewResponse client_cert_len=%d", len(certResp.ClientCert))
	case err := <-errCh2:
		t.Fatalf("stream error waiting for CertRenewResponse: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for CertRenewResponse")
	}

	// Assert: cert must parse and have CN == serverID.
	if len(certResp.ClientCert) == 0 {
		t.Fatal("CertRenewResponse: empty ClientCert")
	}
	cert, err := x509.ParseCertificate(certResp.ClientCert)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	if cert.Subject.CommonName != srv.serverID {
		t.Fatalf("cert CN: got %q, want %q", cert.Subject.CommonName, srv.serverID)
	}
	t.Logf("client cert CN=%s (correct)", cert.Subject.CommonName)

	// Assert: approve HTTP returned 200.
	select {
	case status := <-approveCh:
		if status != http.StatusOK {
			t.Fatalf("approve HTTP: got %d, want 200", status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for approve HTTP response")
	}
	t.Log("approve HTTP returned 200 OK")

	// Assert: DB status is "approved".
	assertReEnrollStatus(t, h, requestID, "approved")
	t.Log("DB status=approved — happy path PASS")
}

// TestReEnrollDenyPath validates that denying a request sets DB status to
// "denied" and no certificate is issued.
func TestReEnrollDenyPath(t *testing.T) {
	h := StartHarness(t)
	adminToken, _ := h.SetupAdminWithTOTP(t)

	srv := seedEnrolledServer(t, h, adminToken, "reenroll-deny-server")
	t.Logf("seeded server id=%s", srv.serverID)

	csrDER := generateCSR(t, srv.serverID)

	stream, conn := openReEnrollStream(t, h)
	defer conn.Close()
	defer stream.CloseSend()

	if err := stream.Send(&pb.AgentMessage{
		Payload: &pb.AgentMessage_ReenrollRequest{
			ReenrollRequest: &pb.ReEnrollRequest{
				ServerId:    srv.serverID,
				Csr:         csrDER,
				Fingerprint: srv.fingerprint,
			},
		},
	}); err != nil {
		t.Fatalf("send ReEnrollRequest: %v", err)
	}

	requestID := waitForPendingReEnroll(t, h, srv.serverID, adminToken, 5*time.Second)
	t.Logf("pending request id=%s", requestID)

	// Deny the request.  This only updates the DB; the stream goroutine remains
	// blocked on the approve channel until its 10-minute timeout.
	denyReEnroll(t, h, adminToken, srv.serverID, requestID)
	t.Log("deny HTTP returned 200 OK")

	// Assert DB status is "denied".
	assertReEnrollStatus(t, h, requestID, "denied")
	t.Log("DB status=denied")

	// Verify no CertRenewResponse arrives within a short window.
	msgCh, _ := recvHubMessage(stream)
	select {
	case msg := <-msgCh:
		if _, ok := msg.Payload.(*pb.HubMessage_CertRenewResponse); ok {
			t.Fatal("deny path: unexpectedly received CertRenewResponse")
		}
		// Any other message (e.g. ReEnrollDenied if the server sends one) is fine.
		t.Logf("deny path: received non-cert message %T (acceptable)", msg.Payload)
	case <-time.After(2 * time.Second):
		// No message — correct, the stream is blocked waiting for approval.
		t.Log("no cert received within 2s — correct, stream blocked")
	}

	t.Log("deny path PASS")
}
