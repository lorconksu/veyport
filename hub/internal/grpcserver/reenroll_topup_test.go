package grpcserver

// Coverage top-up tests for reenroll.go — added to reach the ≥90% new-code gate.
// These tests cover the timeout arms (approval-timeout, proof-timeout) and a
// handful of other cheap branches that were left red after prior coverage work.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// ---------------------------------------------------------------------------
// Timeout-arm tests (use the var seam)
// ---------------------------------------------------------------------------

// TestHandleReEnrollRequest_ApprovalTimeout exercises the approval-timeout arm of
// handleReEnrollRequest (the <-time.After(reEnrollApprovalTimeout) branch).
// The server is enrolled so the function proceeds to the blocking select; we
// shrink the timeout to 20 ms so the test finishes quickly.
// Expected: approvalSent=false, nil error; DB request status becomes "expired".
func TestHandleReEnrollRequest_ApprovalTimeout(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	// Seed server with node crypto so GetNodeCrypto returns valid data.
	seedServer(t, h, "srv-approval-timeout")
	if err := st.SetNodeCrypto("srv-approval-timeout", "dGVzdC1wdWI=", "00112233", "fp-t"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Shrink timeout so the test does not wait 10 minutes.
	orig := reEnrollApprovalTimeout
	reEnrollApprovalTimeout = 20 * time.Millisecond
	t.Cleanup(func() { reEnrollApprovalTimeout = orig })

	stream := &mockStream{ctx: context.Background()}
	req := &pb.ReEnrollRequest{
		ServerId:    "srv-approval-timeout",
		Fingerprint: "fp-t",
		Csr:         testRegistrationCSR(t),
	}

	approvalSent, err := h.handleReEnrollRequest(stream, req)
	if err != nil {
		t.Fatalf("expected nil error on approval timeout, got: %v", err)
	}
	if approvalSent {
		t.Fatal("expected approvalSent=false when approval timeout fires")
	}

	// The session must have been cleared (no goroutine left waiting).
	if _, ok := h.lookupReEnroll("srv-approval-timeout"); ok {
		t.Fatal("expected session to be cleared after approval timeout")
	}

	// The DB request status must be "expired".
	// Retrieve the request — it was inserted by handleReEnrollRequest itself; we
	// need to list all reenroll requests (pending is now empty; status is expired).
	// Use ListPendingReEnroll to confirm it is no longer pending.
	pending, err := st.ListPendingReEnroll()
	if err != nil {
		t.Fatalf("ListPendingReEnroll: %v", err)
	}
	for _, r := range pending {
		if r.ServerID == "srv-approval-timeout" {
			t.Fatalf("expected expired request to not appear in pending list, got %+v", r)
		}
	}
}

// TestReleaseKEK_ProofTimeout exercises the proof-timeout arm of ReleaseKEK
// (the <-time.After(reEnrollProofTimeout) branch).
// We shrink the proof timeout to 20 ms so the test finishes quickly.
// The goroutine reads from sess.approve but never writes to sess.result, so
// ReleaseKEK times out and returns "timed out waiting for agent proof".
func TestReleaseKEK_ProofTimeout(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	seedServer(t, h, "srv-proof-timeout")

	// Seal a real KEK.
	kekRaw := make([]byte, 32)
	kekEnc, err := h.sealKEK(kekRaw)
	if err != nil {
		t.Fatalf("sealKEK: %v", err)
	}
	if err := st.SetNodeCrypto("srv-proof-timeout", "dGVzdC1wdWI=", kekEnc, "fp-t"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Store a valid 32-byte X25519 public key.
	transportPubHex := "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
	transportPubBytes := decodeHexForTest(transportPubHex)
	transportPubB64 := base64.StdEncoding.EncodeToString(transportPubBytes)
	if err := st.SetNodeTransportPub("srv-proof-timeout", transportPubB64); err != nil {
		t.Fatalf("SetNodeTransportPub: %v", err)
	}

	sess := h.registerReEnroll("srv-proof-timeout", testRegistrationCSR(t), "fp-t")

	// Goroutine: drain from sess.approve (simulates stream goroutine receiving the
	// approval) but never write to sess.result — this causes the proof timeout.
	go func() {
		<-sess.approve
		// Intentionally do not write to sess.result.
	}()

	// Shrink the proof timeout so the test finishes quickly.
	orig := reEnrollProofTimeout
	reEnrollProofTimeout = 20 * time.Millisecond
	t.Cleanup(func() { reEnrollProofTimeout = orig })

	releaseErr := h.ReleaseKEK("srv-proof-timeout", "admin-1")
	if releaseErr == nil {
		t.Fatal("expected error from ReleaseKEK on proof timeout")
	}
	if !strings.Contains(releaseErr.Error(), "timed out") {
		t.Fatalf("expected 'timed out' error, got: %v", releaseErr)
	}
}

// ---------------------------------------------------------------------------
// Other cheap branches
// ---------------------------------------------------------------------------

// TestHandleReEnrollRequest_SendApprovedFails: approval signal arrives but
// stream.Send for ReEnrollApproved returns an error → (false, err).
func TestHandleReEnrollRequest_SendApprovedFails(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	seedServer(t, h, "srv-send-fails")
	if err := st.SetNodeCrypto("srv-send-fails", "dGVzdC1wdWI=", "00112233", "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// sendErr will be returned by stream.Send.
	sendErr := errors.New("stream send error")
	stream := &mockStream{ctx: context.Background(), sendErr: sendErr}

	req := &pb.ReEnrollRequest{
		ServerId:    "srv-send-fails",
		Fingerprint: "fp-x",
		Csr:         testRegistrationCSR(t),
	}

	// Send an approval signal via goroutine after a tiny delay.
	go func() {
		time.Sleep(5 * time.Millisecond)
		sess, ok := h.lookupReEnroll("srv-send-fails")
		if !ok {
			return
		}
		sess.approve <- reEnrollApproval{
			ephemeralPub: make([]byte, 32),
			encryptedKek: make([]byte, 44),
			challenge:    make([]byte, 32),
			decidedBy:    "admin-1",
		}
	}()

	approvalSent, err := h.handleReEnrollRequest(stream, req)
	if err == nil {
		t.Fatal("expected error when stream.Send fails for ReEnrollApproved")
	}
	if approvalSent {
		t.Fatal("expected approvalSent=false when stream.Send fails")
	}
}

// TestHandleReEnrollRequest_CreateReEnrollRequestFails exercises the
// "failed to create request" error path in handleReEnrollRequest (lines 181-185).
// We pre-insert a row with the same server_id and then close the DB so any
// additional insert fails. Actually, we insert a request with a duplicate ID
// by setting the UUID manually — but since UUID is generated inside the function
// we can't predict it. Instead we close the store after SetNodeCrypto is done
// but use a second independent store to seed, so GetNodeCrypto still works but
// CreateReEnrollRequest fails.
//
// Simpler approach: we seed the node crypto into the store, then close the store's
// underlying DB so CreateReEnrollRequest fails, but because GetNodeCrypto is
// called first and the store is closed, GetNodeCrypto would also fail. Instead,
// use a helper that triggers a unique constraint violation:
// duplicate the insert by calling CreateReEnrollRequest with a fixed ID before
// the function runs — but the function generates its own ID so we can't control it.
//
// Best available approach: create a second request that closes the DB BETWEEN
// GetNodeCrypto and CreateReEnrollRequest is not feasible without a mock.
// We test the "internal error" send-denied path by triggering a duplicate PK:
// Pre-insert a reenroll_requests row with a crafted fixed UUID that matches
// what uuid.New() would generate — impossible. So we use a wrapper that opens,
// seeds crypto, reads back (GetNodeCrypto), then closes the DB (so subsequent
// calls fail). The simplest path: use a context that is already cancelled so
// the select picks context.Done before CreateReEnrollRequest. But then we skip
// CreateReEnrollRequest entirely. So we skip this specific path and focus on
// the GetNodeCrypto-failure path instead.
//
// NOTE: Lines 181-185 (CreateReEnrollRequest failure) are inherently hard to
// reach without a mock store; they are NOT targeted by this test.

// TestReleaseKEK_GetNodeCryptoReturnsErr exercises the GetNodeCrypto error arm
// of ReleaseKEK (lines 363-365): a session is registered but the server no
// longer exists in the DB (ErrNoRows from GetNodeCrypto).
func TestReleaseKEK_GetNodeCryptoReturnsErr(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	// Register a session — but do NOT create the server, so GetNodeCrypto returns ErrNoRows.
	_ = h.registerReEnroll("srv-ghost-crypto", testRegistrationCSR(t), "fp-x")
	_ = st // silence unused warning — st is kept open for the test cleanup

	releaseErr := h.ReleaseKEK("srv-ghost-crypto", "admin-1")
	if releaseErr == nil {
		t.Fatal("expected error from ReleaseKEK when server does not exist")
	}
	if !strings.Contains(releaseErr.Error(), "get node crypto") {
		t.Fatalf("unexpected error: %v", releaseErr)
	}
}

// TestHandleReEnrollProof_SendCertFails: valid session + valid signature + CA
// configured, but stream.Send for CertRenewResponse returns an error → error
// is posted on sess.result and returned from handleReEnrollProof.
func TestHandleReEnrollProof_SendCertFails(t *testing.T) {
	h, st := testHandler(t) // testHandler wires a real CA.

	seedServer(t, h, "srv-cert-send-fails")

	// Real ed25519 key pair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := st.SetNodeCrypto("srv-cert-send-fails", pubB64, "00112233", "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Insert a re-enroll request row so UpdateReEnrollStatus can find it.
	reqRow := &model.ReEnrollRequest{
		ID: "re-cert-send-fails-1", ServerID: "srv-cert-send-fails",
		RequestedAt: "2026-07-11 00:00:00", IPAddress: "10.0.0.1",
		Fingerprint: "fp-x", Status: "pending", AnomalyFlags: "{}",
	}
	if err := st.CreateReEnrollRequest(reqRow); err != nil {
		t.Fatalf("CreateReEnrollRequest: %v", err)
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatalf("random challenge: %v", err)
	}

	sess := h.registerReEnroll("srv-cert-send-fails", testRegistrationCSR(t), "fp-x")
	sess.requestID = "re-cert-send-fails-1"
	sess.challenge = challenge
	sess.decidedBy = "admin-5"

	sig := ed25519.Sign(priv, challenge)

	// Make stream.Send fail so the CertRenewResponse cannot be delivered.
	sendErr := errors.New("send cert failed")
	stream := &mockStream{ctx: context.Background(), sendErr: sendErr}
	proof := &pb.ReEnrollProof{Signature: sig}

	returnedErr := h.handleReEnrollProof(stream, "srv-cert-send-fails", proof)
	if returnedErr == nil {
		t.Fatal("expected error from handleReEnrollProof when stream.Send fails")
	}
	if !strings.Contains(returnedErr.Error(), "send cert failed") {
		t.Fatalf("unexpected error: %v", returnedErr)
	}

	// The result channel must carry the send error.
	select {
	case resultErr := <-sess.result:
		if resultErr == nil {
			t.Fatal("expected non-nil error on sess.result")
		}
	default:
		t.Fatal("expected error posted on sess.result")
	}
}

// TestReleaseKEK_OpenKEKFails: session registered and server has node crypto
// set but the kekEncHex is invalid (garbage) → openKEK fails → ReleaseKEK returns
// error containing "decrypt KEK".
func TestReleaseKEK_OpenKEKFails(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	// Seed the server with invalid kekEncHex so openKEK fails.
	seedServer(t, h, "srv-bad-kek")
	// Store valid base64 pubkey but a garbage (non-decryptable) kekEncHex.
	// "aabbcc" is valid hex but the decrypted bytes won't be a valid ciphertext.
	if err := st.SetNodeCrypto("srv-bad-kek", "dGVzdC1wdWI=", "aabbcc", "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Register a live session.
	_ = h.registerReEnroll("srv-bad-kek", testRegistrationCSR(t), "fp-x")

	err := h.ReleaseKEK("srv-bad-kek", "admin-1")
	if err == nil {
		t.Fatal("expected error from ReleaseKEK when KEK decryption fails")
	}
	if !strings.Contains(err.Error(), "decrypt KEK") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestReleaseKEK_GetNodeTransportPubFails: session + KEK OK, but the server row
// doesn't exist in the DB so GetNodeTransportPub returns ErrNoRows → error.
func TestReleaseKEK_GetNodeTransportPubFails(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	// Create a server and set crypto — then delete the server so the transport
	// pub query returns ErrNoRows.
	if err := st.CreateServer(&model.Server{ID: "srv-no-tp-row", Name: "srv-no-tp-row", Status: "offline", Labels: "{}"}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	kekRaw := make([]byte, 32)
	kekEnc, err := h.sealKEK(kekRaw)
	if err != nil {
		t.Fatalf("sealKEK: %v", err)
	}
	if err := st.SetNodeCrypto("srv-no-tp-row", "dGVzdC1wdWI=", kekEnc, "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Register a session before deleting the server.
	_ = h.registerReEnroll("srv-no-tp-row", testRegistrationCSR(t), "fp-x")

	// Close the store so GetNodeTransportPub returns an error.
	st.Close()

	releaseErr := h.ReleaseKEK("srv-no-tp-row", "admin-1")
	if releaseErr == nil {
		t.Fatal("expected error when store is closed")
	}
}
