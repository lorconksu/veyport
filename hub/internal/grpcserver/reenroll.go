package grpcserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// reEnrollApprovalTimeout is how long the stream goroutine waits for an admin to
// approve/deny before auto-expiring the request.
// Declared as var (not const) so tests can override it without waiting 10 minutes.
var reEnrollApprovalTimeout = 10 * time.Minute

// reEnrollProofTimeout is how long ReleaseKEK waits for the agent to send its
// proof after the KEK+challenge have been delivered via the stream.
// Declared as var (not const) so tests can override it without waiting 30 seconds.
var reEnrollProofTimeout = 30 * time.Second

// ---------------------------------------------------------------------------
// Session registry
// ---------------------------------------------------------------------------

// reEnrollApproval carries the admin's decision from the HTTP goroutine to the
// stream goroutine over the approve channel.
// ephemeralPub and encryptedKek are produced by sealKEKToNode; the raw KEK
// never travels over this channel — it is sealed before delivery.
type reEnrollApproval struct {
	ephemeralPub  []byte
	encryptedKek  []byte
	challenge     []byte
	decidedBy     string
}

// reEnrollSession holds all transient state for a single in-flight re-enrollment.
// The approve channel is written by the HTTP approve handler (Task 7);
// the result channel is written by the stream's proof handler and read back by
// the HTTP handler to learn the outcome.
type reEnrollSession struct {
	serverID    string
	requestID   string // DB row ID — used when updating status
	csr         []byte // CSR bytes from ReEnrollRequest; signed after proof
	fingerprint string
	challenge   []byte // set when approval arrives; echoed in ReEnrollApproved and verified against proof
	decidedBy   string // set when approval arrives; propagated to UpdateReEnrollStatus

	// approve: HTTP goroutine -> stream goroutine (buffered 1)
	approve chan reEnrollApproval
	// result: stream goroutine -> HTTP goroutine (buffered 1)
	result chan error
}

// registerReEnroll creates a fresh session for serverID, stores it in the
// registry under reEnrollMu, and returns it. Channels are buffered (cap 1) so
// that the HTTP goroutine never blocks if the stream goroutine has already
// exited (timeout / disconnect).
func (h *Handler) registerReEnroll(serverID string, csr []byte, fingerprint string) *reEnrollSession {
	sess := &reEnrollSession{
		serverID:    serverID,
		csr:         csr,
		fingerprint: fingerprint,
		approve:     make(chan reEnrollApproval, 1),
		result:      make(chan error, 1),
	}
	h.reEnrollMu.Lock()
	h.reEnrollSessions[serverID] = sess
	h.reEnrollMu.Unlock()
	return sess
}

// lookupReEnroll returns the live session for serverID (if any).
func (h *Handler) lookupReEnroll(serverID string) (*reEnrollSession, bool) {
	h.reEnrollMu.Lock()
	sess, ok := h.reEnrollSessions[serverID]
	h.reEnrollMu.Unlock()
	return sess, ok
}

// clearReEnroll removes the session for serverID from the registry, but ONLY if
// the currently stored session is the same pointer as sess. This prevents a
// late-exiting goroutine (timeout / disconnect) from deleting a newer session
// that was registered for the same serverID after it was superseded.
func (h *Handler) clearReEnroll(serverID string, sess *reEnrollSession) {
	h.reEnrollMu.Lock()
	if cur, ok := h.reEnrollSessions[serverID]; ok && cur == sess {
		delete(h.reEnrollSessions, serverID)
	}
	h.reEnrollMu.Unlock()
}

// ---------------------------------------------------------------------------
// computeAnomalyFlags
// ---------------------------------------------------------------------------

type anomalyFlags struct {
	FingerprintChanged bool `json:"fingerprint_changed"`
	OriginalOnline     bool `json:"original_online"`
}

// computeAnomalyFlags returns a JSON string describing anomaly signals for the
// given re-enrollment request. It compares the supplied fingerprint against the
// stored enroll fingerprint and checks whether the server's current status is
// "online" (which would indicate the original agent might still be running).
func (h *Handler) computeAnomalyFlags(serverID, fingerprint string) string {
	flags := anomalyFlags{}

	// Compare fingerprint against the stored enrollment fingerprint.
	_, _, enrollFP, err := h.store.GetNodeCrypto(serverID)
	if err == nil {
		flags.FingerprintChanged = enrollFP != fingerprint
	}
	// If the server doesn't exist or has no node material, FingerprintChanged
	// stays false (we can't determine anything — fail safe).

	// Check whether the server is currently online.
	if srv, err := h.store.GetServerByID(serverID); err == nil {
		flags.OriginalOnline = srv.Status == "online"
	}

	out, _ := json.Marshal(flags)
	return string(out)
}

// ---------------------------------------------------------------------------
// handleReEnrollRequest — called from routeAgentMessage
// ---------------------------------------------------------------------------

// handleReEnrollRequest processes an agent's ReEnrollRequest message.
// It validates the server, records the request, computes anomaly flags, and
// then BLOCKS the stream goroutine waiting for an admin approval signal.
// Blocking here is intentional — this is a long-lived bidi stream and the agent
// waits for the hub to send ReEnrollApproved (or ReEnrollDenied / timeout).
//
// Returns (approvalSent=true, nil) ONLY when a ReEnrollApproved message was
// successfully written to the stream — meaning proof is expected next and the
// caller should keep the stream open for the message loop.
// Returns (approvalSent=false, ...) on ALL early-exit paths: unknown/non-enrolled
// server, DB error, approval timeout, context cancellation, or send failure.
// Callers MUST NOT register the stream in connMgr when approvalSent is false.
func (h *Handler) handleReEnrollRequest(stream pb.AgentService_ConnectServer, req *pb.ReEnrollRequest) (approvalSent bool, err error) {
	serverID := req.ServerId
	peerIP := h.peerAddr(stream)

	sendDenied := func(reason string) error {
		return stream.Send(&pb.HubMessage{
			Payload: &pb.HubMessage_ReenrollDenied{
				ReenrollDenied: &pb.ReEnrollDenied{Reason: reason},
			},
		})
	}

	// 1. Verify the server exists and has node material (enrolled via Task 1 path).
	pubB64, _, _, err := h.store.GetNodeCrypto(serverID)
	if err != nil || pubB64 == "" {
		log.Printf("reenroll: unknown or non-enrolled server %s: %v", serverID, err)
		_ = sendDenied("unknown or non-enrolled server")
		return false, nil
	}

	// 2. Compute anomaly flags.
	flags := h.computeAnomalyFlags(serverID, req.Fingerprint)

	// 3. Persist the request.
	reqID := uuid.New().String()
	dbReq := &model.ReEnrollRequest{
		ID:           reqID,
		ServerID:     serverID,
		RequestedAt:  time.Now().UTC().Format("2006-01-02 15:04:05"),
		IPAddress:    peerIP,
		Fingerprint:  req.Fingerprint,
		Status:       "pending",
		AnomalyFlags: flags,
	}
	if err := h.store.CreateReEnrollRequest(dbReq); err != nil {
		log.Printf("reenroll: failed to create request for %s: %v", serverID, err)
		_ = sendDenied("internal error")
		return false, nil
	}

	// 4. Audit.
	h.store.LogAudit(model.AuditEntry{
		Action:    model.AuditReEnrollRequested,
		Target:    &serverID,
		IPAddress: optionalStringPointer(peerIP),
		ActorType: model.AuditActorTypeDevice,
	})

	// Emit clone-suspected audit if either anomaly flag is set.
	var af anomalyFlags
	_ = json.Unmarshal([]byte(flags), &af)
	if af.FingerprintChanged || af.OriginalOnline {
		h.store.LogAudit(model.AuditEntry{
			Action:    model.AuditCloneSuspected,
			Target:    &serverID,
			Detail:    optionalStringPointer(flags),
			IPAddress: optionalStringPointer(peerIP),
			ActorType: model.AuditActorTypeSystem,
		})
	}

	// 5. Register the live session so the HTTP approve handler (Task 7) can signal us.
	sess := h.registerReEnroll(serverID, req.Csr, req.Fingerprint)
	sess.requestID = reqID

	// 6. Block waiting for admin approval, stream disconnect, or timeout.
	select {
	case appr := <-sess.approve:
		sess.challenge = appr.challenge
		sess.decidedBy = appr.decidedBy
		if err := stream.Send(&pb.HubMessage{
			Payload: &pb.HubMessage_ReenrollApproved{
				ReenrollApproved: &pb.ReEnrollApproved{
					EphemeralPub: appr.ephemeralPub,
					EncryptedKek: appr.encryptedKek,
					Challenge:    appr.challenge,
				},
			},
		}); err != nil {
			// Send failed — treat as early exit; caller must not enter the proof loop.
			return false, err
		}
		// ReEnrollApproved was sent; the agent will send ReEnrollProof next.
		return true, nil

	case <-time.After(reEnrollApprovalTimeout):
		h.clearReEnroll(serverID, sess)
		_ = h.store.UpdateReEnrollStatus(reqID, "expired", "")
		log.Printf("reenroll: approval timeout for %s", serverID)
		return false, nil

	case <-stream.Context().Done():
		h.clearReEnroll(serverID, sess)
		return false, nil
	}
}

// ---------------------------------------------------------------------------
// handleReEnrollProof — called from routeAgentMessage
// ---------------------------------------------------------------------------

// handleReEnrollProof processes the agent's ReEnrollProof message.
// It verifies the ed25519 signature over the challenge, issues a new client
// cert via SignCSR, and delivers it via the CertRenewResponse message.
func (h *Handler) handleReEnrollProof(stream pb.AgentService_ConnectServer, serverID string, proof *pb.ReEnrollProof) error {
	sendDenied := func(reason string) error {
		return stream.Send(&pb.HubMessage{
			Payload: &pb.HubMessage_ReenrollDenied{
				ReenrollDenied: &pb.ReEnrollDenied{Reason: reason},
			},
		})
	}

	// 1. Look up the live session.
	sess, ok := h.lookupReEnroll(serverID)
	if !ok {
		_ = sendDenied("no pending re-enroll")
		return nil
	}

	// 2. Load the stored node public key.
	pubB64, _, _, err := h.store.GetNodeCrypto(serverID)
	if err != nil || pubB64 == "" {
		log.Printf("reenroll proof: no node crypto for %s: %v", serverID, err)
		_ = sendDenied("server not enrolled")
		sess.result <- errors.New("server not enrolled")
		h.clearReEnroll(serverID, sess)
		return nil
	}
	pubRaw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		log.Printf("reenroll proof: invalid public key for %s", serverID)
		_ = sendDenied("invalid node public key")
		sess.result <- errors.New("invalid node public key")
		h.clearReEnroll(serverID, sess)
		return nil
	}
	pub := ed25519.PublicKey(pubRaw)

	// 3. Verify the signature over the challenge.
	if !ed25519.Verify(pub, sess.challenge, proof.Signature) {
		log.Printf("reenroll proof: signature verification failed for %s", serverID)
		_ = sendDenied("proof verification failed")
		sess.result <- errors.New("proof verification failed")
		_ = h.store.UpdateReEnrollStatus(sess.requestID, "denied", "")
		h.clearReEnroll(serverID, sess)
		h.store.LogAudit(model.AuditEntry{
			Action:    model.AuditReEnrollDenied,
			Target:    &serverID,
			ActorType: model.AuditActorTypeSystem,
		})
		return nil
	}

	// 4. Issue a new client certificate.
	clientCert, caCert, err := h.issueRegistrationCertificate(serverID, sess.csr)
	if err != nil {
		log.Printf("reenroll proof: failed to sign CSR for %s: %v", serverID, err)
		_ = sendDenied(fmt.Sprintf("cert issuance failed: %v", err))
		sess.result <- err
		_ = h.store.UpdateReEnrollStatus(sess.requestID, "denied", "")
		h.clearReEnroll(serverID, sess)
		return nil
	}

	// Deliver via CertRenewResponse (the T5 contract).
	if err := stream.Send(&pb.HubMessage{
		Payload: &pb.HubMessage_CertRenewResponse{
			CertRenewResponse: &pb.CertRenewResponse{
				ClientCert: clientCert,
				CaCert:     caCert,
			},
		},
	}); err != nil {
		sess.result <- err
		h.clearReEnroll(serverID, sess)
		return err
	}

	// 5. Update DB, signal HTTP goroutine, clean up.
	// NOTE: AuditReEnrollApproved is emitted by the HTTP approve handler (which
	// carries the authoritative human admin UserID + IP). Do NOT duplicate it here.
	_ = h.store.UpdateReEnrollStatus(sess.requestID, "approved", sess.decidedBy)
	sess.result <- nil
	h.clearReEnroll(serverID, sess)

	return nil
}

// ---------------------------------------------------------------------------
// ReleaseKEK — called by the HTTP approve handler (Task 7)
// ---------------------------------------------------------------------------

// ReleaseKEK is the bridge from the HTTP approve handler to the blocked gRPC
// stream goroutine. It:
//  1. Looks up the live re-enrollment session for serverID.
//  2. Decrypts the stored KEK from the database.
//  3. Fetches the node's X25519 transport public key — REQUIRED. If absent,
//     returns an error (node must re-register to obtain a transport key; no
//     raw-KEK fallback, which would reopen the encryption hole).
//  4. Seals the KEK using sealKEKToNode(transportPub, kek).
//  5. Generates a random 32-byte challenge.
//  6. Delivers {ephemeralPub, encryptedKek, challenge} to the stream goroutine.
//  7. Waits (up to reEnrollProofTimeout) for the stream goroutine to verify
//     the agent proof and post the outcome on sess.result.
//
// The raw KEK never leaves the grpcserver package and never travels over the
// approve channel — only the sealed ciphertext is forwarded.
func (h *Handler) ReleaseKEK(serverID, decidedBy string) error {
	sess, ok := h.lookupReEnroll(serverID)
	if !ok {
		return errors.New("no pending re-enroll for server")
	}

	// Load and decrypt the stored KEK.
	_, kekEncHex, _, err := h.store.GetNodeCrypto(serverID)
	if err != nil {
		return fmt.Errorf("get node crypto for %s: %w", serverID, err)
	}
	kek, err := h.openKEK(kekEncHex)
	if err != nil {
		return fmt.Errorf("decrypt KEK for %s: %w", serverID, err)
	}
	// Zeroize the raw KEK when done — it must not persist beyond this scope.
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()

	// Fetch the node's X25519 transport public key.
	transportPubB64, err := h.store.GetNodeTransportPub(serverID)
	if err != nil {
		return fmt.Errorf("get transport pubkey for %s: %w", serverID, err)
	}
	if transportPubB64 == "" {
		return errors.New("node has no transport key; re-register required to enable encrypted re-enrollment")
	}
	transportPubBytes, err := base64.StdEncoding.DecodeString(transportPubB64)
	if err != nil {
		return fmt.Errorf("decode transport pubkey for %s: %w", serverID, err)
	}

	// Seal the KEK for transport to the node.
	ephemeralPub, encryptedKek, err := sealKEKToNode(transportPubBytes, kek)
	if err != nil {
		return fmt.Errorf("seal KEK for %s: %w", serverID, err)
	}

	// Generate a fresh random challenge.
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("generate challenge: %w", err)
	}

	// Signal the stream goroutine with the sealed KEK (NOT the raw kek).
	sess.approve <- reEnrollApproval{
		ephemeralPub: ephemeralPub,
		encryptedKek: encryptedKek,
		challenge:    challenge,
		decidedBy:    decidedBy,
	}

	// Wait for the agent to respond with a proof and the stream goroutine to
	// verify it, or time out.
	select {
	case err := <-sess.result:
		return err
	case <-time.After(reEnrollProofTimeout):
		return errors.New("timed out waiting for agent proof")
	}
}

