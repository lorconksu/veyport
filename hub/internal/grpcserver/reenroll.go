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
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// ErrNoPendingReEnroll is returned by ReleaseKEK when there is no live
// re-enrollment session for the given server. Callers (e.g. the HTTP approve
// handler) should match it with errors.Is rather than comparing error text.
var ErrNoPendingReEnroll = errors.New("no pending re-enroll for server")

// ErrReEnrollDecisionInProgress rejects a duplicate or conflicting admin decision.
var ErrReEnrollDecisionInProgress = errors.New("re-enrollment decision already in progress")

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
	ephemeralPub []byte
	encryptedKek []byte
	challenge    []byte
	decidedBy    string
}

type reEnrollState uint8

const (
	reEnrollPending reEnrollState = iota
	reEnrollPreparing
	reEnrollAwaitingProof
	reEnrollDelivering
	reEnrollFinished
)

// Identity fields are fixed before publication. Mutable state is protected by
// reEnrollMu; a decision belongs to one request and its originating stream.
type reEnrollSession struct {
	serverID    string
	requestID   string
	stream      pb.AgentService_ConnectServer
	csr         []byte
	fingerprint string
	challenge   []byte
	decidedBy   string
	proofUntil  time.Time
	state       reEnrollState
	outcome     error
	approve     chan reEnrollApproval
	result      chan error
	done        chan struct{}
}

func (h *Handler) registerReEnrollLocked(serverID string, csr []byte, fingerprint, requestID string, stream pb.AgentService_ConnectServer) *reEnrollSession {
	if previous := h.reEnrollSessions[serverID]; previous != nil {
		h.finishReEnrollLocked(previous, errors.New("re-enrollment request superseded"))
	}
	sess := &reEnrollSession{
		serverID: serverID, requestID: requestID, stream: stream,
		csr: append([]byte(nil), csr...), fingerprint: fingerprint,
		approve: make(chan reEnrollApproval, 1), result: make(chan error, 1), done: make(chan struct{}),
	}
	h.reEnrollSessions[serverID] = sess
	return sess
}

func (h *Handler) lookupReEnroll(serverID string) (*reEnrollSession, bool) {
	h.reEnrollMu.Lock()
	defer h.reEnrollMu.Unlock()
	sess, ok := h.reEnrollSessions[serverID]
	return sess, ok
}

func (h *Handler) finishReEnrollLocked(sess *reEnrollSession, err error) {
	if sess.state == reEnrollFinished {
		return
	}
	sess.state, sess.outcome = reEnrollFinished, err
	if h.reEnrollSessions[sess.serverID] == sess {
		delete(h.reEnrollSessions, sess.serverID)
	}
	// Completion must never wait for an HTTP caller that has already gone away.
	select {
	case sess.result <- err:
	default:
	}
	close(sess.done)
}

func (h *Handler) clearReEnroll(serverID string, sess *reEnrollSession) {
	h.reEnrollMu.Lock()
	defer h.reEnrollMu.Unlock()
	if sess.serverID == serverID {
		h.finishReEnrollLocked(sess, ErrNoPendingReEnroll)
	}
}

func (h *Handler) endReEnroll(sess *reEnrollSession, reason error, status string) error {
	h.reEnrollMu.Lock()
	defer h.reEnrollMu.Unlock()
	if sess.state == reEnrollFinished {
		return sess.outcome
	}
	if status != "" {
		if err := h.store.DecidePendingReEnroll(sess.serverID, sess.requestID, status, sess.decidedBy); err != nil && !errors.Is(err, store.ErrReEnrollNotPending) {
			log.Printf("reenroll: failed to persist %s for request %s: %v", status, sess.requestID, err)
		}
	}
	h.finishReEnrollLocked(sess, reason)
	return reason
}

// Network calls use a bounded worker. Returning Connect cancels the underlying
// gRPC stream and releases a blocked Send/Recv; no registry lock spans I/O.
func sendReEnrollMessage(stream pb.AgentService_ConnectServer, done <-chan struct{}, until time.Time, msg *pb.HubMessage) error {
	select {
	case <-done:
		return ErrNoPendingReEnroll
	case <-stream.Context().Done():
		return stream.Context().Err()
	default:
	}
	if !time.Now().Before(until) {
		return errors.New("timed out sending re-enrollment response")
	}
	result := make(chan error, 1)
	go func() { result <- stream.Send(msg) }()
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-done:
		return ErrNoPendingReEnroll
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-timer.C:
		return errors.New("timed out sending re-enrollment response")
	}
}

func sendReEnrollDenied(stream pb.AgentService_ConnectServer, reason string) error {
	return sendReEnrollMessage(stream, nil, time.Now().Add(reEnrollProofTimeout), &pb.HubMessage{
		Payload: &pb.HubMessage_ReenrollDenied{ReenrollDenied: &pb.ReEnrollDenied{Reason: reason}},
	})
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
// handleReEnrollRequest — bootstrap handshake only
// ---------------------------------------------------------------------------

// handleReEnrollRequest records a bootstrap request and waits for one admin
// decision. Approval releases only the proof exchange, never normal routing.
func (h *Handler) handleReEnrollRequest(stream pb.AgentService_ConnectServer, req *pb.ReEnrollRequest) (bool, error) {
	if req == nil || req.ServerId == "" {
		_ = sendReEnrollDenied(stream, "server id is required")
		return false, nil
	}
	serverID, peerIP := req.ServerId, h.peerAddr(stream)
	pubB64, _, _, err := h.store.GetNodeCrypto(serverID)
	if err != nil || pubB64 == "" {
		_ = sendReEnrollDenied(stream, "unknown or non-enrolled server")
		return false, nil
	}
	flags := h.computeAnomalyFlags(serverID, req.Fingerprint)
	dbReq := &model.ReEnrollRequest{
		ID: uuid.NewString(), ServerID: serverID,
		RequestedAt: time.Now().UTC().Format("2006-01-02 15:04:05"),
		IPAddress:   peerIP, Fingerprint: req.Fingerprint, Status: "pending", AnomalyFlags: flags,
	}
	// Publication and replacing the durable pending request share the decision
	// lock, closing the HTTP validation-to-release race.
	h.reEnrollMu.Lock()
	err = h.store.CreateCurrentReEnrollRequest(dbReq)
	var sess *reEnrollSession
	if err == nil {
		sess = h.registerReEnrollLocked(serverID, req.Csr, req.Fingerprint, dbReq.ID, stream)
	}
	h.reEnrollMu.Unlock()
	if err != nil {
		log.Printf("reenroll: failed to create request for %s: %v", serverID, err)
		_ = sendReEnrollDenied(stream, "internal error")
		return false, nil
	}
	h.store.LogAudit(model.AuditEntry{Action: model.AuditReEnrollRequested, Target: &serverID, IPAddress: optionalStringPointer(peerIP), ActorType: model.AuditActorTypeDevice})
	var af anomalyFlags
	_ = json.Unmarshal([]byte(flags), &af)
	if af.FingerprintChanged || af.OriginalOnline {
		h.store.LogAudit(model.AuditEntry{Action: model.AuditCloneSuspected, Target: &serverID, Detail: optionalStringPointer(flags), IPAddress: optionalStringPointer(peerIP), ActorType: model.AuditActorTypeSystem})
	}
	timer := time.NewTimer(reEnrollApprovalTimeout)
	defer timer.Stop()
	select {
	case appr := <-sess.approve:
		h.reEnrollMu.Lock()
		valid := h.reEnrollSessions[serverID] == sess && sess.state == reEnrollAwaitingProof && stream.Context().Err() == nil
		until := sess.proofUntil
		h.reEnrollMu.Unlock()
		if !valid {
			return false, nil
		}
		err := sendReEnrollMessage(stream, sess.done, until, &pb.HubMessage{
			Payload: &pb.HubMessage_ReenrollApproved{ReenrollApproved: &pb.ReEnrollApproved{
				EphemeralPub: appr.ephemeralPub, EncryptedKek: appr.encryptedKek, Challenge: appr.challenge,
			}},
		})
		if err != nil {
			h.endReEnroll(sess, err, "expired")
			return false, err
		}
		return true, nil
	case <-sess.done:
		_ = sendReEnrollDenied(stream, "re-enrollment request ended")
		return false, nil
	case <-timer.C:
		h.endReEnroll(sess, errors.New("timed out waiting for admin approval"), "expired")
		return false, nil
	case <-stream.Context().Done():
		h.endReEnroll(sess, stream.Context().Err(), "expired")
		return false, nil
	}
}

// receiveReEnrollProof accepts exactly one proof on the approved bootstrap
// stream, then closes it. The agent reconnects using its newly issued mTLS cert.
func (h *Handler) receiveReEnrollProof(stream pb.AgentService_ConnectServer, serverID string) error {
	h.reEnrollMu.Lock()
	sess := h.reEnrollSessions[serverID]
	if sess == nil || sess.stream != stream || sess.state != reEnrollAwaitingProof {
		h.reEnrollMu.Unlock()
		return nil
	}
	until := sess.proofUntil
	h.reEnrollMu.Unlock()
	defer h.endReEnroll(sess, errors.New("re-enrollment stream ended"), "expired")
	received := make(chan controlReceive, 1)
	go func() {
		msg, err := stream.Recv()
		received <- controlReceive{msg: msg, err: err}
	}()
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case got := <-received:
		if got.err != nil {
			return got.err
		}
		if got.msg == nil || got.msg.GetReenrollProof() == nil {
			h.endReEnroll(sess, errors.New("expected re-enrollment proof"), "denied")
			_ = sendReEnrollDenied(stream, "expected re-enrollment proof")
			return nil
		}
		return h.handleReEnrollProof(stream, serverID, got.msg.GetReenrollProof())
	case <-sess.done:
		return nil
	case <-timer.C:
		h.endReEnroll(sess, errors.New("timed out waiting for agent proof"), "expired")
		return nil
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

func (h *Handler) handleReEnrollProof(stream pb.AgentService_ConnectServer, serverID string, proof *pb.ReEnrollProof) error {
	h.reEnrollMu.Lock()
	sess := h.reEnrollSessions[serverID]
	if sess == nil || sess.stream != stream || sess.state != reEnrollAwaitingProof || len(sess.challenge) != 32 || !time.Now().Before(sess.proofUntil) || stream.Context().Err() != nil {
		h.reEnrollMu.Unlock()
		_ = sendReEnrollDenied(stream, "no approved re-enrollment on this stream")
		return nil
	}
	// Verification, issuance and durable decision form one local operation.
	// Replacement/denial cannot change this request halfway through issuance.
	clientCert, caCert, err := h.verifyReEnrollProofLocked(sess, proof)
	if err == nil {
		err = h.store.DecidePendingReEnroll(serverID, sess.requestID, "approved", sess.decidedBy)
	}
	if err != nil {
		_ = h.store.DecidePendingReEnroll(serverID, sess.requestID, "denied", sess.decidedBy)
		h.finishReEnrollLocked(sess, err)
		h.reEnrollMu.Unlock()
		log.Printf("reenroll proof: request %s denied: %v", sess.requestID, err)
		_ = sendReEnrollDenied(stream, "proof verification or certificate issuance failed")
		h.store.LogAudit(model.AuditEntry{Action: model.AuditReEnrollDenied, Target: &serverID, ActorType: model.AuditActorTypeSystem})
		return nil
	}
	sess.state = reEnrollDelivering
	delete(h.reEnrollSessions, serverID)
	until := sess.proofUntil
	h.reEnrollMu.Unlock()
	err = sendReEnrollMessage(stream, sess.done, until, &pb.HubMessage{
		Payload: &pb.HubMessage_CertRenewResponse{CertRenewResponse: &pb.CertRenewResponse{ClientCert: clientCert, CaCert: caCert}},
	})
	h.endReEnroll(sess, err, "")
	return err
}

func (h *Handler) verifyReEnrollProofLocked(sess *reEnrollSession, proof *pb.ReEnrollProof) ([]byte, []byte, error) {
	pubB64, _, _, err := h.store.GetNodeCrypto(sess.serverID)
	if err != nil || pubB64 == "" {
		return nil, nil, errors.New("server not enrolled")
	}
	pubRaw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return nil, nil, errors.New("invalid node public key")
	}
	if proof == nil || !ed25519.Verify(ed25519.PublicKey(pubRaw), sess.challenge, proof.Signature) {
		return nil, nil, errors.New("proof verification failed")
	}
	return h.issueRegistrationCertificate(sess.serverID, sess.csr)
}

// ReleaseKEK reserves a decision for the exact HTTP-approved request. Duplicate
// decisions fail promptly; expensive sealing never holds the registry lock.
func (h *Handler) ReleaseKEK(serverID, requestID, decidedBy string) error {
	h.reEnrollMu.Lock()
	sess := h.reEnrollSessions[serverID]
	if sess == nil || sess.requestID != requestID || requestID == "" {
		h.reEnrollMu.Unlock()
		return ErrNoPendingReEnroll
	}
	if sess.state != reEnrollPending {
		h.reEnrollMu.Unlock()
		return ErrReEnrollDecisionInProgress
	}
	sess.state = reEnrollPreparing
	h.reEnrollMu.Unlock()
	appr, err := h.prepareReEnrollApproval(serverID, decidedBy)
	h.reEnrollMu.Lock()
	if h.reEnrollSessions[serverID] != sess || sess.state != reEnrollPreparing || sess.stream.Context().Err() != nil {
		h.reEnrollMu.Unlock()
		h.endReEnroll(sess, ErrNoPendingReEnroll, "expired")
		return ErrNoPendingReEnroll
	}
	if err != nil {
		sess.state = reEnrollPending
		h.reEnrollMu.Unlock()
		return err
	}
	if err := h.store.DecidePendingReEnroll(serverID, requestID, "pending", decidedBy); err != nil {
		h.finishReEnrollLocked(sess, err)
		h.reEnrollMu.Unlock()
		return err
	}
	sess.challenge, sess.decidedBy = appr.challenge, decidedBy
	sess.proofUntil = time.Now().Add(reEnrollProofTimeout)
	sess.state = reEnrollAwaitingProof
	sess.approve <- appr // one reserved decision, one buffered slot
	until := sess.proofUntil
	h.reEnrollMu.Unlock()
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case err := <-sess.result:
		return err
	case <-sess.done:
		h.reEnrollMu.Lock()
		err := sess.outcome
		h.reEnrollMu.Unlock()
		return err
	case <-timer.C:
		err := errors.New("timed out waiting for agent proof")
		return h.endReEnroll(sess, err, "expired")
	case <-sess.stream.Context().Done():
		err := sess.stream.Context().Err()
		return h.endReEnroll(sess, err, "expired")
	}
}

// DenyReEnroll shares the approval/replacement lock and immediately releases
// the waiting bootstrap stream. A late denial cannot cancel another request.
func (h *Handler) DenyReEnroll(serverID, requestID, decidedBy string) error {
	h.reEnrollMu.Lock()
	defer h.reEnrollMu.Unlock()
	sess := h.reEnrollSessions[serverID]
	if sess == nil || sess.requestID != requestID || requestID == "" {
		return ErrNoPendingReEnroll
	}
	if sess.state != reEnrollPending {
		return ErrReEnrollDecisionInProgress
	}
	if err := h.store.DecidePendingReEnroll(serverID, requestID, "denied", decidedBy); err != nil {
		return err
	}
	h.finishReEnrollLocked(sess, errors.New("re-enrollment denied by admin"))
	return nil
}

func (h *Handler) prepareReEnrollApproval(serverID, decidedBy string) (reEnrollApproval, error) {
	fail := func(err error) (reEnrollApproval, error) { return reEnrollApproval{}, err }
	_, kekEncHex, _, err := h.store.GetNodeCrypto(serverID)
	if err != nil {
		return fail(fmt.Errorf("get node crypto for %s: %w", serverID, err))
	}
	kek, err := h.openKEK(kekEncHex)
	if err != nil {
		return fail(fmt.Errorf("decrypt KEK for %s: %w", serverID, err))
	}
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()
	transportPubB64, err := h.store.GetNodeTransportPub(serverID)
	if err != nil {
		return fail(fmt.Errorf("get transport pubkey for %s: %w", serverID, err))
	}
	if transportPubB64 == "" {
		return fail(errors.New("node has no transport key; re-register required to enable encrypted re-enrollment"))
	}
	transportPubBytes, err := base64.StdEncoding.DecodeString(transportPubB64)
	if err != nil {
		return fail(fmt.Errorf("decode transport pubkey for %s: %w", serverID, err))
	}
	ephemeralPub, encryptedKek, err := sealKEKToNode(transportPubBytes, kek)
	if err != nil {
		return fail(fmt.Errorf("seal KEK for %s: %w", serverID, err))
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fail(fmt.Errorf("generate challenge: %w", err))
	}
	return reEnrollApproval{ephemeralPub: ephemeralPub, encryptedKek: encryptedKek, challenge: challenge, decidedBy: decidedBy}, nil
}
