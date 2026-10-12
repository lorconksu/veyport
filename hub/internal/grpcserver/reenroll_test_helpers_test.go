package grpcserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// Wait for registration rather than assuming database and audit work takes <5 ms.
func waitForReEnrollSessionForTest(ctx context.Context, h *Handler, serverID string) (*reEnrollSession, error) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if sess, ok := h.lookupReEnroll(serverID); ok {
			return sess, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// The deadline also cancels the mock stream, preventing the handler from waiting
// for its production approval timeout when a test cannot deliver an approval.
func handleApprovedReEnrollForTest(t *testing.T, h *Handler, stream *mockStream, req *pb.ReEnrollRequest) (bool, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stream.ctx = ctx
	type result struct {
		approvalSent bool
		err          error
	}
	results := make(chan result, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("re-enrollment handler did not exit after stream cancellation")
		}
	})
	go func() {
		defer close(done)
		approvalSent, err := h.handleReEnrollRequest(stream, req)
		results <- result{approvalSent, err}
	}()

	sess, err := waitForReEnrollSessionForTest(ctx, h, req.ServerId)
	if err != nil {
		t.Fatalf("waiting for re-enrollment session %s: %v", req.ServerId, err)
	}
	approval := reEnrollApproval{
		ephemeralPub: make([]byte, 32),
		encryptedKek: make([]byte, 44),
		challenge:    make([]byte, 32),
		decidedBy:    "admin-1",
	}
	h.reEnrollMu.Lock()
	sess.state = reEnrollAwaitingProof
	sess.challenge = approval.challenge
	sess.decidedBy = approval.decidedBy
	sess.proofUntil = time.Now().Add(reEnrollProofTimeout)
	sess.approve <- approval
	h.reEnrollMu.Unlock()
	select {
	case got := <-results:
		return got.approvalSent, got.err
	case <-ctx.Done():
		t.Fatalf("waiting for re-enrollment approval result: %v", ctx.Err())
		return false, ctx.Err()
	}
}

func TestWaitForReEnrollSession_DelayedRegistration(t *testing.T) {
	h := &Handler{reEnrollSessions: make(map[string]*reEnrollSession)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})
	go func() {
		defer close(done)
		// Deliberately register later than the former 5 ms lookup.
		timer := time.NewTimer(30 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			registerReEnrollForTest(t, h, "delayed", nil, "fingerprint")
		case <-ctx.Done():
		}
	}()
	sess, err := waitForReEnrollSessionForTest(ctx, h, "delayed")
	if err != nil {
		t.Fatalf("waiting for delayed registration: %v", err)
	}
	if sess.serverID != "delayed" {
		t.Fatalf("expected delayed session, got %s", sess.serverID)
	}
}

func TestWaitForReEnrollSession_MissingRegistration(t *testing.T) {
	h := &Handler{reEnrollSessions: make(map[string]*reEnrollSession)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	sess, err := waitForReEnrollSessionForTest(ctx, h, "missing")
	if sess != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected registration deadline, got session=%v, error=%v", sess, err)
	}
}

// Fixture helpers bind the exact stream and durable request before exercising
// an intended approved-proof state. They never authenticate a normal route.
func registerReEnrollForTest(t *testing.T, h *Handler, serverID string, csr []byte, fingerprint string) *reEnrollSession {
	t.Helper()
	requestID := uuid.NewString()
	if h.store != nil {
		if err := h.store.CreateReEnrollRequest(&model.ReEnrollRequest{ID: requestID, ServerID: serverID, RequestedAt: "2026-10-12 00:00:00", Status: "pending", AnomalyFlags: "{}"}); err != nil {
			t.Fatal(err)
		}
	}
	h.reEnrollMu.Lock()
	defer h.reEnrollMu.Unlock()
	return h.registerReEnrollLocked(serverID, csr, fingerprint, requestID, &mockStream{})
}

func reEnrollRequestIDForTest(h *Handler, serverID string) string {
	if sess, ok := h.lookupReEnroll(serverID); ok {
		return sess.requestID
	}
	return "missing-request"
}

func handleReEnrollProofForTest(t *testing.T, h *Handler, stream *mockStream, serverID string, proof *pb.ReEnrollProof) error {
	t.Helper()
	h.reEnrollMu.Lock()
	if sess := h.reEnrollSessions[serverID]; sess != nil {
		sess.stream, sess.state = stream, reEnrollAwaitingProof
		sess.proofUntil = time.Now().Add(reEnrollProofTimeout)
		if _, err := h.store.GetReEnrollRequest(sess.requestID); err != nil {
			if err := h.store.CreateReEnrollRequest(&model.ReEnrollRequest{ID: sess.requestID, ServerID: serverID, RequestedAt: "2026-10-12 00:00:00", Status: "pending", AnomalyFlags: "{}"}); err != nil {
				h.reEnrollMu.Unlock()
				t.Fatal(err)
			}
		}
	}
	h.reEnrollMu.Unlock()
	return h.handleReEnrollProof(stream, serverID, proof)
}
