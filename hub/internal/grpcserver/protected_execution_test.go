package grpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestDisconnectCleanupPreservesReplacementCapabilitiesAndExecutions(t *testing.T) {
	cm := connmgr.New()
	oldStream := &mockStream{}
	cm.Register("node", oldStream)
	es := NewExecutionSessions(NewTerminalSessions(), cm)
	caps := &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, ProtectedScript: true, BootId: "boot"}
	es.SetCapabilities("node", oldStream, caps)
	oldSession, err := es.Register("node", "old", "actor", "", []byte("id"))
	if err != nil {
		t.Fatal(err)
	}
	defer es.Remove("node", "old")
	if !cm.UnregisterIfCurrent("node", oldStream) {
		t.Fatal("old connection was not removed")
	}
	// Disconnect bookkeeping can pause here while a new authenticated control
	// stream registers and publishes its capabilities.
	newStream := &mockStream{}
	cm.Register("node", newStream)
	es.SetCapabilities("node", newStream, caps)
	newSession, err := es.Register("node", "new", "actor", "", []byte("id"))
	if err != nil {
		t.Fatal(err)
	}
	defer es.Remove("node", "new")
	es.EndConnection("node", oldStream, "agent disconnected")
	if !es.Supports("node") || !es.SupportsProtected("node") {
		t.Fatal("old disconnect erased replacement capabilities")
	}
	select {
	case <-oldSession.Done:
	default:
		t.Fatal("old disconnect retained its execution")
	}
	select {
	case <-newSession.Done:
		t.Fatal("old disconnect cancelled a replacement execution")
	default:
	}
	es.EndConnection("node", newStream, "agent disconnected")
	if es.Supports("node") {
		t.Fatal("current disconnect retained its capability")
	}
	select {
	case <-newSession.Done:
	default:
		t.Fatal("current disconnect retained its execution")
	}
}

func TestProtectedDispatchRequiresCurrentReceiptExpiry(t *testing.T) {
	for _, phase := range []string{"missing", "expired", "past-preparation"} {
		t.Run(phase, func(t *testing.T) {
			s := protectedSession(t, []byte("true\n"))
			expiry := int64(0)
			if phase == "expired" {
				expiry = time.Now().Add(-time.Second).UnixMilli()
			} else if phase == "past-preparation" {
				expiry = s.Binding().ExpiresUnixMilli + 1
			}
			if err := s.DispatchProtected([]byte("verified-fixture"), expiry, "2", bytes.NewReader([]byte("true\n")), func() error { return nil }); err == nil || s.StartAttempted() {
				t.Fatal("invalid receipt authority reached launch dispatch")
			}
		})
	}
}

func TestHandlerBlockedDisconnectPreservesReplacementExecutionRevocations(t *testing.T) {
	h, st := testHandler(t)
	h.notifier = nil
	if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	h.terminals = NewTerminalSessions()
	h.executions = NewExecutionSessions(h.terminals, h.connMgr)
	oldStream := &mockStream{}
	h.connMgr.Register("node", oldStream)
	caps := &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, ProtectedScript: true, BootId: "boot"}
	h.executions.SetCapabilities("node", oldStream, caps)
	oldSession, err := h.executions.Register("node", "old", "actor", "", []byte("id"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.executions.Remove("node", "old")
	st.DB().SetMaxOpenConns(1)
	blocked, err := st.DB().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	finished := make(chan struct{})
	go func() { h.onAgentDisconnected("node", oldStream); close(finished) }()
	deadline := time.Now().Add(time.Second)
	for h.connMgr.GetConn("node") != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.connMgr.GetConn("node") != nil {
		t.Fatal("disconnect did not reach blocked bookkeeping")
	}
	select {
	case <-finished:
		t.Fatal("disconnect did not wait on blocked store")
	default:
	}
	newStream := &mockStream{}
	h.connMgr.Register("node", newStream)
	h.executions.SetCapabilities("node", newStream, caps)
	newSession, err := h.executions.Register("node", "new", "actor", "", []byte("id"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.executions.Remove("node", "new")
	_ = blocked.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("disconnect did not finish after store unblocked")
	}
	if !h.executions.SupportsProtected("node") {
		t.Fatal("old handler cleanup erased replacement capability")
	}
	server, err := st.GetServerByID("node")
	if err != nil || server.Status != "online" {
		t.Fatal("old disconnect made replacement node unavailable to CLI execution")
	}
	select {
	case <-newSession.Done:
		t.Fatal("old handler cleanup cancelled replacement execution")
	default:
	}
	select {
	case <-newSession.Revocations:
		t.Fatal("old terminal cleanup revoked replacement execution")
	default:
	}
	select {
	case <-oldSession.Revocations:
	default:
		t.Fatal("old terminal registration survived its disconnect")
	}
}

func protectedSession(t *testing.T, script []byte) *ExecutionSession {
	t.Helper()
	cm := connmgrForExecutionTest()
	control := cm.GetConn("node").Stream
	es := NewExecutionSessions(NewTerminalSessions(), cm)
	es.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, ProtectedScript: true, BootId: "boot"})
	s, err := es.Register("node", "protected", "actor", "", []byte("sh -s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { es.Remove("node", s.ID) })
	hash := sha256.Sum256(script)
	if err = s.Configure(true, hash[:], uint64(len(script)), DefaultExecutionLimits()); err != nil {
		t.Fatal(err)
	}
	if !es.DeliverPrepared("node", control, preparedForTest(s.ID, "node", []byte("sh -s"))) {
		t.Fatal("protected prepare rejected")
	}
	attach, err := s.IssueAttach()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = es.Attach("node", attach); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestProtectedTransferCompletesBeforeExactStartAndLiveCheck(t *testing.T) {
	script := bytes.Repeat([]byte("x"), 2*MaxExecutionFrameBytes+17)
	s := protectedSession(t, script)
	if err := s.Dispatch(); err == nil {
		t.Fatal("protected preparation downgraded through Standard Dispatch")
	}
	checked := false
	if err := s.DispatchProtected([]byte("independent-verified-fixture"), time.Now().Add(20*time.Second).UnixMilli(), "2", bytes.NewReader(script), func() error { checked = true; return nil }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &executionTestStream{ctx: ctx, sent: make(chan *pb.ExecutionHubMessage, 16)}
	done := make(chan error, 1)
	go func() { done <- sendExecution(stream, s) }()
	var offset uint64
	var complete bool
	var sawStart bool
	for !sawStart {
		select {
		case msg := <-stream.sent:
			if chunk := msg.GetScriptChunk(); chunk != nil {
				if complete || chunk.Offset != offset || !bytes.Equal(chunk.Data, script[offset:offset+uint64(len(chunk.Data))]) {
					t.Fatal("script frames not exact")
				}
				offset += uint64(len(chunk.Data))
			}
			if eof := msg.GetScriptEof(); eof != nil {
				if offset != uint64(len(script)) || eof.Length != offset {
					t.Fatal("premature script EOF")
				}
				complete = true
			}
			if start := msg.GetStart(); start != nil {
				if !complete || !checked || start.PolicyVersion != "2" || len(start.AdmissionReceipt) == 0 || start.AdmissionExpiresUnixMilli <= time.Now().UnixMilli() {
					t.Fatal("Start preceded complete input and live check")
				}
				sawStart = true
			}
		case <-time.After(time.Second):
			t.Fatal("protected transfer stalled")
		}
	}
	s.Cancel("done")
	<-done
}
func TestProtectedTransferFailureCannotSendStart(t *testing.T) {
	for _, failure := range []string{"short", "excess", "hash", "revoked", "expired"} {
		t.Run(failure, func(t *testing.T) {
			script := []byte("marker")
			s := protectedSession(t, script)
			source := script
			check := func() error { return nil }
			switch failure {
			case "short":
				source = script[:3]
			case "excess":
				source = append(append([]byte(nil), script...), 'x')
			case "hash":
				source = []byte("wrong!")
			case "revoked":
				check = func() error { return errors.New("revoked") }
			case "expired":
				check = func() error {
					s.mu.Lock()
					s.prepared.Binding.ExpiresUnixMilli = time.Now().Add(-time.Second).UnixMilli()
					s.mu.Unlock()
					return nil
				}
			}
			if err := s.DispatchProtected([]byte("fixture"), time.Now().Add(20*time.Second).UnixMilli(), "2", bytes.NewReader(source), check); err != nil {
				t.Fatal(err)
			}
			stream := &executionTestStream{sent: make(chan *pb.ExecutionHubMessage, 16)}
			if err := sendExecution(stream, s); err == nil {
				t.Fatal("invalid transfer succeeded")
			}
			if s.StartAttempted() {
				t.Fatal("Start attempted after transfer or live authority failure")
			}
			close(stream.sent)
			for msg := range stream.sent {
				if msg.GetStart() != nil {
					t.Fatal("target Start sent")
				}
			}
		})
	}
}
