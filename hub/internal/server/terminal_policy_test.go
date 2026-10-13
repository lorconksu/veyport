package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

type policyTerminalStream struct {
	pb.AgentService_ConnectServer
	messages chan *pb.HubMessage
	pending  *grpcserver.PendingRequests
	node     string
	ack      bool
}

func (s *policyTerminalStream) Send(m *pb.HubMessage) error {
	s.messages <- m
	if open := m.GetTerminalOpenRequest(); open != nil && s.ack {
		s.pending.Deliver(s.node, open.SessionId, &pb.TerminalOpenAck{SessionId: open.SessionId, Success: true})
	}
	return nil
}
func (s *policyTerminalStream) Context() context.Context { return context.Background() }
func nextPolicyTerminalMessage(t *testing.T, s *policyTerminalStream) *pb.HubMessage {
	t.Helper()
	select {
	case m := <-s.messages:
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("agent terminal message missing")
		return nil
	}
}
func policyTerminalRequest(t *testing.T, s *Server, token, node, method, suffix string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, testServersPrefix+node+testTerminalSessionsSuffix+suffix, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}
func TestActualWebPolicyRecoveryCancelsPendingOpen(t *testing.T) {
	s, token, node := testServerWithAgent(t)
	stream := &policyTerminalStream{messages: make(chan *pb.HubMessage, 10), pending: s.pending, node: node}
	s.connMgr.Register(node, stream)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- policyTerminalRequest(t, s, token, node, "POST", "", strings.NewReader(`{"cols":80,"rows":24}`))
	}()
	open := nextPolicyTerminalMessage(t, stream).GetTerminalOpenRequest()
	if open == nil {
		t.Fatal("expected original Standard open")
	}
	if err := s.store.RequirePolicyRecovery(); err != nil {
		t.Fatal(err)
	}
	select {
	case rec := <-done:
		if rec.Code != http.StatusForbidden {
			t.Fatalf("pending web open returned %d: %s", rec.Code, rec.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("policy did not cancel pending web open")
	}
	close := nextPolicyTerminalMessage(t, stream).GetTerminalClose()
	if close == nil || close.SessionId != open.SessionId {
		t.Fatal("policy did not close exact pending web shell")
	}
	if _, ok := s.terminalSessions.Get(node, open.SessionId); ok {
		t.Fatal("cancelled pending web open leaked registration")
	}
}

type policyChangeReader struct {
	io.Reader
	once   sync.Once
	change func()
}

func (r *policyChangeReader) Read(p []byte) (int, error) {
	r.once.Do(r.change)
	return r.Reader.Read(p)
}
func TestActualWebInputRevalidatesAfterRequestBody(t *testing.T) {
	s, token, node := testServerWithAgent(t)
	stream := &policyTerminalStream{messages: make(chan *pb.HubMessage, 10), pending: s.pending, node: node, ack: true}
	s.connMgr.Register(node, stream)
	id := createTerminalSessionForTest(t, s, token, node)
	if nextPolicyTerminalMessage(t, stream).GetTerminalOpenRequest() == nil {
		t.Fatal("Standard shell did not open")
	}
	body := &policyChangeReader{Reader: strings.NewReader(`{"data":"probe\\n"}`), change: func() {
		if err := s.store.RequirePolicyRecovery(); err != nil {
			t.Fatal(err)
		}
	}}
	rec := policyTerminalRequest(t, s, token, node, "POST", "/"+id+"/input", body)
	if rec.Code == http.StatusAccepted {
		t.Fatal("raw input accepted after policy changed during body decode")
	}
	if nextPolicyTerminalMessage(t, stream).GetTerminalClose() == nil {
		t.Fatal("covered web shell did not close")
	}
	select {
	case m := <-stream.messages:
		if m.GetTerminalInput() != nil {
			t.Fatal("covered raw input reached agent")
		}
	default:
	}
}

type policyCommitFailureEvidence struct{ authorization.Evidence }

func (e policyCommitFailureEvidence) Preserve(ctx context.Context, raw []byte) (string, error) {
	var event auditrecord.Envelope
	if err := json.Unmarshal(raw, &event); err != nil {
		return "", err
	}
	if event.EventType == auditrecord.PolicyCommit {
		return "", errors.New("local fixture commit outage")
	}
	return e.Evidence.Preserve(ctx, raw)
}
func TestActualWebPendingEnhancedCommitFailureClosesUnattachedShell(t *testing.T) {
	h := newGovernanceHTTP(t)
	h.s.connMgr = connmgr.New()
	h.s.pending = grpcserver.NewPendingRequests()
	h.s.terminalSessions = grpcserver.NewTerminalSessions()
	stream := &policyTerminalStream{messages: make(chan *pb.HubMessage, 10), pending: h.s.pending, node: "synthetic-node", ack: true}
	h.s.connMgr.Register("synthetic-node", stream)
	t.Cleanup(func() { h.s.connMgr.Unregister("synthetic-node") })
	raw := h.call(t, "POST", "/api/servers/synthetic-node/terminal/sessions", "officer", map[string]int{"cols": 80, "rows": 24}, http.StatusCreated)
	var shell model.TerminalSessionResponse
	decodeResult(t, raw, &shell)
	if nextPolicyTerminalMessage(t, stream).GetTerminalOpenRequest() == nil {
		t.Fatal("initial Standard web shell did not open")
	}
	change := h.approve(t, h.request(t, h.bootstrapPayload(), 1))
	h.s.securityTransition.Evidence = policyCommitFailureEvidence{h.s.securityTransition.Evidence}
	h.apply(t, change, http.StatusBadRequest)
	state, err := h.s.store.GetPolicyState()
	if err != nil || state.Pending == nil || state.Active.Version != 1 {
		t.Fatalf("expected failed pending Enhanced transition: %+v %v", state, err)
	}
	info, ok := h.s.terminalSessions.Get("synthetic-node", shell.SessionID)
	if !ok || !info.Closed {
		t.Fatal("failed pending transition left unattached covered shell live")
	}
	close := nextPolicyTerminalMessage(t, stream).GetTerminalClose()
	if close == nil || close.SessionId != shell.SessionID {
		t.Fatal("unattached shell was not closed at pending boundary")
	}
}

func TestActualWebExplicitCloseRemainsHubInitiated(t *testing.T) {
	s, token, node := testServerWithAgent(t)
	id := createTerminalSessionForTest(t, s, token, node)
	rec := policyTerminalRequest(t, s, token, node, "DELETE", "/"+id, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("explicit close: %d %s", rec.Code, rec.Body.String())
	}
	action := model.AuditTerminalClosed
	logs, _, err := s.store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range logs {
		if entry.Detail != nil && strings.Contains(*entry.Detail, id) {
			found = true
			if strings.Contains(*entry.Detail, "agent_initiated") {
				t.Fatal("explicit Hub close was attributed to agent")
			}
		}
	}
	if !found {
		t.Fatal("explicit close audit missing")
	}
}
