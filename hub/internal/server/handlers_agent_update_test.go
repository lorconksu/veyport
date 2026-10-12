package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
)

func updateHTTPFixture(t *testing.T) (*Server, string, string) {
	t.Helper()
	s, _, node := testServerWithAgent(t)
	if err := s.store.ActivateServer(node, "node", "127.0.0.1", "linux", "0.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpdateServerStatus(node, "online"); err != nil {
		t.Fatal(err)
	}
	user, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	token, _, _ := sessionTokenPair(t, s, user.ID)
	u, err := grpcserver.NewAgentUpdates(s.store, s.connMgr, s.terminalSessions)
	if err != nil {
		t.Fatal(err)
	}
	u.SetArtifactResolver(func(osName, arch string) (model.AgentArtifact, error) {
		return model.AgentArtifact{OS: osName, Arch: arch, Version: "2.0.1-prototype.4", Revision: strings.Repeat("f", 40), SHA256: strings.Repeat("a", 64), Bytes: 100}, nil
	})
	s.agentUpdates = u
	return s, token, node
}
func updateHTTPRequest(s *Server, token, node, method, suffix, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/servers/"+node+"/agent-update"+suffix, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}
func TestAgentUpdateRESTCheckStartStatusAndClosedInput(t *testing.T) {
	s, token, node := updateHTTPFixture(t)
	rec := updateHTTPRequest(s, token, node, "GET", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"bootstrap_required":true`) {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var count int
	if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM agent_updates").Scan(&count); err != nil || count != 0 {
		t.Fatal("REST check mutated operation")
	}
	for _, body := range []string{`{}`, `{"expected_version":"2.0.1-prototype.4","expected_revision":"` + strings.Repeat("f", 40) + `","url":"https://arbitrary"}`, `{"expected_version":"2.0.1-prototype.4","expected_version":"2.0.2","expected_revision":"x"}`, `{"expected_version":"2.0.1-prototype.4","expected_revision":"x"} {}`} {
		rec = updateHTTPRequest(s, token, node, "POST", "", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatal("accepted ambiguous/arbitrary payload", body, rec.Code, rec.Body.String())
		}
	}
	rec = updateHTTPRequest(s, token, node, "POST", "", `{"expected_version":"2.0.1-prototype.4","expected_revision":"`+strings.Repeat("f", 40)+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var response struct {
		Operation model.AgentUpdate `json:"operation"`
		Ticket    string            `json:"bootstrap_ticket"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || len(response.Ticket) != 64 {
		t.Fatal("missing bootstrap response", err, rec.Body.String())
	}
	rec = updateHTTPRequest(s, token, node, "GET", "/status?operation_id="+response.Operation.ID, "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), response.Ticket) || strings.Contains(rec.Body.String(), "ticket_hash") {
		t.Fatal("status revealed ticket or failed", rec.Code, rec.Body.String())
	}
	rec = updateHTTPRequest(s, token, node, "POST", "/recovery", `{"operation_id":"`+response.Operation.ID+`","verified_sha256":"x"}`)
	if rec.Code != http.StatusConflict {
		t.Fatal("unqualified recovery accepted", rec.Code)
	}
	rec = updateHTTPRequest(s, token, node, "POST", "/recovery", `{"operation_id":"x","binary":"arbitrary"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatal("recovery accepted unknown field")
	}
	if _, err := s.ResolveAgentArtifact("windows", "amd64"); err == nil {
		t.Fatal("unsupported artifact resolver platform")
	}
}
func TestAgentUpdateRESTRequiresInteractiveAdminAndServiceAvailability(t *testing.T) {
	s, token, node := updateHTTPFixture(t)
	apiToken := createAdminAPIToken(t, s)
	for _, method := range []string{"GET", "POST"} {
		rec := updateHTTPRequest(s, apiToken, node, method, "", `{"expected_version":"x","expected_revision":"y"}`)
		if rec.Code != http.StatusForbidden {
			t.Fatal("API token reached maintenance", rec.Code, rec.Body.String())
		}
	}
	rec := updateHTTPRequest(s, "", node, "GET", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated maintenance accepted")
	}
	s.agentUpdates = nil
	rec = updateHTTPRequest(s, token, node, "GET", "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatal("missing maintenance service not explicit", rec.Code)
	}
	request := httptest.NewRequest("GET", "/install/agent-update.sh", nil)
	rec = httptest.NewRecorder()
	s.routes().ServeHTTP(rec, request)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "--ticket") {
		t.Fatal("preserving bootstrap script unavailable", rec.Code)
	}
}
