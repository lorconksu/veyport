package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestAgentUpdateRESTRefusesStaleArtifactAndCrossNodeStatus(t *testing.T) {
	s, token, node := updateHTTPFixture(t)
	rec := updateHTTPRequest(s, token, node, "POST", "", `{"expected_version":"2.0.1-prototype.3","expected_revision":"`+strings.Repeat("f", 40)+`"}`)
	if rec.Code != http.StatusConflict {
		t.Fatal("stale checked artifact accepted", rec.Code, rec.Body.String())
	}
	var count int
	if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM agent_updates").Scan(&count); err != nil || count != 0 {
		t.Fatal("stale request created an operation")
	}
	for _, suffix := range []string{"/status", "/status?operation_id=missing"} {
		rec = updateHTTPRequest(s, token, node, "GET", suffix, "")
		if rec.Code != http.StatusNotFound {
			t.Fatal("missing operation was not explicit", rec.Code, rec.Body.String())
		}
	}
	op := model.AgentUpdate{ID: "other-operation", NodeID: "other-node", State: "succeeded"}
	if err := s.store.CreateAgentUpdate(op); err != nil {
		t.Fatal(err)
	}
	rec = updateHTTPRequest(s, token, node, "GET", "/status?operation_id="+op.ID, "")
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), op.NodeID) {
		t.Fatal("cross-node status disclosed authority", rec.Code, rec.Body.String())
	}
}

func TestAgentUpdateRESTPolicyRecoveryRefusesCheckAndMutation(t *testing.T) {
	s, token, node := updateHTTPFixture(t)
	if err := s.store.RequirePolicyRecovery(); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "POST"} {
		rec := updateHTTPRequest(s, token, node, method, "", `{"expected_version":"2.0.1-prototype.4","expected_revision":"`+strings.Repeat("f", 40)+`"}`)
		if rec.Code != http.StatusForbidden {
			t.Fatal("policy recovery allowed maintenance", method, rec.Code, rec.Body.String())
		}
	}
}

func TestAgentUpdateRESTRecoveryReturnsExplicitAttestationAndReleasesOnlyItsLease(t *testing.T) {
	s, token, node := updateHTTPFixture(t)
	claims, err := auth.ValidateToken(s.jwtSecret, token)
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	op := model.AgentUpdate{ID: "recover-operation", NodeID: node, ActorID: claims.Subject, SessionID: claims.SessionID, State: "unknown", PreviousSHA256: hash, ExpiresAt: time.Now().UnixMilli() - 190001}
	if err = s.store.CreateAgentUpdate(op); err != nil {
		t.Fatal(err)
	}
	s.connMgr.SetMaintenance(node, op.ID)
	s.terminalSessions.SetMaintenance(node, op.ID)
	rec := updateHTTPRequest(s, token, node, "POST", "/recovery", `{"operation_id":"`+op.ID+`","verified_sha256":"`+hash+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatal("qualified recovery refused", rec.Code, rec.Body.String())
	}
	var result model.AgentUpdate
	if err = json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.State != "recovery_acknowledged" || result.ObservedSHA256 != "" || result.ObservedVersion != "" {
		t.Fatal("recovery fabricated confirmed artifact", result, err)
	}
	if _, ok := s.terminalSessions.Register(node, "after-recovery", claims.Subject, ""); !ok {
		t.Fatal("accepted recovery retained its own maintenance lease")
	}
	s.agentUpdates = nil
	for _, entry := range []struct{ method, suffix, body string }{{"POST", "", `{}`}, {"GET", "/status", ""}, {"POST", "/recovery", `{}`}} {
		rec = updateHTTPRequest(s, token, node, entry.method, entry.suffix, entry.body)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatal("unavailable update service route was not explicit", entry, rec.Code)
		}
	}
}
