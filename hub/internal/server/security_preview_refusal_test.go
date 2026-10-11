package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestGovernanceHTTPPreviewRefusesAmbiguousOrUnsafeProtectedChanges(t *testing.T) {
	h := newGovernanceHTTP(t)
	for _, test := range []struct {
		name    string
		payload model.SecurityChangePayload
		want    int
	}{
		{"missing_policy", model.SecurityChangePayload{Kind: "policy"}, 400},
		{"mixed_role_and_person", model.SecurityChangePayload{Kind: "role", Role: &model.SecurityRoleChange{UserID: "viewer", Role: model.RoleOriginalReader, Grant: true}, Person: &model.SecurityPersonChange{UserID: "viewer", PersonID: "new-person", Verification: "verified"}}, 400},
		{"legacy_role", model.SecurityChangePayload{Kind: "role", Role: &model.SecurityRoleChange{UserID: "viewer", Role: model.RoleAdmin, Grant: true}}, 400},
		{"missing_role_principal", model.SecurityChangePayload{Kind: "role", Role: &model.SecurityRoleChange{Role: model.RoleOriginalReader, Grant: true}}, 400},
		{"unverified_person", model.SecurityChangePayload{Kind: "person", Person: &model.SecurityPersonChange{UserID: "viewer", PersonID: "new-person"}}, 400},
		{"invalid_person_identity", model.SecurityChangePayload{Kind: "person", Person: &model.SecurityPersonChange{UserID: "viewer", PersonID: "new person", Verification: "verified"}}, 400},
		{"unbounded_person_verification", model.SecurityChangePayload{Kind: "person", Person: &model.SecurityPersonChange{UserID: "viewer", PersonID: "new-person", Verification: strings.Repeat("v", 2049)}}, 400},
		{"invalid_audit_retention", model.SecurityChangePayload{Kind: "audit-settings", AuditSettings: &model.AuditSettings{}}, 400},
		{"plaintext_ldap", model.SecurityChangePayload{Kind: "ldap", LDAP: &model.SecurityLDAPSettings{Enabled: true, URL: "ldap://directory.synthetic.invalid"}}, 400},
		{"ambiguous_ldap_credential", model.SecurityChangePayload{Kind: "ldap", LDAP: &model.SecurityLDAPSettings{ClearBindPassword: true, BindCredentialRef: h.policy.CredentialRef}}, 400},
		{"unbounded_ldap_endpoint", model.SecurityChangePayload{Kind: "ldap", LDAP: &model.SecurityLDAPSettings{URL: strings.Repeat("x", 4097)}}, 400},
		{"unbounded_ldap_trust", model.SecurityChangePayload{Kind: "ldap", LDAP: &model.SecurityLDAPSettings{CACertPEM: strings.Repeat("x", 32769)}}, 400},
		{"unknown_recovery_operation", model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "viewer", Operation: "clear-all-credentials"}}, 400},
		{"unversioned_password_recovery", model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "viewer", Operation: "password-reset"}}, 400},
		{"missing_recovery_principal", model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{Operation: "mfa-reset"}}, 400},
		{"unknown_change_kind", model.SecurityChangePayload{Kind: "security-superuser", Role: &model.SecurityRoleChange{UserID: "viewer", Role: model.RoleOriginalReader}}, 400},
		{"nominations_on_role_change", model.SecurityChangePayload{Kind: "role", Role: &model.SecurityRoleChange{UserID: "viewer", Role: model.RoleOriginalReader}, Nominations: []model.SecurityNomination{{UserID: "viewer"}}}, 400},
		{"bootstrap_without_independent_people", model.SecurityChangePayload{Kind: "bootstrap", Policy: &h.policy}, 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			h.call(t, "POST", "/api/security/changes/preview", "officer", authorization.Proposal{Reason: "Unsafe proposal must never acquire a reviewable digest", ExpectedVersion: 1, Change: mustMarshal(t, test.payload)}, test.want)
		})
	}
	for _, test := range []struct {
		name   string
		change func(*model.AuditPolicy)
		want   int
	}{
		{"unknown_profile", func(p *model.AuditPolicy) { p.Profile = "automatic" }, 400},
		{"runtime_outside_bound", func(p *model.AuditPolicy) { p.RuntimeSeconds = 0 }, 400},
		{"retention_below_minimum", func(p *model.AuditPolicy) { p.RetentionHours = 23 }, 400},
		{"duplicate_actor_scope", func(p *model.AuditPolicy) { p.Actors = []string{"viewer", "viewer"} }, 400},
		{"invalid_node_scope", func(p *model.AuditPolicy) { p.Nodes = []string{"unsafe node"} }, 400},
		{"duplicate_receipt_trust", func(p *model.AuditPolicy) { p.TrustKeyIDs = []string{"fixture-key", "fixture-key"} }, 400},
		{"incomplete_enhanced_destination", func(p *model.AuditPolicy) { p.CredentialRef = "" }, 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := h.policy
			test.change(&p)
			h.call(t, "POST", "/api/security/changes/preview", "officer", authorization.Proposal{Reason: "Unsafe enforcement scope must never acquire a digest", ExpectedVersion: 1, Change: mustMarshal(t, model.SecurityChangePayload{Kind: "policy", Policy: &p})}, test.want)
		})
	}
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"reason":"review","expected_version":1,"change":{"Kind":"role","role":{"user_id":"viewer","role":"original-reader","grant":true}}}`),
		json.RawMessage(`{"reason":"review","expected_version":1,"change":{"kind":"role","kind":"person","role":{"user_id":"viewer","role":"original-reader","grant":true}}}`),
		json.RawMessage(`{"reason":"review","expected_version":1,"change":{"kind":"recovery","recovery":{"user_id":"viewer","operation":"password-reset","secret_ref":"secret:version-1","prepared_password_hash":"attacker-supplied"}}}`),
	} {
		h.call(t, "POST", "/api/security/changes/preview", "officer", raw, http.StatusBadRequest)
	}
	for _, proposal := range []authorization.Proposal{
		{Reason: " ", ExpectedVersion: 1},
		{Reason: strings.Repeat("r", 2049), ExpectedVersion: 1},
		{Reason: "review", ExpectedVersion: 0},
	} {
		proposal.Change = mustMarshal(t, model.SecurityChangePayload{Kind: "policy", Policy: &h.policy})
		h.call(t, "POST", "/api/security/changes/preview", "officer", proposal, http.StatusBadRequest)
	}
	changes, err := h.s.store.ListSecurityChanges(100, 0)
	state, stateErr := h.s.store.GetPolicyState()
	if err != nil || stateErr != nil || len(changes) != 0 || state.Active.Version != 1 || state.Pending != nil || state.State != "standard" || len(h.archive.Governance.Envelopes()) != 0 {
		t.Fatalf("refused previews changed protected state: changes%d state%+v errors%v/%v", len(changes), state, err, stateErr)
	}
}
