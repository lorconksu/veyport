package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auditruntime"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/testaudit"
	"github.com/wyiu/veyport/proto/protectedinput"
)

type governanceTestSpool struct{ failed bool }

func (s *governanceTestSpool) Ready() error {
	if s.failed {
		return protectedinput.ErrUnavailable
	}
	return nil
}
func (*governanceTestSpool) Create() (protectedinput.File, error) {
	return nil, protectedinput.ErrUnavailable
}

type governanceHTTP struct {
	s         *Server
	api       *httptest.Server
	archive   *testaudit.Fixture
	runtime   *auditruntime.Runtime
	clock     *testaudit.Clock
	spool     *governanceTestSpool
	protected bool
	users     map[string]*model.User
	secrets   map[string]string
	tokens    map[string]string
	clients   map[string]*http.Client
	policy    model.AuditPolicy
}

func newGovernanceHTTP(t *testing.T) *governanceHTTP {
	t.Helper()
	s := testServer(t)
	clock := testaudit.NewClock()
	s.SetClock(clock.Now)
	h := &governanceHTTP{s: s, clock: clock, spool: &governanceTestSpool{}, protected: true, users: map[string]*model.User{}, secrets: map[string]string{}, tokens: map[string]string{}, clients: map[string]*http.Client{}}
	h.archive = testaudit.New(t, clock)
	if err := s.store.CreateServer(&model.Server{ID: "synthetic-node", Name: "Synthetic unit-test node", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	password := "Synthetic-Test1!"
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"officer", "approver-a", "approver-b", "viewer"} {
		key, err := auth.GenerateTOTPSecret(id, "synthetic-governance-tests")
		if err != nil {
			t.Fatal(err)
		}
		secret := key.Secret()
		h.secrets[id] = secret
		encoded, err := s.encryptTOTPSecret(secret)
		if err != nil {
			t.Fatal(err)
		}
		role := model.RoleViewer
		if id == "officer" {
			role = model.RoleAdmin
		}
		u := &model.User{ID: id, Username: id, Email: id + "@synthetic.test.invalid", Role: role, PasswordHash: passwordHash, TOTPSecret: &encoded, TOTPEnabled: true, AuthProvider: model.AuthProviderLocal}
		if err = s.store.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		h.users[id] = u
	}
	h.runtime, err = auditruntime.Load(h.archive.ConfigFile(t), auditruntime.Options{Store: s.store, Spool: h.spool, GatewayReady: func() bool { return true }, SupportsProtected: func(string) bool { return h.protected }, ResolveSecret: s.resolveSecuritySecret, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "security")
	installation, err := authorization.InitInstallation(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.securityTransition.Evidence = h.runtime.Evidence()
	s.securityTransition.InstallationID = installation
	s.securityTransition.EnrollmentPath = filepath.Join(dir, "enhanced-enrollment.json")
	s.securityDestinationTester = h.runtime
	s.securityAllowedHosts = h.runtime.AllowedHosts()
	h.api = httptest.NewServer(s.routes())
	t.Cleanup(h.api.Close)
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	for n, id := range []string{"officer", "approver-a", "approver-b", "viewer"} {
		transport := &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, byte(n+2))}}).DialContext}
		h.clients[id] = &http.Client{Transport: transport, Timeout: 15 * time.Second}
		t.Cleanup(transport.CloseIdleConnections)
		response := h.call(t, "POST", "/api/auth/login", id, model.LoginRequest{Username: id, Password: password}, http.StatusAccepted)
		var primary model.LoginResponse
		decodeResult(t, response, &primary)
		code, err := totp.GenerateCode(h.secrets[id], clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		response = h.call(t, "POST", "/api/auth/login/totp", id, model.LoginTOTPRequest{TOTPToken: primary.TOTPToken, Code: code}, http.StatusOK)
		var signedIn model.AuthResponse
		decodeResult(t, response, &signedIn)
		if signedIn.AccessToken == "" || signedIn.User.ID != id {
			t.Fatal("real password+MFA login did not establish session")
		}
		h.tokens[id] = signedIn.AccessToken
	}
	credential, _ := json.Marshal(h.archive.Credential)
	secretResponse := h.call(t, "POST", "/api/security/secrets", "officer", map[string]string{"kind": "destination", "value": string(credential)}, http.StatusCreated)
	var secret struct {
		Ref string `json:"credential_ref"`
	}
	decodeResult(t, secretResponse, &secret)
	if secret.Ref == "" || bytes.Contains(secretResponse, []byte("private_key")) || bytes.Contains(secretResponse, []byte("CERTIFICATE")) {
		t.Fatal("write-only credential exposed")
	}
	h.policy = model.AuditPolicy{Profile: "enhanced", Nodes: []string{"synthetic-node"}, RuntimeSeconds: 60, RetentionHours: 24, Destination: h.archive.Config.Endpoint, CredentialRef: secret.Ref, TrustKeyIDs: []string{"fixture-key"}, QualificationSHA256: h.archive.Config.QualificationSHA256}
	return h
}

func decodeResult(t *testing.T, raw []byte, dst any) {
	t.Helper()
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("response JSON: %v (%s)", err, raw)
	}
}
func (h *governanceHTTP) call(t *testing.T, method, path, actor string, body any, want int) []byte {
	t.Helper()
	var raw []byte
	if body != nil {
		raw = mustMarshal(t, body)
	}
	req, err := http.NewRequest(method, h.api.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if actor != "" {
		token := h.tokens[actor]
		if token == "" {
			token = actor
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	client := h.clients[actor]
	if client == nil {
		client = h.api.Client()
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, 256<<10))
	if err != nil {
		t.Fatal(err)
	}
	if want != 0 && response.StatusCode != want {
		t.Fatalf("%s %s: got%d want%d: %s", method, path, response.StatusCode, want, result)
	}
	if want == 0 && response.StatusCode < 400 {
		t.Fatalf("%s %s unexpectedly succeeded: %s", method, path, result)
	}
	return result
}
func (h *governanceHTTP) stepup(t *testing.T, actor, action, digest, id string) string {
	t.Helper()
	h.clock.Advance(30 * time.Second)
	code, err := totp.GenerateCode(h.secrets[actor], h.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	response := h.call(t, "POST", "/api/security/step-up", actor, map[string]string{"action": action, "digest": digest, "code": code, "change_id": id}, 200)
	var proof struct {
		Proof string `json:"proof"`
	}
	decodeResult(t, response, &proof)
	if proof.Proof == "" {
		t.Fatal("fresh MFA did not issue proof")
	}
	return proof.Proof
}

func (h *governanceHTTP) reloginNominees(t *testing.T) {
	t.Helper()
	for _, actor := range []string{"officer", "approver-a", "approver-b"} {
		h.login(t, actor, "Synthetic-Test1!")
	}
}

func (h *governanceHTTP) login(t *testing.T, actor, password string) {
	t.Helper()
	h.clock.Advance(30 * time.Second)
	response := h.call(t, "POST", "/api/auth/login", actor, model.LoginRequest{Username: actor, Password: password}, 202)
	var primary model.LoginResponse
	decodeResult(t, response, &primary)
	code, err := totp.GenerateCode(h.secrets[actor], h.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	response = h.call(t, "POST", "/api/auth/login/totp", actor, model.LoginTOTPRequest{TOTPToken: primary.TOTPToken, Code: code}, 200)
	var login model.AuthResponse
	decodeResult(t, response, &login)
	h.tokens[actor] = login.AccessToken
}
func (h *governanceHTTP) bootstrapPayload() model.SecurityChangePayload {
	return model.SecurityChangePayload{Kind: "bootstrap", Policy: &h.policy, Nominations: []model.SecurityNomination{{UserID: "officer", PersonID: "synthetic-person-officer", Roles: []model.Role{model.RoleSecurityOfficer}, Verification: "Synthetic unit test nomination, never staging approval"}, {UserID: "approver-a", PersonID: "synthetic-person-a", Roles: []model.Role{model.RoleSecurityApprover}, Verification: "Synthetic unit test nomination, never staging approval"}, {UserID: "approver-b", PersonID: "synthetic-person-b", Roles: []model.Role{model.RoleSecurityApprover}, Verification: "Synthetic unit test nomination, never staging approval"}}}
}
func (h *governanceHTTP) request(t *testing.T, payload model.SecurityChangePayload, version uint64) model.SecurityChange {
	t.Helper()
	changeRaw := mustMarshal(t, payload)
	response := h.call(t, "POST", "/api/security/changes/preview", "officer", authorization.Proposal{Reason: "Synthetic governance behavior test", ExpectedVersion: version, Change: changeRaw}, 200)
	var preview authorization.Preview
	decodeResult(t, response, &preview)
	proof := h.stepup(t, "officer", authorization.ActionRequest, preview.Digest, "")
	response = h.call(t, "POST", "/api/security/changes", "officer", map[string]any{"reason": preview.Proposal.Reason, "expected_version": preview.Proposal.ExpectedVersion, "change": json.RawMessage(preview.Proposal.Change), "step_up_proof": proof}, 201)
	var change model.SecurityChange
	decodeResult(t, response, &change)
	return change
}
func (h *governanceHTTP) approve(t *testing.T, change model.SecurityChange) model.SecurityChange {
	t.Helper()
	for _, actor := range []string{"approver-a", "approver-b"} {
		proof := h.stepup(t, actor, authorization.ActionApprove, change.Digest, change.ID)
		response := h.call(t, "POST", "/api/security/changes/"+change.ID+"/approve", actor, map[string]string{"step_up_proof": proof}, 200)
		decodeResult(t, response, &change)
	}
	if change.State != "approved" || len(change.Approvals) != 2 {
		t.Fatal("three-person quorum incomplete")
	}
	return change
}
func (h *governanceHTTP) apply(t *testing.T, change model.SecurityChange, want int) model.SecurityChange {
	t.Helper()
	proof := h.stepup(t, "officer", authorization.ActionApply, change.Digest, change.ID)
	response := h.call(t, "POST", "/api/security/changes/"+change.ID+"/apply", "officer", map[string]string{"step_up_proof": proof}, want)
	if want == 200 {
		decodeResult(t, response, &change)
	}
	payload, _ := authorization.DecodeChange(change.Payload)
	state, err := h.s.store.GetPolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if payload.Kind == "bootstrap" && state.Active.Version == change.ExpectedVersion+1 {
		// Approved role/person installation revokes old authority credentials.
		// The next requests use real new password+MFA sessions.
		h.reloginNominees(t)
	}
	return change
}

func TestGovernanceHTTPThreePeopleFreshMFAExternalReceiptAndPolicyRead(t *testing.T) {
	h := newGovernanceHTTP(t)
	h.call(t, "POST", "/api/audit-policy/test", "officer", h.policy, 200)
	change := h.approve(t, h.request(t, h.bootstrapPayload(), 1))
	before := len(h.archive.Originals.Envelopes())
	h.call(t, "GET", "/api/audit-policy", "officer", nil, 200)
	h.call(t, "GET", "/api/security/changes?limit=10&offset=0", "officer", nil, 200)
	h.call(t, "GET", "/api/security/changes/"+change.ID, "approver-a", nil, 200)
	if len(h.archive.Originals.Envelopes()) != before {
		t.Fatal("viewing governance performed writes")
	}
	change = h.apply(t, change, 200)
	if change.State != "applied" || change.IntentRef == "" || change.CommitRef == "" || change.ResultRef == "" {
		t.Fatalf("application lacked verified receipt references: %+v", change)
	}
	state, err := h.s.store.GetPolicyState()
	if err != nil || state.Active.Version != 2 || state.Active.Policy.Profile != "enhanced" || state.Pending != nil {
		t.Fatalf("active policy: %+v %v", state, err)
	}
	latest, err := h.runtime.Evidence().Anchor(context.Background(), h.s.securityTransition.InstallationID)
	if err != nil || latest.Version != 2 || latest.SHA256 != state.Active.SHA256 {
		t.Fatalf("external latest anchor: %+v %v", latest, err)
	}
	var intent *auditrecord.Envelope
	for _, record := range h.archive.Governance.Envelopes() {
		if record.EventID == change.ID+"-policy.intent" {
			r := record
			intent = &r
		}
	}
	stored, err := h.s.store.GetSecurityChange(change.ID)
	if err != nil {
		t.Fatal(err)
	}
	if intent == nil || intent.Details.Requester.UserID != "officer" || intent.Actor.UserID != "officer" || len(intent.Details.Approvals) != 2 || !bytes.Equal(intent.Details.ApprovedChange, stored.ApprovedBytes) || auditrecord.Hash(intent.Details.ApprovedChange) != change.Digest {
		t.Fatal("archived intent lost exact approved bytes/quorum/actor")
	}
	before = len(h.archive.Originals.Envelopes())
	response := h.call(t, "GET", "/api/audit-policy", "viewer", nil, 200)
	if bytes.Contains(response, []byte("destination")) || bytes.Contains(response, []byte("credential_ref")) {
		t.Fatal("viewer received full security policy")
	}
	h.call(t, "GET", "/api/audit-policy", "officer", nil, 200)
	if len(h.archive.Originals.Envelopes()) != before {
		t.Fatal("active readiness polling wrote records")
	}
	h.call(t, "POST", "/api/audit-policy/test", "viewer", h.policy, 403)
	h.call(t, "GET", "/api/security/changes", "viewer", nil, 403)
	h.call(t, "POST", "/api/security/changes/"+change.ID+"/reconcile", "viewer", nil, 403)
	h.call(t, "POST", "/api/security/changes/"+change.ID+"/reconcile", "officer", nil, 200)
}

func TestGovernanceHTTPActivationFailuresPreserveOldPolicy(t *testing.T) {
	for _, fault := range []string{"ready", "ingest", "receipt", "spool", "agent"} {
		t.Run(fault, func(t *testing.T) {
			h := newGovernanceHTTP(t)
			change := h.approve(t, h.request(t, h.bootstrapPayload(), 1))
			if fault == "spool" {
				h.spool.failed = true
			} else if fault == "agent" {
				h.protected = false
			} else {
				h.archive.SetFault(fault)
			}
			h.apply(t, change, 0)
			state, err := h.s.store.GetPolicyState()
			if err != nil || state.Active.Version != 1 || state.Pending != nil {
				t.Fatalf("failed activation changed policy: %+v %v", state, err)
			}
			if len(h.archive.Governance.Envelopes()) != 0 {
				t.Fatal("failed candidate archived governance intent")
			}
			h.spool.failed = false
			h.protected = true
			h.archive.SetFault("")
			h.apply(t, change, 200)
		})
	}
}

func TestGovernanceHTTPUncertainResultRequiresFixedAnchorThenHistoricalRecovery(t *testing.T) {
	h := newGovernanceHTTP(t)
	change := h.approve(t, h.request(t, h.bootstrapPayload(), 1))
	h.archive.SetFault("result-uncertain")
	h.apply(t, change, 0)
	state, err := h.s.store.GetPolicyState()
	if err != nil || state.Active.Version != 2 || state.Pending == nil {
		t.Fatalf("uncertain result not retained pending: %+v %v", state, err)
	}
	if _, err = h.s.securityService().PolicyForExecution("officer", "synthetic-node"); !errors.Is(err, authorization.ErrTransition) {
		t.Fatalf("uncertain covered execution opened: %v", err)
	}
	h.archive.SetFault("anchor")
	h.call(t, "POST", "/api/security/changes/"+change.ID+"/reconcile", "officer", nil, 0)
	stored, err := h.s.store.GetSecurityChange(change.ID)
	if err != nil || stored.State != "applying" {
		t.Fatalf("anchor outage finalized: %+v %v", stored, err)
	}
	h.archive.SetFault("")
	h.clock.Advance(25 * time.Hour)
	h.archive.Originals.SetFailed(true)
	if err = h.s.securityService().Startup(context.Background(), h.s.securityTransition); err != nil {
		t.Fatalf("historical governance recovery depended on expired originals: %v", err)
	}
	stored, err = h.s.store.GetSecurityChange(change.ID)
	if err != nil || stored.State != "applied" || stored.ResultRef == "" {
		t.Fatalf("historical result not reconciled: %+v %v", stored, err)
	}
	state, err = h.s.store.GetPolicyState()
	if err != nil || state.Pending != nil || state.State != "enhanced" {
		t.Fatalf("recovery state: %+v %v", state, err)
	}
	count := 0
	for _, record := range h.archive.Governance.Envelopes() {
		if record.EventID == change.ID+"-policy.result" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("reconciliation duplicated immutable result: %d", count)
	}
}

func TestGovernanceHTTPDisablePreservesGovernanceWithoutAgentAvailability(t *testing.T) {
	h := newGovernanceHTTP(t)
	if err := h.s.store.UpdateUserRole("viewer", model.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	h.login(t, "viewer", "Synthetic-Test1!")
	initial := h.call(t, "GET", "/api/audit-policy", "viewer", nil, 200)
	if !bytes.Contains(initial, []byte(`"governance_enrolled":false`)) || !bytes.Contains(initial, []byte(`"policy"`)) {
		t.Fatal("initial operations admin cannot inspect bootstrap policy")
	}
	h.apply(t, h.approve(t, h.request(t, h.bootstrapPayload(), 1)), 200)
	p := h.policy
	p.Profile = "standard"
	change := h.approve(t, h.request(t, model.SecurityChangePayload{Kind: "policy", Policy: &p}, 2))
	h.protected = false
	h.spool.failed = true
	h.apply(t, change, 200)
	state, err := h.s.store.GetPolicyState()
	if err != nil || state.Active.Version != 3 || state.Active.Policy.Profile != "standard" {
		t.Fatalf("disable unnecessarily depended on agent: %+v %v", state, err)
	}
	summary := h.call(t, "GET", "/api/audit-policy", "viewer", nil, 200)
	if !bytes.Contains(summary, []byte(`"governance_enrolled":true`)) || bytes.Contains(summary, []byte(`"policy"`)) {
		t.Fatal("Standard disable restored bootstrap-admin policy visibility")
	}
	h.call(t, "GET", "/api/security/changes", "viewer", nil, 403)
	h.call(t, "POST", "/api/security/secrets", "viewer", map[string]string{"kind": "destination", "value": "unauthorized-bootstrap-secret"}, 403)
	h.call(t, "POST", "/api/audit-policy/test", "viewer", p, 403)
	response := h.call(t, "POST", "/api/security/changes/preview", "officer", authorization.Proposal{Reason: "Attempt repeated bootstrap", ExpectedVersion: 3, Change: mustMarshal(t, h.bootstrapPayload())}, 200)
	var preview authorization.Preview
	decodeResult(t, response, &preview)
	proof := h.stepup(t, "officer", authorization.ActionRequest, preview.Digest, "")
	h.call(t, "POST", "/api/security/changes", "officer", map[string]any{"reason": preview.Proposal.Reason, "expected_version": 3, "change": json.RawMessage(preview.Proposal.Change), "step_up_proof": proof}, 403)
	latest, err := h.runtime.Evidence().Anchor(context.Background(), h.s.securityTransition.InstallationID)
	if err != nil || latest.Version != 3 {
		t.Fatalf("disable erased governance continuity: %+v %v", latest, err)
	}
}

func TestGovernanceHTTPDestinationPermissionAndImmutableRequestFailures(t *testing.T) {
	h := newGovernanceHTTP(t)
	bad := h.policy
	bad.Destination = "https://127.0.0.1:1"
	h.call(t, "POST", "/api/audit-policy/test", "officer", bad, 403)
	bad = h.policy
	bad.TrustKeyIDs = []string{"unapproved-key"}
	h.call(t, "POST", "/api/audit-policy/test", "officer", bad, 503)
	h.call(t, "POST", "/api/security/secrets", "viewer", map[string]string{"kind": "destination", "value": "hidden"}, 403)
	h.call(t, "POST", "/api/security/secrets", "officer", map[string]string{"kind": "invalid", "value": "hidden"}, 400)
	previewResponse := h.call(t, "POST", "/api/security/changes/preview", "officer", authorization.Proposal{Reason: "Exact approved reason", ExpectedVersion: 1, Change: mustMarshal(t, h.bootstrapPayload())}, 200)
	var preview authorization.Preview
	decodeResult(t, previewResponse, &preview)
	proof := h.stepup(t, "officer", authorization.ActionRequest, preview.Digest, "")
	h.call(t, "POST", "/api/security/changes", "officer", map[string]any{"reason": "Edited reason", "expected_version": 1, "change": json.RawMessage(preview.Proposal.Change), "step_up_proof": proof}, 403)
	response := h.call(t, "POST", "/api/security/changes", "officer", map[string]any{"reason": preview.Proposal.Reason, "expected_version": 1, "change": json.RawMessage(preview.Proposal.Change), "step_up_proof": proof}, 201)
	var change model.SecurityChange
	decodeResult(t, response, &change)
	h.call(t, "POST", "/api/security/changes", "officer", map[string]any{"reason": preview.Proposal.Reason, "expected_version": 1, "change": json.RawMessage(preview.Proposal.Change), "step_up_proof": proof}, 403)
	h.call(t, "POST", "/api/security/step-up", "officer", map[string]string{"action": authorization.ActionApprove, "digest": change.Digest, "change_id": change.ID, "code": "000000"}, 403)
	h.call(t, "POST", "/api/security/changes/"+change.ID+"/approve", "approver-a", map[string]string{"step_up_proof": proof}, 403)
	if strings.Contains(string(response), "private_key_pem") {
		t.Fatal("request leaked credential bytes")
	}
}

func (h *governanceHTTP) secret(t *testing.T, kind, value string) string {
	t.Helper()
	response := h.call(t, "POST", "/api/security/secrets", "officer", map[string]string{"kind": kind, "value": value}, 201)
	var secret struct {
		Ref string `json:"credential_ref"`
	}
	decodeResult(t, response, &secret)
	if secret.Ref == "" || bytes.Contains(response, []byte(value)) {
		t.Fatal("write-only secret did not return only its immutable reference")
	}
	return secret.Ref
}

func TestGovernanceHTTPSecretPreflightLeavesApprovedChangeRetryable(t *testing.T) {
	h := newGovernanceHTTP(t)
	h.apply(t, h.approve(t, h.request(t, h.bootstrapPayload(), 1)), 200)
	passwordRef := h.secret(t, "password", "SyntheticTemporary@1234")
	for _, payload := range []model.SecurityChangePayload{
		{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "viewer", Operation: "password-reset", SecretRef: "secret:missing"}},
		{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "viewer", Operation: "password-reset", SecretRef: h.policy.CredentialRef}},
		{Kind: "ldap", LDAP: &model.SecurityLDAPSettings{BindCredentialRef: "secret:missing"}},
		{Kind: "ldap", LDAP: &model.SecurityLDAPSettings{BindCredentialRef: passwordRef}},
		{Kind: "ldap", LDAP: &model.SecurityLDAPSettings{Enabled: true, URL: "ldaps://directory.synthetic.invalid"}},
	} {
		change := h.approve(t, h.request(t, payload, 2))
		before := len(h.archive.Governance.Envelopes())
		h.apply(t, change, 0)
		stored, err := h.s.store.GetSecurityChange(change.ID)
		if err != nil || stored.State != "approved" || stored.IntentRef != "" {
			t.Fatalf("invalid immutable reference began transition: %+v %v", stored, err)
		}
		state, err := h.s.store.GetPolicyState()
		if err != nil || state.Active.Version != 2 || state.Pending != nil || len(h.archive.Governance.Envelopes()) != before {
			t.Fatalf("failed preflight changed policy/evidence: %+v %v", state, err)
		}
	}
	// A valid independent change remains usable after rejected proposals. Its
	// approved reference is archived, while only encrypted prepared settings enter
	// the application database.
	bindPassword := "Synthetic directory bind credential"
	bindRef := h.secret(t, "destination", bindPassword)
	ldap := &model.SecurityLDAPSettings{Enabled: true, URL: "ldaps://directory.synthetic.invalid", BindDN: "cn=hub,dc=synthetic,dc=invalid", BindCredentialRef: bindRef, UserBaseDN: "ou=people,dc=synthetic,dc=invalid", GroupBaseDN: "ou=groups,dc=synthetic,dc=invalid", ViewerGroups: []string{"viewers"}}
	change := h.apply(t, h.approve(t, h.request(t, model.SecurityChangePayload{Kind: "ldap", LDAP: ldap}, 2)), 200)
	config, err := h.s.loadLDAPConfig()
	if err != nil || !config.Enabled || config.BindPassword != bindPassword {
		t.Fatalf("approved LDAP settings not prepared: %+v %v", config, err)
	}
	storedSecret, err := h.s.store.GetConfig(configKeyLDAPBindPassword)
	if err != nil || storedSecret == bindPassword || storedSecret == "" {
		t.Fatal("prepared bind password was not encrypted")
	}
	for _, event := range h.archive.Governance.Envelopes() {
		if event.Details.RequestID == change.ID && bytes.Contains(event.Details.ApprovedChange, []byte(bindPassword)) {
			t.Fatal("prepared LDAP credential leaked into exact governance evidence")
		}
	}
}

func TestGovernanceHTTPProtectedPasswordAndMFARecoveryUsesRealApprovedArchive(t *testing.T) {
	h := newGovernanceHTTP(t)
	payload := h.bootstrapPayload()
	payload.Nominations = append(payload.Nominations, model.SecurityNomination{UserID: "viewer", PersonID: "synthetic-person-reader", Roles: []model.Role{model.RoleOriginalReader, model.RoleSecurityOfficer}, Verification: "Synthetic test recovery principal, never staging approval"})
	h.apply(t, h.approve(t, h.request(t, payload, 1)), 200)
	temporary, replacement := "SyntheticTemporary@1234", "SyntheticReplacement@1234"
	ref := h.secret(t, "password", temporary)
	h.apply(t, h.approve(t, h.request(t, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "viewer", Operation: "password-reset", SecretRef: ref}}, 2)), 200)
	h.call(t, "GET", "/api/auth/me", "viewer", nil, 401)
	response := h.call(t, "POST", "/api/auth/login", "viewer", model.LoginRequest{Username: "viewer", Password: temporary}, 202)
	var primary model.LoginResponse
	decodeResult(t, response, &primary)
	h.clock.Advance(30 * time.Second)
	code, err := totp.GenerateCode(h.secrets["viewer"], h.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	response = h.call(t, "POST", "/api/auth/login/totp", "viewer", model.LoginTOTPRequest{TOTPToken: primary.TOTPToken, Code: code}, 200)
	var login model.LoginResponse
	decodeResult(t, response, &login)
	h.tokens["viewer"] = login.RecoveryToken
	if !login.MustChangePassword || login.RecoveryToken == "" {
		t.Fatal("approved recovery lost purpose-bound completion authority")
	}
	h.call(t, "POST", "/api/auth/refresh", "viewer", model.RefreshRequest{RefreshToken: login.RecoveryToken}, 401)
	h.call(t, "POST", "/api/executions/not-a-read-permit/original-access/preview", "viewer", map[string]any{"purpose": "Recovery is not an original-read permit", "records": []string{"script"}}, 403)
	h.call(t, "POST", "/api/security/changes/preview", "viewer", authorization.Proposal{Reason: "Unfinished recovery cannot mutate governance", ExpectedVersion: 3, Change: mustMarshal(t, model.SecurityChangePayload{Kind: "policy", Policy: &h.policy})}, 403)
	response = h.call(t, "POST", "/api/auth/password/recovery", "viewer", map[string]string{"new_password": replacement}, 200)

	current, err := h.s.store.GetUserByID("viewer")
	if err != nil || current.MustChangePassword || !auth.ComparePassword(current.PasswordHash, replacement) {
		t.Fatal("approved temporary credential was not consumed by mandatory rotation")
	}
	h.login(t, "viewer", replacement)
	h.call(t, "PUT", "/api/auth/password", "viewer", model.ChangePasswordRequest{CurrentPassword: replacement, NewPassword: temporary}, 403)
	h.apply(t, h.approve(t, h.request(t, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "viewer", Operation: "mfa-reset"}}, 3)), 200)
	response = h.call(t, "POST", "/api/auth/login", "viewer", model.LoginRequest{Username: "viewer", Password: replacement}, 200)
	decodeResult(t, response, &primary)
	if !primary.RequiresTOTPSetup || primary.SetupToken == "" {
		t.Fatal("approved MFA reset did not issue authenticated setup")
	}
	h.tokens["viewer"] = primary.SetupToken
	response = h.call(t, "POST", "/api/auth/totp/setup", "viewer", nil, 200)
	var setup model.TOTPSetupResponse
	decodeResult(t, response, &setup)
	code, err = totp.GenerateCode(setup.Secret, h.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	response = h.call(t, "POST", "/api/auth/totp/enable", "viewer", model.TOTPEnableRequest{Code: code}, 200)
	var signed model.AuthResponse
	decodeResult(t, response, &signed)
	h.tokens["viewer"] = signed.AccessToken
	response = h.call(t, "GET", "/api/auth/me", "viewer", nil, 200)
	if !bytes.Contains(response, []byte("original-reader")) {
		t.Fatal("approved MFA completion lost live security role")
	}
	current, err = h.s.store.GetUserByID("viewer")
	if err != nil || !current.TOTPEnabled || current.MustChangePassword {
		t.Fatal("approved recovery remained incomplete")
	}
	h.tokens["viewer"] = primary.SetupToken
	h.call(t, "POST", "/api/auth/totp/setup", "viewer", nil, 401)
	for _, event := range h.archive.Governance.Envelopes() {
		if bytes.Contains(event.Details.ApprovedChange, []byte(temporary)) || bytes.Contains(event.Details.ApprovedChange, []byte(replacement)) || bytes.Contains(event.Details.ApprovedChange, []byte(setup.Secret)) {
			t.Fatal("recovery credentials leaked into governance archive")
		}
	}
}

func TestGovernanceHTTPReadinessReportsActualAuthorityAndMarkerWithoutMutatingState(t *testing.T) {
	h := newGovernanceHTTP(t)
	readiness := func(governance, transport, marker bool) {
		t.Helper()
		response := h.call(t, "GET", "/api/audit-policy", "officer", nil, 200)
		var result struct {
			Readiness map[string]bool `json:"readiness"`
		}
		decodeResult(t, response, &result)
		if result.Readiness["governance"] != governance || result.Readiness["archive_and_transport"] != transport || result.Readiness["enrollment_marker"] != marker {
			t.Fatalf("misleading configured readiness: %s", response)
		}
	}
	readiness(true, false, false) // Enhanced archive/marker do not apply before enrollment.
	h.apply(t, h.approve(t, h.request(t, h.bootstrapPayload(), 1)), 200)
	before := len(h.archive.Governance.Envelopes())
	readiness(true, true, true)
	h.protected = false
	readiness(true, false, true)
	h.protected = true
	h.archive.SetFault("anchor")
	readiness(false, true, true)
	h.archive.SetFault("")
	marker, err := os.ReadFile(h.s.securityTransition.EnrollmentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(h.s.securityTransition.EnrollmentPath, marker, 0600)
	if err := os.Remove(h.s.securityTransition.EnrollmentPath); err != nil {
		t.Fatal(err)
	}
	readiness(false, true, false)
	wrong := authorization.EnrollmentMarker{InstallationID: h.s.securityTransition.InstallationID, Version: 1, SHA256: authorization.Digest([]byte("restored old marker"))}
	if err := os.WriteFile(h.s.securityTransition.EnrollmentPath, mustMarshal(t, wrong), 0600); err != nil {
		t.Fatal(err)
	}
	readiness(false, true, false)
	state, err := h.s.store.GetPolicyState()
	if err != nil || state.Active.Version != 2 || state.State != "enhanced" || state.Pending != nil || len(h.archive.Governance.Envelopes()) != before {
		t.Fatalf("read-only failed readiness changed state or evidence: %+v %v", state, err)
	}
}
