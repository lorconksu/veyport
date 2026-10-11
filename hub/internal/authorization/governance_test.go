package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestStandardMigrationPreservesRolesAndHasNoSecurityAuthority(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, role := range []model.Role{model.RoleAdmin, model.RoleAuditor, model.RoleViewer} {
		u := &model.User{ID: string(role), Username: string(role), Email: string(role) + "@test.invalid", Role: role}
		if err := st.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		effective, err := New(st).Effective(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !effective.HasRole(role) || effective.Can("security.approve") {
			t.Fatalf("incorrect role authority: %+v", effective)
		}
	}
	p, err := New(st).PolicyForExecution("admin", "node")
	if err != nil || p.Enhanced || p.Version != 1 {
		t.Fatalf("standard policy: %+v %v", p, err)
	}
}
func TestStepupCannotBeReusedOrChanged(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	digest := Digest([]byte("exact"))
	proof, err := st.IssueStepup("u", "s", "security.approve", digest, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ConsumeStepup(proof, "u", "other", "security.approve", digest, now); err == nil {
		t.Fatal("changed session accepted")
	}
	if err := st.ConsumeStepup(proof, "u", "s", "security.approve", digest, now); err != nil {
		t.Fatal(err)
	}
	if err := st.ConsumeStepup(proof, "u", "s", "security.approve", digest, now); err == nil {
		t.Fatal("proof reused")
	}
}
func TestExactPayloadRejectsDuplicateFields(t *testing.T) {
	raw := json.RawMessage(`{"kind":"policy","kind":"bootstrap","policy":{"profile":"standard"}}`)
	if _, err := DecodeChange(raw); err == nil {
		t.Fatal("duplicate field accepted")
	}
}

type fakeEvidence struct {
	mu        sync.Mutex
	records   map[string][]byte
	fail      string
	anchor    PolicyAnchor
	anchorErr error
}

func (e *fakeEvidence) Ready(context.Context, model.AuditPolicy) error { return nil }
func (e *fakeEvidence) Preserve(_ context.Context, raw []byte) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, envelope, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return "", err
	}
	if envelope.EventType == e.fail {
		return "", errors.New("injected archive outage")
	}
	if prior, ok := e.records[envelope.EventID]; ok && !bytes.Equal(prior, raw) {
		return "", errors.New("event conflict")
	}
	e.records[envelope.EventID] = append([]byte(nil), raw...)
	if envelope.EventType == auditrecord.PolicyAnchor {
		e.anchor = PolicyAnchor{InstallationID: envelope.Details.InstallationID, Version: envelope.PolicyVersion, SHA256: envelope.PolicySHA256, RequestID: envelope.Details.RequestID, RequestSHA256: envelope.Details.RequestSHA256}
	}
	return "protected:" + auditrecord.Hash(raw), nil
}
func (e *fakeEvidence) Anchor(_ context.Context, id string) (PolicyAnchor, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.anchorErr != nil {
		return PolicyAnchor{}, e.anchorErr
	}
	if e.anchor.Version == 0 {
		return PolicyAnchor{}, auditgate.ErrAnchorNotFound
	}
	if e.anchor.InstallationID != id {
		return PolicyAnchor{}, ErrRecovery
	}
	return e.anchor, nil
}
func fixtureGovernance(t *testing.T) (*Service, authorizationFixture) {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	service := New(st)
	now := time.Date(2026, 10, 11, 6, 0, 0, 0, time.UTC)
	service.Now = func() time.Time { return now }
	secret := "JBSWY3DPEHPK3PXP"
	ids := []string{"requester", "approver-one", "approver-two", "other-admin"}
	for _, id := range ids {
		u := &model.User{ID: id, Username: id, Email: id + "@test.invalid", Role: model.RoleAdmin, TOTPEnabled: true, TOTPSecret: &secret}
		if err := st.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
	nominations := []model.SecurityNomination{{UserID: ids[0], PersonID: "person-one", Roles: []model.Role{model.RoleSecurityOfficer}, Verification: "Operator verified person one"}, {UserID: ids[1], PersonID: "person-two", Roles: []model.Role{model.RoleSecurityApprover}, Verification: "Operator verified person two"}, {UserID: ids[2], PersonID: "person-three", Roles: []model.Role{model.RoleSecurityApprover}, Verification: "Operator verified person three"}}
	policy := model.AuditPolicy{Profile: "enhanced", RuntimeSeconds: 3600, RetentionHours: 24, Destination: "https://audit.test.invalid", CredentialRef: "secret:version-1", TrustKeyIDs: []string{"receipt-key"}, QualificationSHA256: Digest([]byte("qualification"))}
	change, _ := json.Marshal(model.SecurityChangePayload{Kind: "bootstrap", Policy: &policy, Nominations: nominations})
	p := Proposal{Reason: "Activate independently governed audit policy", ExpectedVersion: 1, Change: change}
	preview, err := Normalize(p)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := st.IssueStepup(ids[0], "session-requester", ActionRequest, preview.Digest, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.Request(ids[0], "session-requester", proof, p)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &fakeEvidence{records: map[string][]byte{}}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := TransitionConfig{Evidence: evidence, EnrollmentPath: filepath.Join(dir, "enhanced-enrollment.json"), InstallationID: "test-installation"}
	return service, authorizationFixture{change: c, config: cfg, evidence: evidence, now: now}
}

type authorizationFixture struct {
	change   model.SecurityChange
	config   TransitionConfig
	evidence *fakeEvidence
	now      time.Time
}

func approveFixture(t *testing.T, s *Service, f authorizationFixture, user string) {
	t.Helper()
	proof, err := s.Store.IssueStepup(user, "session-"+user, ActionApprove, f.change.Digest, s.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Approve(f.change.ID, user, "session-"+user, proof); err != nil {
		t.Fatal(err)
	}
}
func applyFixture(t *testing.T, s *Service, f authorizationFixture) error {
	t.Helper()
	proof, err := s.Store.IssueStepup("requester", "session-requester", ActionApply, f.change.Digest, s.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Apply(context.Background(), f.change.ID, "requester", "session-requester", proof, f.config)
	return err
}
func TestBootstrapFreezeIndependenceAndActivation(t *testing.T) {
	s, f := fixtureGovernance(t)
	if err := s.Store.UpdateUserRole("approver-one", model.RoleViewer); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("nominee role mutation: %v", err)
	}
	if err := s.Store.UpdateUserTOTP("approver-one", nil, false); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("nominee MFA recovery: %v", err)
	}
	self, _ := s.Store.IssueStepup("requester", "session-requester", ActionApprove, f.change.Digest, s.Now())
	if _, err := s.Approve(f.change.ID, "requester", "session-requester", self); err == nil {
		t.Fatal("requester approved self")
	}
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	if err := applyFixture(t, s, f); err != nil {
		t.Fatal(err)
	}
	state, err := s.Store.GetPolicyState()
	if err != nil || state.State != "enhanced" || state.Active.Version != 2 {
		t.Fatalf("activation %+v %v", state, err)
	}
	if len(f.evidence.records) != 4 {
		t.Fatalf("intent/commit/anchor/result expected: %d", len(f.evidence.records))
	}
	for _, raw := range f.evidence.records {
		var e auditrecord.Envelope
		json.Unmarshal(raw, &e)
		if e.EventType == auditrecord.PolicyIntent && !bytes.Equal(e.Details.ApprovedChange, f.change.ApprovedBytes) {
			t.Fatal("approved bytes changed")
		}
	}
	if err := s.GuardInteractive("requester", "node"); !errors.Is(err, ErrInteractive) {
		t.Fatalf("interactive shell allowed: %v", err)
	}
	other, err := s.Effective("other-admin")
	if err != nil || other.Can(ActionApprove) || other.Can(ActionRequest) {
		t.Fatalf("admin became security superuser %+v %v", other, err)
	}
}
func TestRefreshGenerationPreservesVotesButCredentialChangeInvalidates(t *testing.T) {
	s, f := fixtureGovernance(t)
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	if _, err := s.Store.IncrementTokenGeneration("approver-one"); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Store.GetSecurityChange(f.change.ID)
	if err := s.ValidateQuorum(c); err != nil {
		t.Fatalf("routine refresh invalidated approval: %v", err)
	}
	if _, err := s.Store.DisableUser("approver-one", "other-admin", s.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateQuorum(c); err == nil {
		t.Fatal("suspended vote accepted")
	}
	if _, err := s.Store.EnableUser("approver-one", s.Now()); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("unprotected reenable %v", err)
	}
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("revoked approver applied")
	}
}
func TestCrashCommitAndResultRemainStrictAndReconcile(t *testing.T) {
	for _, fail := range []string{auditrecord.PolicyCommit, auditrecord.PolicyResult, auditrecord.PolicyAnchor} {
		t.Run(fail, func(t *testing.T) {
			s, f := fixtureGovernance(t)
			approveFixture(t, s, f, "approver-one")
			approveFixture(t, s, f, "approver-two")
			f.evidence.fail = fail
			if err := applyFixture(t, s, f); err == nil {
				t.Fatal("outage was ignored")
			}
			state, _ := s.Store.GetPolicyState()
			if state.State != "applying" {
				t.Fatalf("lost transition: %+v", state)
			}
			p, err := s.PolicyForExecution("requester", "node")
			if !errors.Is(err, ErrTransition) || !p.Enhanced {
				t.Fatalf("crash opened Standard admission: %+v %v", p, err)
			}
			f.evidence.fail = ""
			s.Now = func() time.Time { return f.now.Add(48 * time.Hour) }
			if _, err := s.ReconcileChange(context.Background(), f.change.ID, f.config); err != nil {
				t.Fatal(err)
			}
			state, _ = s.Store.GetPolicyState()
			if state.State != "enhanced" || state.Active.Version != 2 {
				t.Fatalf("recovery failed: %+v", state)
			}
		})
	}
}
func TestExternalAnchorDetectsDatabaseRollbackAndMissingMarker(t *testing.T) {
	s, f := fixtureGovernance(t)
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	if err := applyFixture(t, s, f); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAnchor(context.Background(), f.config); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB().Exec("UPDATE audit_policy_state SET active_version=1,state='standard'"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAnchor(context.Background(), f.config); !errors.Is(err, ErrRecovery) {
		t.Fatalf("rollback not detected: %v", err)
	}
	p, err := s.PolicyForExecution("other-admin", "any")
	if !errors.Is(err, ErrRecovery) || !p.RecoveryRequired {
		t.Fatalf("rollback did not fail closed: %+v %v", p, err)
	}
}
func TestSuspensionDuringExternalCommitPreventsActivation(t *testing.T) {
	s, f := fixtureGovernance(t)
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	evidence := &suspendingEvidence{fakeEvidence: f.evidence, store: s.Store, now: s.Now()}
	f.config.Evidence = evidence
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("suspension during archive I/O was ignored")
	}
	state, err := s.Store.GetPolicyState()
	if err != nil || state.Active.Version != 1 || state.State != "applying" {
		t.Fatalf("revoked vote activated: %+v %v", state, err)
	}
	c, _ := s.Store.GetSecurityChange(f.change.ID)
	invalid := false
	for _, a := range c.Approvals {
		if a.UserID == "approver-one" && a.InvalidatedAt != nil {
			invalid = true
		}
	}
	if !invalid {
		t.Fatal("invalidated approval history was not exposed")
	}
}

type suspendingEvidence struct {
	*fakeEvidence
	store *store.Store
	now   time.Time
}

func (e *suspendingEvidence) Preserve(ctx context.Context, raw []byte) (string, error) {
	_, record, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return "", err
	}
	if record.EventType == auditrecord.PolicyCommit {
		if _, err := e.store.DisableUser("approver-one", "other-admin", e.now); err != nil {
			return "", err
		}
	}
	return e.fakeEvidence.Preserve(ctx, raw)
}
func TestKnownMarkerBeforeAnchorCrashReconcilesAtStartup(t *testing.T) {
	s, f := fixtureGovernance(t)
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	f.evidence.fail = auditrecord.PolicyAnchor
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("anchor outage ignored")
	}
	if err := s.CheckAnchor(context.Background(), f.config); err != nil {
		t.Fatalf("known pre-CAS marker treated as unknown rollback: %v", err)
	}
	if err := s.Store.RequirePolicyRecovery(); err != nil {
		t.Fatal(err)
	}
	f.evidence.fail = ""
	if err := s.Startup(context.Background(), f.config); err != nil {
		t.Fatalf("legitimate interrupted transition stranded: %v", err)
	}
	state, _ := s.Store.GetPolicyState()
	if state.State != "enhanced" || state.Active.Version != 2 {
		t.Fatalf("startup did not reconcile: %+v", state)
	}
}
func TestInstallationIdentifierPrivateDurableAndSymlinkRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "security")
	id, err := InitInstallation(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := InitInstallation(dir)
	if err != nil || again != id {
		t.Fatal("installation identity changed")
	}
	marker := filepath.Join(dir, "enhanced-enrollment.json")
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, marker); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(marker, EnrollmentMarker{InstallationID: id, Version: 2, SHA256: Digest([]byte("p"))}); err == nil {
		t.Fatal("symlink marker accepted")
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "outside" {
		t.Fatal("marker followed symlink")
	}
}
func protectedChange(t *testing.T, s *Service, payload model.SecurityChangePayload) (model.SecurityChange, error) {
	t.Helper()
	state, err := s.Store.GetPolicyState()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(payload)
	p := Proposal{Reason: "Independent reviewed policy change", ExpectedVersion: state.Active.Version, Change: raw}
	preview, err := Normalize(p)
	if err != nil {
		return model.SecurityChange{}, err
	}
	proof, err := s.Store.IssueStepup("requester", "session-requester", ActionRequest, preview.Digest, s.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s.Request("requester", "session-requester", proof, p)
}
func activatedFixture(t *testing.T) (*Service, authorizationFixture) {
	t.Helper()
	s, f := fixtureGovernance(t)
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	if err := applyFixture(t, s, f); err != nil {
		t.Fatal(err)
	}
	return s, f
}
func TestDisableRemainsProtectedUntilResultAndCannotRebootstrap(t *testing.T) {
	s, f := activatedFixture(t)
	policy := model.AuditPolicy{Profile: "standard", RuntimeSeconds: 3600, RetentionHours: 24}
	c, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	f.change = c
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	f.evidence.fail = auditrecord.PolicyResult
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("result outage ignored")
	}
	state, _ := s.Store.GetPolicyState()
	if state.Active.Policy.Profile != "standard" || state.Previous == nil {
		t.Fatalf("disable crash lost previous policy %+v", state)
	}
	p, err := s.PolicyForExecution("requester", "node")
	if !p.Enhanced || !errors.Is(err, ErrTransition) {
		t.Fatalf("disable crash reopened unaudited work %+v %v", p, err)
	}
	f.evidence.fail = ""
	if _, err := s.ReconcileChange(context.Background(), c.ID, f.config); err != nil {
		t.Fatal(err)
	}
	bootstrap, _ := DecodeChange(fixturePayload(t))
	_, err = protectedChange(t, s, bootstrap)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("rebootstrap bypass after disable %v", err)
	}
	officer, _ := s.Effective("requester")
	if !officer.Can(ActionRequest) {
		t.Fatal("disable removed established governance")
	}
	if err := s.Store.UpdateAuditSettings(s.Store.GetAuditSettings()); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("disable reopened legacy audit mutation: %v", err)
	}
}
func fixturePayload(t *testing.T) []byte {
	t.Helper()
	_, f := fixtureGovernance(t)
	return f.change.Payload
}
func TestConcurrentApplicationHasSingleVersionWinner(t *testing.T) {
	s, f := activatedFixture(t)
	state, _ := s.Store.GetPolicyState()
	candidate := state.Active.Policy
	candidate.RuntimeSeconds = 1800
	c1, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &candidate})
	if err != nil {
		t.Fatal(err)
	}
	candidate.RuntimeSeconds = 1200
	c2, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &candidate})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []model.SecurityChange{c1, c2} {
		af := f
		af.change = c
		approveFixture(t, s, af, "approver-one")
		approveFixture(t, s, af, "approver-two")
	}
	outcomes := make(chan error, 2)
	var wg sync.WaitGroup
	for _, c := range []model.SecurityChange{c1, c2} {
		proof, _ := s.Store.IssueStepup("requester", "session-requester", ActionApply, c.Digest, s.Now())
		wg.Add(1)
		go func(c model.SecurityChange, proof string) {
			defer wg.Done()
			_, err := s.Apply(context.Background(), c.ID, "requester", "session-requester", proof, f.config)
			outcomes <- err
		}(c, proof)
	}
	wg.Wait()
	close(outcomes)
	winners := 0
	for err := range outcomes {
		if err == nil {
			winners++
		}
	}
	state, err = s.Store.GetPolicyState()
	if err != nil || winners != 1 || state.Active.Version != 3 {
		t.Fatalf("concurrent winners=%d state=%+v err=%v", winners, state, err)
	}
}
func TestProtectedPersonAliasCannotApproveAsIndependent(t *testing.T) {
	s, f := activatedFixture(t)
	c, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "person", Person: &model.SecurityPersonChange{UserID: "approver-two", PersonID: "person-one", Verification: "Operator verified linked alias"}})
	if err != nil {
		t.Fatal(err)
	}
	f.change = c
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	if err := applyFixture(t, s, f); err != nil {
		t.Fatal(err)
	}
	state, _ := s.Store.GetPolicyState()
	policy := state.Active.Policy
	c, err = protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := s.Store.IssueStepup("approver-two", "session-approver-two", ActionApprove, c.Digest, s.Now())
	if _, err := s.Approve(c.ID, "approver-two", "session-approver-two", proof); !errors.Is(err, ErrIndependent) {
		t.Fatalf("linked alias voted independently %v", err)
	}
}
func TestExpiredAndChangedRequestCannotApply(t *testing.T) {
	s, f := fixtureGovernance(t)
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	s.Now = func() time.Time { return f.now.Add(25 * time.Hour) }
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("expired request applied")
	}
	s.Now = func() time.Time { return f.now }
	if _, err := s.Store.DB().Exec("UPDATE security_changes SET payload=? WHERE id=?", []byte(`{"reason":"edited","expected_version":1,"change":{"kind":"policy"}}`), f.change.ID); err != nil {
		t.Fatal(err)
	}
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("edited request retained quorum")
	}
}

func TestCompletedQuorumRejectsLateVoteAndRemainsValid(t *testing.T) {
	s, f := activatedFixture(t)
	// Add a third authorized principal as test setup, then freeze the first two.
	if _, err := s.Store.DB().Exec("INSERT INTO user_roles(user_id,role) VALUES('other-admin','security-approver')"); err != nil {
		t.Fatal(err)
	}
	state, _ := s.Store.GetPolicyState()
	c, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &state.Active.Policy})
	if err != nil {
		t.Fatal(err)
	}
	f.change = c
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	proof, _ := s.Store.IssueStepup("other-admin", "session-other-admin", ActionApprove, c.Digest, s.Now())
	if _, err := s.Approve(c.ID, "other-admin", "session-other-admin", proof); !errors.Is(err, store.ErrSecurityConflict) {
		t.Fatalf("late vote changed completed quorum: %v", err)
	}
	if _, err := s.Store.DisableUser("other-admin", "requester", s.Now()); err != nil {
		t.Fatal(err)
	}
	c, _ = s.Store.GetSecurityChange(c.ID)
	if len(c.Approvals) != 2 || s.ValidateQuorum(c) != nil {
		t.Fatal("late principal invalidated the frozen two-person quorum")
	}
	if err := applyFixture(t, s, f); err != nil {
		t.Fatal(err)
	}
}

func TestPendingRecoveryAuthenticatesAnchorBeforeAnyMutation(t *testing.T) {
	for _, activePending := range []bool{false, true} {
		for _, failure := range []string{"admin_unavailable", "external_newer", "marker_newer"} {
			t.Run(fmt.Sprintf("active_pending=%t/%s", activePending, failure), func(t *testing.T) {
				s, f := activatedFixture(t)
				c, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "role", Role: &model.SecurityRoleChange{UserID: "other-admin", Role: model.RoleOriginalReader, Grant: true}})
				if err != nil {
					t.Fatal(err)
				}
				f.change = c
				approveFixture(t, s, f, "approver-one")
				approveFixture(t, s, f, "approver-two")
				f.evidence.fail = auditrecord.PolicyCommit
				if activePending {
					f.evidence.fail = auditrecord.PolicyResult
				}
				if err := applyFixture(t, s, f); err == nil {
					t.Fatal("injected interruption ignored")
				}
				// Simulate restoring a pending database with ingestion still healthy.
				f.evidence.fail = ""
				switch failure {
				case "admin_unavailable":
					f.evidence.anchorErr = errors.New("admin lookup unavailable")
				case "external_newer":
					f.evidence.anchor.Version = 4
					f.evidence.anchor.SHA256 = Digest([]byte("later protected policy"))
				case "marker_newer":
					if err := writeMarker(f.config.EnrollmentPath, EnrollmentMarker{f.config.InstallationID, 4, Digest([]byte("later protected policy"))}); err != nil {
						t.Fatal(err)
					}
				}
				beforeRecords := len(f.evidence.records)
				beforeRoles, _ := s.Store.UserRoles("other-admin")
				if err := s.Startup(context.Background(), f.config); !errors.Is(err, ErrRecovery) {
					t.Fatalf("startup trusted stale pending database: %v", err)
				}
				if _, err := s.ReconcileChange(context.Background(), c.ID, f.config); !errors.Is(err, ErrRecovery) {
					t.Fatalf("operator recovery ignored failed anchor: %v", err)
				}
				after, _ := s.Store.GetSecurityChange(c.ID)
				state, _ := s.Store.GetPolicyState()
				afterRoles, _ := s.Store.UserRoles("other-admin")
				if after.State != "applying" || after.ResultRef != "" || state.State != "recovery_required" || len(f.evidence.records) != beforeRecords || !reflect.DeepEqual(beforeRoles, afterRoles) {
					t.Fatalf("failed anchor allowed side effects or Finish: %+v %+v", after, state)
				}
			})
		}
	}
}

func TestArchiveOccurrenceUsesApplicationTimeAndFreezesRetries(t *testing.T) {
	s, f := fixtureGovernance(t)
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	applyTime := f.now.Add(time.Hour)
	s.Now = func() time.Time { return applyTime }
	f.evidence.fail = auditrecord.PolicyResult
	if err := applyFixture(t, s, f); err == nil {
		t.Fatal("result interruption ignored")
	}
	for _, raw := range f.evidence.records {
		_, event, err := auditrecord.ExpectedFor(raw)
		if err != nil || !event.OccurredAt.Equal(applyTime) {
			t.Fatalf("event reports request creation time: %+v %v", event, err)
		}
	}
	f.evidence.fail = ""
	s.Now = func() time.Time { return applyTime.Add(time.Hour) }
	if _, err := s.ReconcileChange(context.Background(), f.change.ID, f.config); err != nil {
		t.Fatal(err)
	}
	_, result, err := auditrecord.ExpectedFor(f.evidence.records[f.change.ID+"-"+auditrecord.PolicyResult])
	if err != nil || !result.OccurredAt.Equal(applyTime) {
		t.Fatalf("retry changed first materialized occurrence: %+v %v", result, err)
	}
}

func TestActivatedPendingRequiresItsOwnAnchorAndMarker(t *testing.T) {
	for _, failure := range []string{"old_anchor", "missing_anchor", "missing_marker", "old_marker"} {
		t.Run(failure, func(t *testing.T) {
			s, f := activatedFixture(t)
			oldAnchor := f.evidence.anchor
			state, _ := s.Store.GetPolicyState()
			oldMarker := EnrollmentMarker{f.config.InstallationID, state.Active.Version, state.Active.SHA256}
			c, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &state.Active.Policy})
			if err != nil {
				t.Fatal(err)
			}
			f.change = c
			approveFixture(t, s, f, "approver-one")
			approveFixture(t, s, f, "approver-two")
			f.evidence.fail = auditrecord.PolicyResult
			if err := applyFixture(t, s, f); err == nil {
				t.Fatal("result interruption ignored")
			}
			f.evidence.fail = ""
			switch failure {
			case "old_anchor":
				f.evidence.anchor = oldAnchor
			case "missing_anchor":
				f.evidence.anchorErr = auditgate.ErrAnchorNotFound
			case "missing_marker", "old_marker":
				if err := os.Remove(f.config.EnrollmentPath); err != nil {
					t.Fatal(err)
				}
				if failure == "old_marker" {
					if err := writeMarker(f.config.EnrollmentPath, oldMarker); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := s.ReconcileChange(context.Background(), c.ID, f.config); !errors.Is(err, ErrRecovery) {
				t.Fatalf("active CAS finished without its persisted anchor/marker: %v", err)
			}
			change, _ := s.Store.GetSecurityChange(c.ID)
			if change.State != "applying" || change.ResultRef != "" {
				t.Fatal("inconsistent recovery finished")
			}
		})
	}
}

func TestNominationFreezeRechecksValidatedIdentityAtomically(t *testing.T) {
	for _, change := range []string{"mfa", "person"} {
		t.Run(change, func(t *testing.T) {
			s, f := fixtureGovernance(t)
			payload, _ := DecodeChange(f.change.Payload)
			// Replay the already validated proposal at the store boundary after
			// simulating a concurrent identity update before the freeze starts.
			if _, err := s.Store.DB().Exec("DELETE FROM security_nominations WHERE request_id=?", f.change.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Store.DB().Exec("DELETE FROM security_changes WHERE id=?", f.change.ID); err != nil {
				t.Fatal(err)
			}
			if change == "mfa" {
				if _, err := s.Store.DB().Exec("UPDATE users SET totp_secret=NULL,totp_enabled=0 WHERE id='approver-one'"); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := s.Store.DB().Exec("UPDATE security_identity_links SET person_id='user:requester' WHERE user_id='approver-one'"); err != nil {
					t.Fatal(err)
				}
			}
			proof, _ := s.Store.IssueStepup("requester", "session-requester", ActionRequest, f.change.Digest, s.Now())
			if err := s.Store.CreateSecurityChange(f.change, payload.Nominations, "session-requester", proof, s.Now()); !errors.Is(err, store.ErrSecurityConflict) {
				t.Fatalf("stale nomination identity froze: %v", err)
			}
			var count int
			if err := s.Store.DB().QueryRow("SELECT COUNT(*) FROM security_changes WHERE id=?", f.change.ID).Scan(&count); err != nil || count != 0 {
				t.Fatalf("failed nomination left a partial freeze: %d %v", count, err)
			}
		})
	}
}

func TestLegacySettingsWritersRecheckProtectedState(t *testing.T) {
	s, _ := fixtureGovernance(t)
	if err := s.Store.UpdateAuditSettings(s.Store.GetAuditSettings()); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("pending bootstrap settings bypass: %v", err)
	}
	if _, err := s.Store.DB().Exec("UPDATE users SET auth_provider='ldap' WHERE id='approver-one'"); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.UpdateLegacyLDAPConfig(map[string]string{"ldap.url": "ldaps://replacement.invalid"}); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("nominated LDAP identity changed through legacy writer: %v", err)
	}
	if got, _ := s.Store.GetConfig("ldap.url"); got != "" {
		t.Fatal("protected rejection left partial configuration")
	}
}

func TestIncompleteCleanupPreservesRecoveredPrincipalAliasAndAudit(t *testing.T) {
	s, f := activatedFixture(t)
	c, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "approver-one", Operation: "mfa-reset"}})
	if err != nil {
		t.Fatal(err)
	}
	f.change = c
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	if err := applyFixture(t, s, f); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"protected-alias", "ordinary-incomplete"} {
		if err := s.Store.CreateUser(&model.User{ID: id, Username: id, Email: id + "@test.invalid", Role: model.RoleViewer}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Store.DB().Exec("UPDATE security_identity_links SET person_id='person-two' WHERE user_id='protected-alias'"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"approver-one", "protected-alias", "ordinary-incomplete"} {
		if _, err := s.Store.DB().Exec("INSERT INTO audit_logs(id,user_id,action) VALUES(?,?,'test.history')", "history-"+id, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Store.DeleteIncompleteUsers(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"approver-one", "protected-alias"} {
		if _, err := s.Store.GetUserByID(id); err != nil {
			t.Fatalf("cleanup deleted protected identity: %s %v", id, err)
		}
		var count int
		if err := s.Store.DB().QueryRow("SELECT COUNT(*) FROM audit_logs WHERE id=?", "history-"+id).Scan(&count); err != nil || count != 1 {
			t.Fatalf("cleanup erased protected history: %s %d %v", id, count, err)
		}
	}
	if _, err := s.Store.GetUserByID("ordinary-incomplete"); err == nil {
		t.Fatal("ordinary incomplete-user cleanup stopped working")
	}
}
