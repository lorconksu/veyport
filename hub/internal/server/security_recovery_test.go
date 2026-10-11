package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

type recoveryEvidence struct{ anchor authorization.PolicyAnchor }

func (e *recoveryEvidence) Ready(context.Context, model.AuditPolicy) error { return nil }
func (e *recoveryEvidence) Preserve(_ context.Context, raw []byte) (string, error) {
	_, record, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return "", err
	}
	if record.EventType == auditrecord.PolicyAnchor {
		e.anchor = authorization.PolicyAnchor{InstallationID: record.Details.InstallationID, Version: record.PolicyVersion, SHA256: record.PolicySHA256, RequestID: record.Details.RequestID, RequestSHA256: record.Details.RequestSHA256}
	}
	return "protected:" + auditrecord.Hash(raw), nil
}
func (e *recoveryEvidence) Anchor(_ context.Context, id string) (authorization.PolicyAnchor, error) {
	if e.anchor.Version == 0 {
		return authorization.PolicyAnchor{}, auditgate.ErrAnchorNotFound
	}
	if e.anchor.InstallationID != id {
		return authorization.PolicyAnchor{}, authorization.ErrRecovery
	}
	return e.anchor, nil
}

// Votes use synthetic principals; login, setup, rotation and middleware use the
// real HTTP routes. No staging identity or approval is represented here.
func approveRecoveryPayload(t *testing.T, s *Server, payload model.SecurityChangePayload) {
	t.Helper()
	service := s.securityService()
	state, err := s.store.GetPolicyState()
	if err != nil {
		t.Fatal(err)
	}
	raw := mustMarshal(t, payload)
	proposal := authorization.Proposal{Reason: "Independently approved test recovery", ExpectedVersion: state.Active.Version, Change: raw}
	preview, err := authorization.Normalize(proposal)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := s.store.IssueStepup("recovery-officer", "officer-session", authorization.ActionRequest, preview.Digest, s.now())
	change, err := service.Request("recovery-officer", "officer-session", proof, proposal)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"recovery-approver-one", "recovery-approver-two"} {
		proof, _ := s.store.IssueStepup(id, id+"-session", authorization.ActionApprove, change.Digest, s.now())
		if _, err = service.Approve(change.ID, id, id+"-session", proof); err != nil {
			t.Fatal(err)
		}
	}
	proof, _ = s.store.IssueStepup("recovery-officer", "officer-session", authorization.ActionApply, change.Digest, s.now())
	if _, err = service.Apply(context.Background(), change.ID, "recovery-officer", "officer-session", proof, s.securityTransition); err != nil {
		t.Fatal(err)
	}
}

func recoveryServer(t *testing.T) (*Server, *model.User) {
	t.Helper()
	s := testServer(t)
	for _, id := range []string{"recovery-officer", "recovery-approver-one", "recovery-approver-two", "recovery-target"} {
		quickSecurityUser(t, s, id, model.RoleAdmin)
	}
	hash, err := auth.HashPassword("SyntheticExisting@1234")
	if err != nil || s.store.UpdateUserPassword("recovery-target", hash) != nil {
		t.Fatalf("initial test credential: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s.securityTransition = authorization.TransitionConfig{Evidence: &recoveryEvidence{}, InstallationID: "test-recovery-installation", EnrollmentPath: filepath.Join(dir, "enhanced-enrollment.json"), ResolveSecret: s.resolveSecuritySecret}
	policy := model.AuditPolicy{Profile: "enhanced", RuntimeSeconds: 3600, RetentionHours: 24, Destination: "https://audit.test.invalid", CredentialRef: "secret:qualified", TrustKeyIDs: []string{"qualified-key"}, QualificationSHA256: authorization.Digest([]byte("qualified"))}
	nominations := []model.SecurityNomination{}
	for i, id := range []string{"recovery-officer", "recovery-approver-one", "recovery-approver-two", "recovery-target"} {
		role := model.RoleSecurityApprover
		if i == 0 {
			role = model.RoleSecurityOfficer
		}
		if i == 3 {
			role = model.RoleOriginalReader
		}
		nominations = append(nominations, model.SecurityNomination{UserID: id, PersonID: "verified-" + id, Roles: []model.Role{role}, Verification: "Operator verified synthetic person"})
	}
	approveRecoveryPayload(t, s, model.SecurityChangePayload{Kind: "bootstrap", Policy: &policy, Nominations: nominations})
	target, _ := s.store.GetUserByID("recovery-target")
	return s, target
}

func installApprovedTemporaryPassword(t *testing.T, s *Server, temporary string) {
	t.Helper()
	token, _, _ := sessionTokenPair(t, s, "recovery-officer")
	response := securityCall(s, "POST", "/api/security/secrets", token, mustMarshal(t, map[string]string{"kind": "password", "value": temporary}))
	var secret struct {
		Ref string `json:"credential_ref"`
	}
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &secret) != nil || secret.Ref == "" {
		t.Fatalf("write-only temporary credential: %d %s", response.Code, response.Body.String())
	}
	approveRecoveryPayload(t, s, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: "recovery-target", Operation: "password-reset", SecretRef: secret.Ref}})
}

func TestSecurityApprovedPasswordRecoveryWithExistingMFA(t *testing.T) {
	s, target := recoveryServer(t)
	temporary, replacement := "SyntheticTemp@1234", "SyntheticReplacement@1234"
	installApprovedTemporaryPassword(t, s, temporary)
	login := securityCall(s, "POST", "/api/auth/login", "", mustMarshal(t, model.LoginRequest{Username: target.Username, Password: temporary}))
	var stage model.LoginResponse
	if login.Code != 202 || json.Unmarshal(login.Body.Bytes(), &stage) != nil {
		t.Fatalf("temporary password login: %d %s", login.Code, login.Body.String())
	}
	code, _ := auth.GenerateValidCode(*target.TOTPSecret)
	login = securityCall(s, "POST", "/api/auth/login/totp", "", mustMarshal(t, model.LoginTOTPRequest{TOTPToken: stage.TOTPToken, Code: code}))
	var signed model.AuthResponse
	if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &signed) != nil {
		t.Fatalf("recovery MFA login: %d %s", login.Code, login.Body.String())
	}
	rotated := securityCall(s, "PUT", "/api/auth/password", signed.AccessToken, mustMarshal(t, model.ChangePasswordRequest{CurrentPassword: temporary, NewPassword: replacement}))
	if rotated.Code != 200 {
		t.Fatalf("approved mandatory rotation: %d %s", rotated.Code, rotated.Body.String())
	}
	current, _ := s.store.GetUserByID(target.ID)
	if current.MustChangePassword || !auth.ComparePassword(current.PasswordHash, replacement) {
		t.Fatal("approved temporary password did not rotate")
	}
	if _, err := s.store.CompleteApprovedPasswordRecovery(target.ID, current.PasswordHash, current.SecurityRevision, target.PasswordHash, s.now()); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("recovery grant reused: %v", err)
	}
	access, _, _ := sessionTokenPair(t, s, target.ID)
	rotated = securityCall(s, "PUT", "/api/auth/password", access, mustMarshal(t, model.ChangePasswordRequest{CurrentPassword: replacement, NewPassword: temporary}))
	if rotated.Code != 403 {
		t.Fatalf("approved recovery weakened ordinary protected writes: %d %s", rotated.Code, rotated.Body.String())
	}
}

func TestSecurityApprovedPasswordAndMFARecoveryCompletesFreshSetup(t *testing.T) {
	s, target := recoveryServer(t)
	temporary, replacement := "SyntheticTemp@1234", "SyntheticReplacement@1234"
	installApprovedTemporaryPassword(t, s, temporary)
	before, _ := s.store.GetUserByID(target.ID)
	stale, _ := auth.GenerateSetupToken(s.jwtSecret, target.ID, string(target.Role), before.TokenGeneration)
	approveRecoveryPayload(t, s, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: target.ID, Operation: "mfa-reset"}})
	response := securityCall(s, "POST", "/api/auth/totp/setup", stale, nil)
	if response.Code != 401 {
		t.Fatalf("old setup credential consumed new recovery: %d %s", response.Code, response.Body.String())
	}
	response = securityCall(s, "POST", "/api/auth/login", "", mustMarshal(t, model.LoginRequest{Username: target.Username, Password: temporary}))
	var stage model.LoginResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &stage) != nil || !stage.RequiresTOTPSetup || !stage.MustChangePassword {
		t.Fatalf("recovery primary login: %d %s", response.Code, response.Body.String())
	}
	response = securityCall(s, "POST", "/api/auth/totp/setup", stage.SetupToken, nil)
	var setup model.TOTPSetupResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &setup) != nil {
		t.Fatalf("approved MFA re-enrollment: %d %s", response.Code, response.Body.String())
	}
	code, _ := auth.GenerateValidCode(setup.Secret)
	response = securityCall(s, "POST", "/api/auth/totp/enable", stage.SetupToken, mustMarshal(t, model.TOTPEnableRequest{Code: code, NewPassword: replacement}))
	var signed model.AuthResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &signed) != nil {
		t.Fatalf("approved rotation and MFA completion: %d %s", response.Code, response.Body.String())
	}
	response = securityCall(s, "GET", "/api/auth/me", signed.AccessToken, nil)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "original-reader") {
		t.Fatalf("recovery issued unusable session: %d %s", response.Code, response.Body.String())
	}
	current, _ := s.store.GetUserByID(target.ID)
	if !current.TOTPEnabled || current.MustChangePassword || !auth.ComparePassword(current.PasswordHash, replacement) {
		t.Fatal("recovery left incomplete credentials")
	}
	response = securityCall(s, "POST", "/api/auth/totp/setup", stage.SetupToken, nil)
	if response.Code != 401 {
		t.Fatal("completed recovery reused setup credential")
	}
}

func TestSecurityApprovedMFARecoveryConsumesSetupOnce(t *testing.T) {
	s, target := recoveryServer(t)
	approveRecoveryPayload(t, s, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: target.ID, Operation: "mfa-reset"}})
	previousSetup, _ := s.store.GetUserByID(target.ID)
	// A newer approved reset cannot be consumed by an in-flight older setup.
	approveRecoveryPayload(t, s, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: target.ID, Operation: "mfa-reset"}})
	staleSecret := "JBSWY3DPEHPK3PXP"
	if err := s.store.UpdateUserTOTP(target.ID, &staleSecret, false, previousSetup.TokenGeneration); !errors.Is(err, store.ErrSecurityConflict) {
		t.Fatalf("stale setup consumed replacement MFA grant: %v", err)
	}
	if err := s.store.UpdateUserTOTP(target.ID, nil, false); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("legacy recovery operation bypassed approved self completion: %v", err)
	}
	response := securityCall(s, "POST", "/api/auth/login", "", mustMarshal(t, model.LoginRequest{Username: target.Username, Password: "SyntheticExisting@1234"}))
	var stage model.LoginResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &stage) != nil || !stage.RequiresTOTPSetup {
		t.Fatalf("approved MFA recovery login: %d %s", response.Code, response.Body.String())
	}
	response = securityCall(s, "POST", "/api/auth/totp/setup", stage.SetupToken, nil)
	var setup model.TOTPSetupResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &setup) != nil {
		t.Fatalf("approved MFA setup: %d %s", response.Code, response.Body.String())
	}
	code, _ := auth.GenerateValidCode(setup.Secret)
	response = securityCall(s, "POST", "/api/auth/totp/enable", stage.SetupToken, mustMarshal(t, model.TOTPEnableRequest{Code: code}))
	var signed model.AuthResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &signed) != nil {
		t.Fatalf("approved MFA completion: %d %s", response.Code, response.Body.String())
	}
	if response := securityCall(s, "GET", "/api/auth/me", signed.AccessToken, nil); response.Code != 200 {
		t.Fatalf("MFA completion issued stale access: %d %s", response.Code, response.Body.String())
	}
	if response := securityCall(s, "POST", "/api/auth/totp/setup", stage.SetupToken, nil); response.Code != 401 {
		t.Fatalf("approved MFA setup credential reused: %d %s", response.Code, response.Body.String())
	}
	var grants int
	if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM security_mfa_recoveries WHERE user_id=?", target.ID).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("MFA recovery grant not consumed: %d %v", grants, err)
	}
}
