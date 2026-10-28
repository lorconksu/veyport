package server

import (
	"encoding/json"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"testing"
)

func TestDaybreakRevokedApprovedMFAGrantRefusedThroughHTTP(t *testing.T) {
	s, target := recoveryServer(t)
	approveRecoveryPayload(t, s, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: target.ID, Operation: "mfa-reset"}})
	login := securityCall(s, "POST", "/api/auth/login", "", mustMarshal(t, model.LoginRequest{Username: target.Username, Password: "SyntheticExisting@1234"}))
	var stage model.LoginResponse
	if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &stage) != nil || stage.SetupToken == "" {
		t.Fatalf("initial setup login %d %s", login.Code, login.Body.String())
	}
	setup := securityCall(s, "POST", "/api/auth/totp/setup", stage.SetupToken, nil)
	var mfa model.TOTPSetupResponse
	if setup.Code != 200 || json.Unmarshal(setup.Body.Bytes(), &mfa) != nil {
		t.Fatalf("initial setup %d %s", setup.Code, setup.Body.String())
	}
	var oldGrant int
	if err := s.store.DB().QueryRow("SELECT token_generation FROM security_mfa_recoveries WHERE user_id=?", target.ID).Scan(&oldGrant); err != nil {
		t.Fatal(err)
	}
	approveRecoveryPayload(t, s, model.SecurityChangePayload{Kind: "role", Role: &model.SecurityRoleChange{UserID: target.ID, Role: model.RoleSecurityApprover, Grant: true}})
	installApprovedTemporaryPassword(t, s, "SyntheticTemporary@1234")
	login = securityCall(s, "POST", "/api/auth/login", "", mustMarshal(t, model.LoginRequest{Username: target.Username, Password: "SyntheticTemporary@1234"}))
	if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &stage) != nil || stage.SetupToken == "" {
		t.Fatalf("recovery login %d %s", login.Code, login.Body.String())
	}
	code := validTOTPCode(t, mfa.Secret, s.now())
	done := securityCall(s, "POST", "/api/auth/totp/enable", stage.SetupToken, mustMarshal(t, model.TOTPEnableRequest{Code: code, NewPassword: "NewPermanent@1234"}))
	after, _ := s.store.GetUserByID(target.ID)
	t.Logf("old_grant_generation=%d final_generation=%d response=%d mfa_enabled=%v", oldGrant, after.TokenGeneration, done.Code, after.TOTPEnabled)
	if done.Code == 200 || after.TOTPEnabled {
		t.Fatal("stale grant revived")
	}
	if !after.MustChangePassword || !auth.ComparePassword(after.PasswordHash, "SyntheticTemporary@1234") {
		t.Fatal("refusal consumed temporary credential")
	}
	var grant int
	if err := s.store.DB().QueryRow("SELECT token_generation FROM security_mfa_recoveries WHERE user_id=?", target.ID).Scan(&grant); err != nil || grant != oldGrant {
		t.Fatal("revoked grant advanced")
	}
}
