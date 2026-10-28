package server

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestDaybreakPartialProtectedSetupOnMFAPersistenceFailure(t *testing.T) {
	f := newLifecycleFixture(t)
	if _, err := f.s.store.DB().Exec("INSERT INTO user_roles(user_id,role) VALUES(?,'original-reader')", f.viewerID); err != nil {
		t.Fatal(err)
	}
	u := managementUser(t, f)
	temporary := "TemporaryRecovery!1234"
	hash, err := auth.HashPassword(temporary)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.store.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration}, hash, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	login := lifecycleRequest(t, f.s, "POST", "/api/auth/login", "", model.LoginRequest{Username: lifecycleViewerName, Password: temporary})
	if login.Code != 200 {
		t.Fatalf("login %d %s", login.Code, login.Body.String())
	}
	setupToken := managementJSON(t, login)["setup_token"].(string)
	setup := lifecycleRequest(t, f.s, "POST", "/api/auth/totp/setup", setupToken, nil)
	if setup.Code != 200 {
		t.Fatalf("setup %d %s", setup.Code, setup.Body.String())
	}
	secret := managementJSON(t, setup)["secret"].(string)
	if _, err := f.s.store.DB().Exec("CREATE TRIGGER daybreak_mfa_failure BEFORE UPDATE OF totp_enabled ON users WHEN NEW.totp_enabled=1 BEGIN SELECT RAISE(ABORT,'synthetic MFA failure'); END"); err != nil {
		t.Fatal(err)
	}
	replacement := "PermanentRecovery!1234"
	done := lifecycleRequest(t, f.s, "POST", "/api/auth/totp/enable", setupToken, model.TOTPEnableRequest{Code: validTOTPCode(t, secret, f.s.now()), NewPassword: replacement})
	after := managementUser(t, f)
	t.Logf("response=%d hash_rotated=%v must_change=%v mfa_enabled=%v", done.Code, auth.ComparePassword(after.PasswordHash, replacement), after.MustChangePassword, after.TOTPEnabled)
	if done.Code == 200 || !auth.ComparePassword(after.PasswordHash, temporary) || !after.MustChangePassword || after.TOTPEnabled {
		t.Fatal("setup failure consumed credential")
	}
	if after.TokenGeneration != u.TokenGeneration+1 {
		t.Fatal("failure advanced generation")
	}
	var grants int
	if err := f.s.store.DB().QueryRow("SELECT COUNT(*) FROM local_break_glass_recoveries WHERE user_id=? AND password_pending=1 AND token_generation=?", u.ID, after.TokenGeneration).Scan(&grants); err != nil || grants != 1 {
		t.Fatal("failure consumed authority")
	}
	if _, err := f.s.store.DB().Exec("DROP TRIGGER daybreak_mfa_failure"); err != nil {
		t.Fatal(err)
	}
	// A failed write must leave the same setup snapshot usable on the next code.
	retryAt := f.s.now().Add(30 * time.Second)
	f.s.SetClock(func() time.Time { return retryAt })
	retry := lifecycleRequest(t, f.s, "POST", "/api/auth/totp/enable", setupToken, model.TOTPEnableRequest{Code: validTOTPCode(t, secret, f.s.now()), NewPassword: replacement})
	if retry.Code != 200 {
		t.Fatalf("retry %d %s", retry.Code, retry.Body.String())
	}
}

func TestDaybreakApprovedSetupPersistenceFailurePreservesAuthority(t *testing.T) {
	s, target := recoveryServer(t)
	approveRecoveryPayload(t, s, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: target.ID, Operation: "mfa-reset"}})
	installApprovedTemporaryPassword(t, s, "SyntheticTemporary@1234")
	login := securityCall(s, "POST", "/api/auth/login", "", mustMarshal(t, model.LoginRequest{Username: target.Username, Password: "SyntheticTemporary@1234"}))
	var stage model.LoginResponse
	if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &stage) != nil || stage.SetupToken == "" {
		t.Fatal("temporary login failed")
	}
	setup := securityCall(s, "POST", "/api/auth/totp/setup", stage.SetupToken, nil)
	var mfa model.TOTPSetupResponse
	if setup.Code != 200 || json.Unmarshal(setup.Body.Bytes(), &mfa) != nil {
		t.Fatal("setup failed")
	}
	before, _ := s.store.GetUserByID(target.ID)
	var originalMFA, originalPassword int
	if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM security_mfa_recoveries WHERE user_id=?", target.ID).Scan(&originalMFA); err != nil {
		t.Fatal(err)
	}
	if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM security_password_recoveries WHERE user_id=?", target.ID).Scan(&originalPassword); err != nil {
		t.Fatal(err)
	}
	managementServerExec(t, s, "CREATE TRIGGER daybreak_approved_failure BEFORE UPDATE OF totp_enabled ON users WHEN NEW.totp_enabled=1 BEGIN SELECT RAISE(ABORT,'synthetic MFA failure'); END")
	done := securityCall(s, "POST", "/api/auth/totp/enable", stage.SetupToken, mustMarshal(t, model.TOTPEnableRequest{Code: validTOTPCode(t, mfa.Secret, s.now()), NewPassword: "NewPermanent@1234"}))
	after, _ := s.store.GetUserByID(target.ID)
	if done.Code == 200 || !reflect.DeepEqual(before, after) {
		t.Fatal("failed approved setup changed credentials")
	}
	var mfaCount, passwordCount int
	_ = s.store.DB().QueryRow("SELECT COUNT(*) FROM security_mfa_recoveries WHERE user_id=?", target.ID).Scan(&mfaCount)
	_ = s.store.DB().QueryRow("SELECT COUNT(*) FROM security_password_recoveries WHERE user_id=?", target.ID).Scan(&passwordCount)
	if mfaCount != 1 || passwordCount != 1 || originalMFA != mfaCount || originalPassword != passwordCount {
		t.Fatal("failed approved setup consumed grants")
	}
	managementServerExec(t, s, "DROP TRIGGER daybreak_approved_failure")
	retryAt := s.now().Add(30 * time.Second)
	s.SetClock(func() time.Time { return retryAt })
	retry := securityCall(s, "POST", "/api/auth/totp/enable", stage.SetupToken, mustMarshal(t, model.TOTPEnableRequest{Code: validTOTPCode(t, mfa.Secret, s.now()), NewPassword: "NewPermanent@1234"}))
	if retry.Code != 200 {
		t.Fatalf("live MFA authority did not survive password apply/completion: %d %s", retry.Code, retry.Body.String())
	}
}
