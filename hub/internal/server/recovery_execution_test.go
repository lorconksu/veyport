package server

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/sshconfig"
	"github.com/wyiu/veyport/hub/internal/testaudit"
	"github.com/wyiu/veyport/hub/internal/userca"
)

func recoveryCommandLogin(t *testing.T, s *Server, target *model.User, password string, clock *testaudit.Clock) model.AuthResponse {
	t.Helper()
	stage := securityCall(s, "POST", "/api/auth/login", "", mustMarshal(t, model.LoginRequest{Username: target.Username, Password: password}))
	if stage.Code != http.StatusAccepted {
		t.Fatalf("recovery password stage status=%d", stage.Code)
	}
	var login model.LoginResponse
	decodeResult(t, stage.Body.Bytes(), &login)
	code, err := totp.GenerateCode(*target.TOTPSecret, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	second := securityCall(s, "POST", "/api/auth/login/totp", "", mustMarshal(t, model.LoginTOTPRequest{TOTPToken: login.TOTPToken, Code: code}))
	if second.Code != http.StatusOK {
		t.Fatalf("recovery MFA stage status=%d", second.Code)
	}
	var signed model.AuthResponse
	decodeResult(t, second.Body.Bytes(), &signed)
	var recovered model.LoginResponse
	decodeResult(t, second.Body.Bytes(), &recovered)
	if recovered.MustChangePassword {
		if recovered.RecoveryToken == "" {
			t.Fatal("missing purpose-bound recovery")
		}
		signed.AccessToken = recovered.RecoveryToken
	}
	return signed
}

func TestApprovedPasswordRecoveryBlocksCertificateAndExistingCommandAuthorityUntilCompletion(t *testing.T) {
	s, target := recoveryServer(t)
	clock := testaudit.NewClock()
	s.SetClock(clock.Now)
	var err error
	s.userCA, err = userca.InitUserCA(s.store, s.storageKey)
	if err != nil {
		t.Fatal(err)
	}
	s.sshHostKey, err = userca.InitHostKey(s.store, s.storageKey)
	if err != nil {
		t.Fatal(err)
	}
	s.sshConfig = sshconfig.Load(s.store, "")
	const node = "approved-recovery-command-node"
	if err := s.store.CreateServer(&model.Server{ID: node, Name: node, Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	before, _, _ := sessionTokenPair(t, s, target.ID)
	publicKey := testSSHClientPublicKey(t)
	issued := postSSHCert(t, s.routes(), before, map[string]string{"public_key": publicKey})
	if issued.Code != http.StatusOK {
		t.Fatalf("pre-recovery certificate status=%d", issued.Code)
	}
	var certificate model.SSHCertificateResponse
	decodeResult(t, issued.Body.Bytes(), &certificate)
	existing := parseSSHCertFromResponse(t, certificate.Certificate)
	if existing.ValidBefore <= uint64(clock.Now().Unix()) {
		t.Fatal("pre-recovery certificate was not live")
	}
	if _, err := AuthorizeTerminalExecution(s.store, target.ID, node); err != nil {
		t.Fatalf("completed principal lacked pre-recovery command authority: %v", err)
	}

	temporary, replacement := "SyntheticCommandTemp@1234", "SyntheticCommandReplacement@1234"
	installApprovedTemporaryPassword(t, s, temporary)
	if _, err := AuthorizeTerminalExecution(s.store, target.ID, node); !errors.Is(err, ErrTerminalNotAuthorized) {
		t.Errorf("existing certificate/command authorization allowed unfinished recovery: %v", err)
	}
	signed := recoveryCommandLogin(t, s, target, temporary, clock)
	if signed.AccessToken == "" {
		t.Fatal("approved temporary credential did not issue a recovery challenge")
	}
	denied := postSSHCert(t, s.routes(), signed.AccessToken, map[string]string{"public_key": publicKey})
	if denied.Code != http.StatusForbidden {
		t.Errorf("unfinished recovery issued certificate: status=%d", denied.Code)
	}
	if count := countSSHAuditAction(t, s, model.AuditSSHCertIssueRefused); count != 0 {
		t.Errorf("recovery certificate denial audit count=%d want0", count)
	}

	completed := securityCall(s, "POST", "/api/auth/password/recovery", signed.AccessToken, mustMarshal(t, map[string]string{"new_password": replacement}))
	if completed.Code != http.StatusOK {
		t.Fatalf("approved password completion status=%d", completed.Code)
	}
	clock.Advance(30 * time.Second)
	signed = recoveryCommandLogin(t, s, target, replacement, clock)
	if signed.User.MustChangePassword {
		t.Fatal("completed approved recovery remained pending")
	}
	if _, err := AuthorizeTerminalExecution(s.store, target.ID, node); err != nil {
		t.Fatalf("completed recovery did not restore existing command rights: %v", err)
	}
	restored := postSSHCert(t, s.routes(), signed.AccessToken, map[string]string{"public_key": publicKey})
	if restored.Code != http.StatusOK {
		t.Fatalf("completed recovery certificate status=%d", restored.Code)
	}
}

func TestMandatoryPasswordChangeBlocksEveryExecutionPrincipalKind(t *testing.T) {
	for _, kind := range []struct {
		name     string
		provider model.AuthProvider
		role     model.Role
	}{
		{"local_admin", model.AuthProviderLocal, model.RoleAdmin},
		{"ldap_admin", model.AuthProviderLDAP, model.RoleAdmin},
		{"assigned_ldap_terminal_user", model.AuthProviderLDAP, model.RoleViewer},
	} {
		t.Run(kind.name, func(t *testing.T) {
			s := testServer(t)
			u := &model.User{ID: kind.name, Username: kind.name, Email: kind.name + "@test.invalid", Role: kind.role, AuthProvider: kind.provider, ExternalID: kind.name, LDAPUsername: "synthetic_os_user", TerminalAccess: true, MustChangePassword: true}
			if err := s.store.CreateUser(u); err != nil {
				t.Fatal(err)
			}
			if err := s.store.CreateServer(&model.Server{ID: "assigned-node", Name: "assigned-node", Status: "online", Labels: "{}"}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.store.CreatePermission(u.ID, "assigned-node", "/"); err != nil {
				t.Fatal(err)
			}
			if _, err := AuthorizeTerminalExecution(s.store, u.ID, "assigned-node"); !errors.Is(err, ErrTerminalNotAuthorized) {
				t.Errorf("unfinished credential authorized execution: %v", err)
			}
			if _, err := s.store.DB().Exec("UPDATE users SET must_change_password=0 WHERE id=?", u.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := AuthorizeTerminalExecution(s.store, u.ID, "assigned-node"); err != nil {
				t.Fatalf("completion failed to restore ordinary role/assignment authority: %v", err)
			}
		})
	}
}
