package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestRecoveryPasswordReuseRejectionsAreAudited(t *testing.T) {
	f := newLifecycleFixture(t)
	setHistoryDepthOne(t, f.s)
	managementEnableExistingMFA(t, f)
	// The fixture starts with a temporary password; establish a permanent one.
	hash, err := auth.HashPassword(historyOutgoingPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.store.UpdateUserPassword(f.viewerID, hash); err != nil {
		t.Fatal(err)
	}
	temporary := managementReset(t, f)["temporary_password"].(string)
	token := managementRecovery(t, f, temporary)
	for _, password := range []string{temporary, historyOutgoingPassword} {
		action := model.AuditUserPasswordReuseRejected
		_, before, err := f.s.store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		rejected := lifecycleRequest(t, f.s, "POST", "/api/auth/password/recovery", token, map[string]string{"new_password": password})
		if rejected.Code != 400 {
			t.Fatalf("rejection status=%d", rejected.Code)
		}
		entries, count, err := f.s.store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 100})
		if err != nil || count != before+1 {
			t.Fatalf("missing reuse event: before=%d after=%d err=%v", before, count, err)
		}
		entry := entries[0]
		if entry.UserID == nil || *entry.UserID != f.viewerID || entry.Outcome != model.AuditOutcomeFailure || entry.IPAddress == nil || *entry.IPAddress == "" || entry.CorrelationID == nil || *entry.CorrelationID == "" {
			t.Fatalf("incomplete failure event: %+v", entry)
		}
		raw, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), password) || strings.Contains(string(raw), hash) {
			t.Fatal("audit contains credential material")
		}
	}
}

func TestLDAPGovernedPasswordRecoveryFailsAtEveryBoundary(t *testing.T) {
	for _, protected := range []bool{false, true} {
		t.Run(fmt.Sprintf("protected-%t", protected), func(t *testing.T) {
			s, protectedTarget := recoveryServer(t)
			target := protectedTarget
			if !protected {
				quickSecurityUser(t, s, "ordinary-ldap", model.RoleViewer)
				target, _ = s.store.GetUserByID("ordinary-ldap")
			}
			payload := model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: target.ID, Operation: "password-reset", SecretRef: recoveryPasswordSecret(t, s, "TemporaryLDAP!1234")}}
			change := prepareRecoveryPayload(t, s, payload)
			// A target can change directory source after independent approval.
			if _, err := s.store.DB().Exec("UPDATE users SET auth_provider='ldap' WHERE id=?", target.ID); err != nil {
				t.Fatal(err)
			}
			before, _ := s.store.GetUserByID(target.ID)
			state, _ := s.store.GetPolicyState()
			proposal := authorization.Proposal{Reason: "Directory password reset must be refused", ExpectedVersion: state.Active.Version, Change: mustMarshal(t, payload)}
			preview, _ := authorization.Normalize(proposal)
			token, _, _ := sessionTokenPair(t, s, "recovery-officer")
			response := securityCall(s, "POST", "/api/security/changes/preview", token, mustMarshal(t, map[string]any{"reason": proposal.Reason, "expected_version": proposal.ExpectedVersion, "change": payload}))
			if response.Code != 400 || !strings.Contains(response.Body.String(), "local accounts only") {
				t.Fatalf("LDAP preview: %d %s", response.Code, response.Body.String())
			}
			proof, _ := s.store.IssueStepup("recovery-officer", "officer-session", authorization.ActionRequest, preview.Digest, s.now())
			if _, err := s.securityService().Request("recovery-officer", "officer-session", proof, proposal); !errors.Is(err, store.ErrLocalPasswordOnly) {
				t.Fatalf("LDAP request: %v", err)
			}
			// Call the store directly so service validation cannot mask a gap.
			direct := change
			direct.ID, direct.ApprovedBytes = "directory-request", preview.Bytes
			if err := s.store.CreateSecurityChange(direct, nil, "officer-session", proof, s.now()); !errors.Is(err, store.ErrLocalPasswordOnly) {
				t.Fatalf("LDAP store request: %v", err)
			}
			proof, _ = s.store.IssueStepup("recovery-officer", "officer-session", authorization.ActionApply, change.Digest, s.now())
			if _, err := s.securityService().Apply(t.Context(), change.ID, "recovery-officer", "officer-session", proof, s.securityTransition); !errors.Is(err, store.ErrLocalPasswordOnly) {
				t.Fatalf("LDAP apply: %v", err)
			}
			after, _ := s.store.GetUserByID(target.ID)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("LDAP apply changed directory shadow credentials")
			}
		})
	}
}

func TestLDAPApprovedPasswordCompletionIndependentlyFailsClosed(t *testing.T) {
	for _, protected := range []bool{false, true} {
		t.Run(fmt.Sprintf("protected-%t", protected), func(t *testing.T) {
			s, target := recoveryServer(t)
			if !protected {
				quickSecurityUser(t, s, "ordinary-completion", model.RoleViewer)
				target, _ = s.store.GetUserByID("ordinary-completion")
			}
			payload := model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: target.ID, Operation: "password-reset", SecretRef: recoveryPasswordSecret(t, s, "TemporaryLDAP!1234")}}
			approveRecoveryPayload(t, s, payload)
			// Reproduce legacy invalid state without touching a directory service.
			if _, err := s.store.DB().Exec("UPDATE users SET auth_provider='ldap' WHERE id=?", target.ID); err != nil {
				t.Fatal(err)
			}
			before, _ := s.store.GetUserByID(target.ID)
			_, err := s.store.CompleteApprovedPasswordRecoveryAudited(store.PasswordRecoverySnapshot{UserID: before.ID, PasswordHash: before.PasswordHash, SecurityRevision: before.SecurityRevision, TokenGeneration: before.TokenGeneration}, "must-not-install", s.now(), 1, model.AuditEntry{Action: model.AuditUserPasswordChanged})
			if !errors.Is(err, store.ErrLocalPasswordOnly) {
				t.Fatalf("LDAP completion: %v", err)
			}
			token, err := auth.GenerateTokenWithExpiry(s.jwtSecret, before.ID, string(before.Role), auth.TokenTypePasswordRecovery, 5*time.Minute, before.TokenGeneration)
			if err != nil {
				t.Fatal(err)
			}
			response := securityCall(s, "POST", "/api/auth/password/recovery", token, mustMarshal(t, map[string]string{"new_password": "NewLocalPassword!1234"}))
			if response.Code == 200 {
				t.Fatal("LDAP HTTP completion accepted")
			}
			after, _ := s.store.GetUserByID(target.ID)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("LDAP completion mutated credentials")
			}
		})
	}
}

// Exercise the compiled production command against the registered user's actual
// file-backed database, then complete recovery through the real HTTP routes.
func TestBreakGlassCLIHistorySurvivesReenrollment(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "veyport")
	build := exec.Command("go", "build", "-mod=readonly", "-buildvcs=false", "-o", binary, "./cmd/veyport")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v %s", err, output)
	}
	for _, test := range []struct {
		name               string
		changed, protected bool
	}{{name: "registered"}, {name: "ordinarily-changed", changed: true}, {name: "protected-local", protected: true}} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recovery.db")
			st, err := store.New(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			s := New(Config{Store: st, JWTSecret: "break-glass-regression-secret", IsDev: true})
			token := registerAndGetAdminToken(t, s)
			setHistoryDepthOne(t, s)
			settings := st.GetAuditSettings()
			settings.TemporaryPasswordTTLHours = 2
			if err := st.UpdateAuditSettings(settings); err != nil {
				t.Fatal(err)
			}
			outgoing := testPassword
			if test.changed {
				response := lifecycleRequest(t, s, "PUT", "/api/auth/password", token, model.ChangePasswordRequest{CurrentPassword: outgoing, NewPassword: historyOutgoingPassword})
				if response.Code != 200 {
					t.Fatalf("ordinary change: %d %s", response.Code, response.Body.String())
				}
				outgoing = historyOutgoingPassword
			}
			u, _ := st.GetUserByUsername("admin")
			if test.protected {
				if _, err := st.DB().Exec("INSERT INTO user_roles(user_id,role) VALUES(?,'original-reader')", u.ID); err != nil {
					t.Fatal(err)
				}
			}
			var temporary string
			for range 2 {
				before, _ := st.GetUserByID(u.ID)
				cmd := exec.Command(binary, "admin", "reset-totp", "--username", u.Username, "--db", path)
				cmd.Env = os.Environ()
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("CLI reset: %v %s", err, output)
				}
				for _, line := range strings.Split(string(output), "\n") {
					if value, ok := strings.CutPrefix(line, "Temporary password: "); ok {
						temporary = value
					}
				}
				after, _ := st.GetUserByID(u.ID)
				if temporary == "" || !after.MustChangePassword || after.TOTPEnabled || after.TOTPSecret != nil || after.TempPasswordExpiresAt == nil || !auth.ComparePassword(after.PasswordHash, temporary) || after.TokenGeneration != before.TokenGeneration+1 || after.SSHCredentialGeneration != before.SSHCredentialGeneration+1 {
					t.Fatal("CLI did not install expiring temporary recovery state")
				}
				if delta := time.Until(*after.TempPasswordExpiresAt); delta < 119*time.Minute || delta > 121*time.Minute {
					t.Fatal("CLI ignored configured TTL")
				}
				assertHistoryPassword(t, s, u.ID, outgoing, true)
			}
			login := lifecycleRequest(t, s, "POST", "/api/auth/login", "", model.LoginRequest{Username: u.Username, Password: temporary})
			if login.Code != 200 {
				t.Fatalf("temporary login: %d %s", login.Code, login.Body.String())
			}
			setupToken := managementJSON(t, login)["setup_token"].(string)
			setup := lifecycleRequest(t, s, "POST", "/api/auth/totp/setup", setupToken, nil)
			if setup.Code != 200 {
				t.Fatalf("setup: %d %s", setup.Code, setup.Body.String())
			}
			secret := managementJSON(t, setup)["secret"].(string)
			for _, candidate := range []string{outgoing, temporary} {
				rejected := lifecycleRequest(t, s, "POST", "/api/auth/totp/enable", setupToken, model.TOTPEnableRequest{Code: validTOTPCode(t, secret, s.now()), NewPassword: candidate})
				if rejected.Code != 400 {
					t.Fatalf("CLI reenrollment reused credential: %d %s", rejected.Code, rejected.Body.String())
				}
				now := s.now().Add(31 * time.Second)
				s.SetClock(func() time.Time { return now })
			}
			replacement := "ReenrolledPermanent!1234"
			done := lifecycleRequest(t, s, "POST", "/api/auth/totp/enable", setupToken, model.TOTPEnableRequest{Code: validTOTPCode(t, secret, s.now()), NewPassword: replacement})
			if done.Code != 200 {
				t.Fatalf("reenrollment: %d %s", done.Code, done.Body.String())
			}
			access := managementJSON(t, done)["access_token"].(string)
			rejected := lifecycleRequest(t, s, "PUT", "/api/auth/password", access, model.ChangePasswordRequest{CurrentPassword: replacement, NewPassword: outgoing})
			want := 400
			if test.protected {
				want = 403
			}
			if rejected.Code != want {
				t.Fatalf("outgoing permanent password reuse after CLI recovery: %d %s", rejected.Code, rejected.Body.String())
			}
			assertHistoryPassword(t, s, u.ID, temporary, false)
			var grants int
			if err := st.DB().QueryRow("SELECT COUNT(*) FROM local_break_glass_recoveries WHERE user_id=?", u.ID).Scan(&grants); err != nil || grants != 0 {
				t.Fatal("reenrollment did not consume break-glass grant")
			}
		})
	}
}
