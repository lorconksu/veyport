package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

const historyOutgoingPassword = "OutgoingPermanent!1234"

func TestPasswordHistoryEndpointRejectsPriorBehindLegacySeedAfterDepthReduction(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	u, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	priorHash, err := auth.HashPassword(historyOutgoingPassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{priorHash, u.PasswordHash} {
		if err := s.store.AddPasswordHistory(u.ID, hash); err != nil {
			t.Fatal(err)
		}
	}
	setHistoryDepthOne(t, s)
	rejected := lifecycleRequest(t, s, "PUT", "/api/auth/password", token, model.ChangePasswordRequest{CurrentPassword: testPassword, NewPassword: historyOutgoingPassword})
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("reuse status %d: %s", rejected.Code, rejected.Body.String())
	}
	after, err := s.store.GetUserByID(u.ID)
	if err != nil || after.PasswordHash != u.PasswordHash || after.TokenGeneration != u.TokenGeneration {
		t.Fatal("rejection mutated active credential")
	}
}

func setHistoryDepthOne(t *testing.T, s *Server) {
	t.Helper()
	settings := s.store.GetAuditSettings()
	settings.PasswordHistoryCount = 1
	if err := s.store.UpdateAuditSettings(settings); err != nil {
		t.Fatal(err)
	}
}

func assertHistoryPassword(t *testing.T, s *Server, userID, password string, want bool) {
	t.Helper()
	got, err := s.store.PasswordMatchesRecent(userID, password, 1)
	if err != nil || got != want {
		t.Fatalf("password history match = %t, want %t; error: %v", got, want, err)
	}
}

func TestPasswordHistoryOrdinaryChangeDepthOne(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	u, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	setHistoryDepthOne(t, s)
	current := testPassword
	for _, next := range []string{historyOutgoingPassword, "NextPermanent!1234"} {
		before, err := s.store.GetUserByID(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		// Current-password reuse must fail even with no seeded history row.
		rejected := lifecycleRequest(t, s, "PUT", "/api/auth/password", token, model.ChangePasswordRequest{CurrentPassword: current, NewPassword: current})
		if rejected.Code != http.StatusBadRequest {
			t.Fatalf("active password reuse status %d: %s", rejected.Code, rejected.Body.String())
		}
		done := lifecycleRequest(t, s, "PUT", "/api/auth/password", token, model.ChangePasswordRequest{CurrentPassword: current, NewPassword: next})
		if done.Code != http.StatusOK {
			t.Fatalf("ordinary change status %d: %s", done.Code, done.Body.String())
		}
		assertHistoryPassword(t, s, u.ID, current, true)
		assertHistoryPassword(t, s, u.ID, next, false)
		after, err := s.store.GetUserByID(u.ID)
		if err != nil || after.TokenGeneration != before.TokenGeneration+1 || after.SSHCredentialGeneration != before.SSHCredentialGeneration+1 {
			t.Fatalf("change failed to revoke credential generations: %v", err)
		}
		token, _, _ = sessionTokenPair(t, s, u.ID)
		rejected = lifecycleRequest(t, s, "PUT", "/api/auth/password", token, model.ChangePasswordRequest{CurrentPassword: next, NewPassword: current})
		if rejected.Code != http.StatusBadRequest {
			t.Fatalf("prior password reuse status %d: %s", rejected.Code, rejected.Body.String())
		}
		current = next
	}
	assertHistoryPassword(t, s, u.ID, testPassword, false)
}

func TestPasswordHistoryResetCompletionDepthOne(t *testing.T) {
	for _, existingMFA := range []bool{false, true} {
		name := "initial-TOTP-enrollment"
		if existingMFA {
			name = "existing-TOTP-recovery"
		}
		t.Run(name, func(t *testing.T) {
			f := newLifecycleFixture(t)
			setHistoryDepthOne(t, f.s)
			hash, err := auth.HashPassword(historyOutgoingPassword)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.s.store.UpdateUserPassword(f.viewerID, hash); err != nil {
				t.Fatal(err)
			}
			if err := f.s.store.SetTemporaryPasswordState(f.viewerID, false, nil); err != nil {
				t.Fatal(err)
			}
			if existingMFA {
				managementEnableExistingMFA(t, f)
			}
			// Retrying a reset must not let a temporary credential displace history.
			managementReset(t, f)
			temporary := managementReset(t, f)["temporary_password"].(string)
			assertHistoryPassword(t, f.s, f.viewerID, historyOutgoingPassword, true)
			before := managementUser(t, f)
			replacement := "ReplacementPermanent!1234"
			var token, secret string
			path := "/api/auth/password/recovery"
			if existingMFA {
				token = managementRecovery(t, f, temporary)
			} else {
				login := lifecycleRequest(t, f.s, "POST", "/api/auth/login", "", model.LoginRequest{Username: lifecycleViewerName, Password: temporary})
				if login.Code != http.StatusOK {
					t.Fatalf("setup login status %d", login.Code)
				}
				token = managementJSON(t, login)["setup_token"].(string)
				setup := lifecycleRequest(t, f.s, "POST", "/api/auth/totp/setup", token, nil)
				if setup.Code != http.StatusOK {
					t.Fatalf("TOTP setup status %d", setup.Code)
				}
				secret = managementJSON(t, setup)["secret"].(string)
				path = "/api/auth/totp/enable"
			}
			for _, candidate := range []string{historyOutgoingPassword, temporary, replacement} {
				body := map[string]string{"new_password": candidate}
				if !existingMFA {
					body["code"] = validTOTPCode(t, secret, f.s.now())
				}
				response := lifecycleRequest(t, f.s, "POST", path, token, body)
				want := http.StatusBadRequest
				if candidate == replacement {
					want = http.StatusOK
				}
				if response.Code != want {
					t.Fatalf("completion status %d, want %d: %s", response.Code, want, response.Body.String())
				}
				// A rejected password does not consume the credential generation.
				if want == http.StatusBadRequest && managementUser(t, f).TokenGeneration != before.TokenGeneration {
					t.Fatal("rejected password consumed recovery authority")
				}
				now := f.s.now().Add(31 * time.Second)
				f.s.SetClock(func() time.Time { return now })
			}
			after := managementUser(t, f)
			if after.MustChangePassword || after.TempPasswordExpiresAt != nil || !after.TOTPEnabled || !auth.ComparePassword(after.PasswordHash, replacement) {
				t.Fatal("completion left incomplete password or MFA state")
			}
			assertHistoryPassword(t, f.s, f.viewerID, historyOutgoingPassword, true)
			assertHistoryPassword(t, f.s, f.viewerID, temporary, false)
			assertHistoryPassword(t, f.s, f.viewerID, replacement, false)
		})
	}
}

func TestPasswordHistoryNewAccountTOTPEnrollmentRejectsActiveTemporaryPassword(t *testing.T) {
	f := newLifecycleFixture(t)
	setHistoryDepthOne(t, f.s)
	assertHistoryPassword(t, f.s, f.viewerID, f.viewerPass, false)
	login := lifecycleRequest(t, f.s, "POST", "/api/auth/login", "", model.LoginRequest{Username: lifecycleViewerName, Password: f.viewerPass})
	if login.Code != http.StatusOK {
		t.Fatalf("setup login status %d", login.Code)
	}
	token := managementJSON(t, login)["setup_token"].(string)
	setup := lifecycleRequest(t, f.s, "POST", "/api/auth/totp/setup", token, nil)
	if setup.Code != http.StatusOK {
		t.Fatalf("TOTP setup status %d", setup.Code)
	}
	secret := managementJSON(t, setup)["secret"].(string)
	code := validTOTPCode(t, secret, f.s.now())
	rejected := lifecycleRequest(t, f.s, "POST", "/api/auth/totp/enable", token, model.TOTPEnableRequest{Code: code, NewPassword: f.viewerPass})
	if rejected.Code != http.StatusBadRequest || !managementUser(t, f).MustChangePassword || managementUser(t, f).TOTPEnabled {
		t.Fatalf("enrollment accepted the active temporary password: %d", rejected.Code)
	}
	now := f.s.now().Add(31 * time.Second)
	f.s.SetClock(func() time.Time { return now })
	code = validTOTPCode(t, secret, now)
	done := lifecycleRequest(t, f.s, "POST", "/api/auth/totp/enable", token, model.TOTPEnableRequest{Code: code, NewPassword: historyOutgoingPassword})
	if done.Code != http.StatusOK {
		t.Fatalf("enrollment status %d: %s", done.Code, done.Body.String())
	}
	assertHistoryPassword(t, f.s, f.viewerID, f.viewerPass, false)
	assertHistoryPassword(t, f.s, f.viewerID, historyOutgoingPassword, false)
}
