package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestPasswordRecoveryRechecksAuthenticatedSnapshotAtCommit(t *testing.T) {
	for _, mode := range []string{"healthy", "generation revoked", "MFA removed", "MFA replaced"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleFixture(t)
			managementEnableExistingMFA(t, f)
			reset := managementReset(t, f)
			recovery := managementRecovery(t, f, reset["temporary_password"].(string))
			before := managementUser(t, f)
			body := &managementDelayedBody{reader: strings.NewReader(`{"new_password":"SnapshotPermanent!Password123"}`), before: func() { mutateManagementRecoveryAuthority(t, f, before, mode) }}
			req := httptest.NewRequest("POST", "/api/auth/password/recovery", body)
			req.Header.Set("Authorization", testBearerPrefix+recovery)
			response := httptest.NewRecorder()
			f.s.routes().ServeHTTP(response, req)
			live := managementUser(t, f)
			if mode == "healthy" {
				if response.Code != http.StatusOK || live.MustChangePassword {
					t.Fatal("healthy MFA-authenticated snapshot did not complete recovery")
				}
				return
			}
			expectedSSH := before.SSHCredentialGeneration
			if mode == "MFA removed" || mode == "MFA replaced" {
				expectedSSH++
			}
			if response.Code != http.StatusConflict || !live.MustChangePassword || live.PasswordHash != before.PasswordHash || live.SSHCredentialGeneration != expectedSSH {
				t.Fatalf("revoked recovery changed credential authority: status=%d required_change=%v", response.Code, live.MustChangePassword)
			}
		})
	}
}

func mutateManagementRecoveryAuthority(t *testing.T, f *lifecycleFixture, before *model.User, mode string) {
	t.Helper()
	switch mode {
	case "healthy":
		return
	case "generation revoked":
		if _, err := f.s.store.IncrementTokenGeneration(f.viewerID); err != nil {
			t.Fatal(err)
		}
	case "MFA removed":
		if err := f.s.store.UpdateUserTOTP(f.viewerID, nil, false); err != nil {
			t.Fatal(err)
		}
	case "MFA replaced":
		replacement := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
		if err := f.s.store.UpdateUserTOTP(f.viewerID, &replacement, true); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown authority mutation %q", mode)
	}
	if mode == "generation revoked" {
		return
	}
	live := managementUser(t, f)
	if live.TokenGeneration != before.TokenGeneration+1 || live.SSHCredentialGeneration != before.SSHCredentialGeneration+1 || live.SecurityRevision == before.SecurityRevision || live.PasswordHash != before.PasswordHash {
		t.Fatal("MFA change did not revoke both credential epochs and retain the password")
	}
}
