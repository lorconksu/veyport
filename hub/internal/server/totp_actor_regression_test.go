package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestTOTPDisableRechecksVerifiedActorAtTransactionBoundary(t *testing.T) {
	for _, mutation := range []struct{ name, sql string }{
		{"healthy", ""},
		{"admin role revoked", "DELETE FROM user_roles WHERE user_id=? AND role='admin'"},
		{"account disabled", "UPDATE users SET disabled_at=datetime('now') WHERE id=?"},
		{"credential revoked", "UPDATE users SET token_generation=token_generation+1 WHERE id=?"},
		{"MFA replaced", "UPDATE users SET totp_secret='replacement' WHERE id=?"},
		{"MFA disabled", "UPDATE users SET totp_enabled=0 WHERE id=?"},
		{"session ended", "UPDATE sessions SET ended_at=datetime('now') WHERE user_id=?"},
		{"session expired", "UPDATE sessions SET expires_at=datetime('now','-1 second') WHERE user_id=?"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			f := newLifecycleFixture(t)
			managementEnableExistingMFA(t, f)
			admin, err := f.s.store.GetUserByID(f.adminID)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := f.s.totpSecretForValidation(admin.TOTPSecret)
			if err != nil {
				t.Fatal(err)
			}
			f.s.totpCache.Clear()
			before := totpDurableState(t, f.s, f.viewerID)
			var checked atomic.Bool
			// Install the clock only after the real authentication/admin middleware
			// passed. The handler reads it after validating this actor's TOTP and
			// immediately before calling the transactional factor-removal writer.
			handler := f.s.authMiddleware(auth.TokenTypeAccess, f.s.interactiveOnly(f.s.adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				f.s.SetClock(func() time.Time {
					if checked.CompareAndSwap(false, true) {
						if mutation.sql != "" {
							managementServerExec(t, f.s, mutation.sql, f.adminID)
						}
					}
					return time.Now().UTC()
				})
				defer f.s.SetClock(func() time.Time { return time.Now().UTC() })
				f.s.handleTOTPDisable(w, r)
			}))))
			req := httptest.NewRequest("POST", testTOTPDisablePath, mustJSON(t, model.TOTPDisableRequest{UserID: f.viewerID, AdminTOTPCode: validTOTPCode(t, *secret, time.Now())}))
			req.Header.Set("Authorization", testBearerPrefix+f.adminToken)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if !checked.Load() {
				t.Fatalf("request did not reach checked actor boundary: %d %s", response.Code, response.Body.String())
			}
			if mutation.sql == "" {
				if response.Code != http.StatusOK || managementUser(t, f).TOTPEnabled {
					t.Fatalf("live actor refused: %d %s", response.Code, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusForbidden || before != totpDurableState(t, f.s, f.viewerID) {
				t.Fatalf("revoked actor changed target or wrote success audit: %d %s", response.Code, response.Body.String())
			}
		})
	}
}
