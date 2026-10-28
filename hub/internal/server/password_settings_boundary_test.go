package server

import (
	"context"
	"database/sql/driver"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/store"
	"modernc.org/sqlite"
)

func TestPasswordCompletionIncludesDelayedSettingsRead(t *testing.T) {
	for _, operation := range []string{"password", "protected password", "combined setup"} {
		t.Run(operation, func(t *testing.T) {
			var s *Server
			var token, userID, method, path, body string
			if operation == "protected password" {
				s, _ = recoveryServer(t)
				installApprovedTemporaryPassword(t, s, "SyntheticTemporary@1234")
				u, err := s.store.GetUserByID("recovery-target")
				if err != nil {
					t.Fatal(err)
				}
				token, err = auth.GenerateTokenWithExpiry(s.jwtSecret, u.ID, string(u.Role), auth.TokenTypePasswordRecovery, 5*time.Minute, u.TokenGeneration)
				if err != nil {
					t.Fatal(err)
				}
				userID = u.ID
				method = "POST"
				path = "/api/auth/password/recovery"
				body = `{"new_password":"SettingsBoundary!Password123"}`
			} else {
				s = testServer(t)
				token = registerAndGetAdminToken(t, s)
				claims, err := auth.ValidateToken(s.jwtSecret, token)
				if err != nil {
					t.Fatal(err)
				}
				userID = claims.Subject
				method = "PUT"
				path = "/api/auth/password"
				body = `{"current_password":"` + testPassword + `","new_password":"SettingsBoundary!Password123"}`
				if operation == "combined setup" {
					u, err := s.store.GetUserByID(userID)
					if err != nil {
						t.Fatal(err)
					}
					hash, err := auth.HashPassword("SyntheticTemporary@1234")
					if err != nil {
						t.Fatal(err)
					}
					if err := s.store.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration}, hash, s.now()); err != nil {
						t.Fatal(err)
					}
					u, _ = s.store.GetUserByID(userID)
					token, err = auth.GenerateTokenWithExpiry(s.jwtSecret, u.ID, string(u.Role), auth.TokenTypeSetup, 5*time.Minute, u.TokenGeneration)
					if err != nil {
						t.Fatal(err)
					}
					setup := lifecycleRequest(t, s, "POST", "/api/auth/totp/setup", token, nil)
					if setup.Code != 200 {
						t.Fatalf("setup: %s", setup.Body.String())
					}
					secret := managementJSON(t, setup)["secret"].(string)
					method = "POST"
					path = "/api/auth/totp/enable"
					body = fmt.Sprintf(`{"code":%q,"new_password":"SettingsBoundary!Password123"}`, validTOTPCode(t, secret, s.now()))
				}
			}
			if _, err := s.store.DB().Exec("INSERT INTO _config(key,value) VALUES('auth.password_history_count','1') ON CONFLICT(key) DO UPDATE SET value=excluded.value"); err != nil {
				t.Fatal(err)
			}
			before, err := s.store.GetUserByID(userID)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := auth.ValidateToken(s.jwtSecret, token)
			if err != nil {
				t.Fatal(err)
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			var reads atomic.Int32
			name := "settings_delay_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			// The second history-settings read is the final preparation before the
			// store call. A SQL scalar gate deterministically blocks that real read.
			if err := sqlite.RegisterScalarFunction(name, 2, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
				targetRead := int32(2)
				if operation == "protected password" {
					targetRead = 1
				}
				if args[0] == "auth.password_history_count" && reads.Add(1) == targetRead {
					close(entered)
					<-resume
				}
				return args[1], nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.store.DB().Exec("ALTER TABLE _config RENAME TO settings_boundary_config; CREATE VIEW _config AS SELECT key," + name + "(key,value) AS value FROM settings_boundary_config"); err != nil {
				t.Fatal(err)
			}
			keeper, err := s.store.DB().Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer keeper.Close()
			// Keep the shared-memory database alive while fresh connections load the scalar gate.
			// Open fresh pooled connections after function registration.
			s.store.DB().SetMaxIdleConns(0)
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Authorization", testBearerPrefix+token)
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); s.routes().ServeHTTP(rec, req) }()
			select {
			case <-entered:
			case <-done:
				close(resume)
				t.Fatalf("request missed delayed settings read: %d %s", rec.Code, rec.Body.String())
			case <-time.After(20 * time.Second):
				close(resume)
				<-done
				t.Fatal("settings read never reached")
			}
			expired := claims.ExpiresAt.Time.Add(time.Second)
			s.SetClock(func() time.Time { return expired })
			close(resume)
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("request did not finish")
			}
			live, err := s.store.GetUserByID(userID)
			if err != nil {
				t.Fatal(err)
			}
			if rec.Code < 400 || live.PasswordHash != before.PasswordHash || live.TOTPEnabled != before.TOTPEnabled || live.TokenGeneration != before.TokenGeneration {
				t.Fatalf("expired settings-gap authority committed: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestReactivationResamplesAuthorityAfterDelayedPolicyRead(t *testing.T) {
	f := newLifecycleFixture(t)
	claims, err := auth.ValidateToken(f.s.jwtSecret, f.adminToken)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	managementServerExec(t, f.s, "UPDATE sessions SET expires_at=? WHERE id=?", expires.Format("2006-01-02 15:04:05"), claims.SessionID)
	managementServerExec(t, f.s, "UPDATE users SET created_at='2000-01-01 00:00:00',last_activity_at=NULL,reactivated_at=NULL,dormancy_exempt=0 WHERE id=?", f.viewerID)
	if err := f.s.store.SetConfig("account.dormant_days", "35"); err != nil {
		t.Fatal(err)
	}
	name := "reactivation_policy_delay_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	entered, resume := make(chan struct{}), make(chan struct{})
	var blocked atomic.Bool
	if err := sqlite.RegisterScalarFunction(name, 2, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		if args[0] == "account.dormant_days" && blocked.CompareAndSwap(false, true) {
			close(entered)
			<-resume
		}
		return args[1], nil
	}); err != nil {
		t.Fatal(err)
	}
	managementServerExec(t, f.s, "ALTER TABLE _config RENAME TO reactivation_config; CREATE VIEW _config AS SELECT key,"+name+"(key,value) AS value FROM reactivation_config")
	keeper, err := f.s.store.DB().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	f.s.store.DB().SetMaxIdleConns(0)
	req := httptest.NewRequest("POST", "/", nil)
	req.SetPathValue("id", f.viewerID)
	req.Header.Set("Authorization", testBearerPrefix+f.adminToken)
	req = req.WithContext(context.WithValue(req.Context(), ctxUserID, f.adminID))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); f.s.handleReactivateUser(rec, req) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(resume)
		<-done
		t.Fatal("reactivation policy read did not block")
	}
	time.Sleep(time.Until(expires) + 100*time.Millisecond)
	close(resume)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reactivation request did not terminate")
	}
	user := managementUser(t, f)
	if rec.Code < 400 || user.ReactivatedAt != nil {
		t.Fatalf("expired administrator session committed reactivation: HTTP %d reactivated=%t", rec.Code, user.ReactivatedAt != nil)
	}
}
