package server

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// Snapshot full rows so rollback assertions include generations, secrets,
// history contents, grants, session/token state, setup state and success audits.
func totpDurableState(t *testing.T, s *Server, user string) string {
	t.Helper()
	state := map[string][][]any{}
	queries := map[string]string{"users": "SELECT * FROM users WHERE id=?", "_config": "SELECT * FROM _config WHERE ?!='' ORDER BY key", "audit_logs": "SELECT * FROM audit_logs WHERE target=? ORDER BY rowid"}
	for _, table := range []string{"password_history", "sessions", "api_tokens", "application_login_anchors", "application_sessions", "application_launch_tickets", "local_break_glass_recoveries", "security_mfa_recoveries", "security_password_recoveries", "stepup_proofs"} {
		queries[table] = "SELECT * FROM " + table + " WHERE user_id=? ORDER BY rowid"
	}
	for name, query := range queries {
		rows, err := s.store.DB().Query(query, user)
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			state[name] = append(state[name], values)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func seedTOTPAuthority(t *testing.T, s *Server, user string) {
	t.Helper()
	for _, query := range []string{
		`INSERT INTO sessions(id,user_id,kind,created_at,last_seen_at) VALUES('fault-session',?,'web',datetime('now'),datetime('now'))`,
		`INSERT INTO api_tokens(id,user_id,name,token_hash,token_prefix) VALUES('fault-token',?,'fault','fault-hash','fault')`,
		`INSERT INTO application_login_anchors(id,user_id,completed_mfa_at,token_generation) VALUES('fault-anchor',?,1,0)`,
		`INSERT INTO applications(id,slug,public_hostname,name,config_version,enabled,config_json) SELECT 'fault-app','fault-app','fault.invalid','Fault',1,1,'{}' WHERE ?!=''`,
		`INSERT INTO application_sessions(id,credential_digest,app_id,user_id,anchor_id,config_version,access_revision,created_at,last_seen_at,expires_at) VALUES('fault-app-session','fault-digest','fault-app',?,'fault-anchor',1,1,1,1,9999999999999)`,
		`INSERT INTO application_launch_tickets(digest,app_id,user_id,anchor_id,hostname,path,config_version,access_revision,expires_at) VALUES('fault-ticket','fault-app',?,'fault-anchor','fault.invalid','/',1,1,9999999999999)`,
		`INSERT INTO stepup_proofs(hash,user_id,session_id,action,digest,created_at,expires_at) VALUES('fault-proof',?,'fault-session','test',printf('%064d',0),0,9999999999)`,
	} {
		managementServerExec(t, s, query, user)
	}
}

func TestTOTPCompletionStorageFailuresReturnOpaque500AndRollBack(t *testing.T) {
	for _, boundary := range []string{
		"BEFORE UPDATE OF password_hash ON users", "BEFORE DELETE ON password_history",
		"BEFORE INSERT ON audit_logs WHEN NEW.action='user.password_changed'",
		"BEFORE INSERT ON audit_logs WHEN NEW.action='user.totp_enabled'",
		"BEFORE UPDATE OF totp_enabled ON users WHEN NEW.totp_enabled=1",
		"BEFORE INSERT ON _config WHEN NEW.key='initial_setup_completed'",
	} {
		t.Run(boundary, func(t *testing.T) {
			f := newLifecycleFixture(t)
			login := lifecycleRequest(t, f.s, "POST", "/api/auth/login", "", model.LoginRequest{Username: lifecycleViewerName, Password: f.viewerPass})
			if login.Code != 200 {
				t.Fatalf("login: %d %s", login.Code, login.Body.String())
			}
			token := managementJSON(t, login)["setup_token"].(string)
			setup := lifecycleRequest(t, f.s, "POST", "/api/auth/totp/setup", token, nil)
			if setup.Code != 200 {
				t.Fatalf("setup: %d %s", setup.Code, setup.Body.String())
			}
			secret := managementJSON(t, setup)["secret"].(string)
			seedTOTPAuthority(t, f.s, f.viewerID)
			u := managementUser(t, f)
			managementServerExec(t, f.s, "INSERT INTO password_history(id,user_id,password_hash) VALUES('legacy',?,?)", u.ID, u.PasswordHash)
			before := totpDurableState(t, f.s, f.viewerID)
			managementServerExec(t, f.s, "CREATE TRIGGER totp_http_fault "+boundary+" BEGIN SELECT RAISE(ABORT,'synthetic SQLite secret outage'); END")
			done := lifecycleRequest(t, f.s, "POST", "/api/auth/totp/enable", token, model.TOTPEnableRequest{Code: validTOTPCode(t, secret, f.s.now()), NewPassword: managementValidPermanent})
			if done.Code != 500 || strings.Contains(done.Body.String(), "SQLite") || strings.Contains(done.Body.String(), secret) || before != totpDurableState(t, f.s, f.viewerID) {
				t.Fatalf("storage failure leaked details, misclassified status, or changed state: %d %s", done.Code, done.Body.String())
			}
		})
	}
}

func TestAdminTOTPDisableStorageFailuresReturnOpaque500AndRollBack(t *testing.T) {
	for _, boundary := range []string{
		"BEFORE UPDATE OF totp_secret ON users", "BEFORE UPDATE OF token_generation ON users",
		"BEFORE UPDATE OF ssh_credential_generation ON users", "BEFORE UPDATE ON api_tokens",
		"BEFORE UPDATE ON sessions", "BEFORE UPDATE ON application_login_anchors",
		"BEFORE UPDATE ON application_sessions", "BEFORE DELETE ON application_launch_tickets",
		"BEFORE UPDATE ON stepup_proofs", "BEFORE INSERT ON audit_logs WHEN NEW.action='user.totp_disabled'", "commit",
	} {
		t.Run(boundary, func(t *testing.T) {
			f := newLifecycleFixture(t)
			managementEnableExistingMFA(t, f)
			seedTOTPAuthority(t, f.s, f.viewerID)
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
			if boundary == "commit" {
				managementServerExec(t, f.s, "CREATE TABLE totp_http_deferred(user_id TEXT REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED)")
				managementServerExec(t, f.s, "CREATE TRIGGER totp_http_fault AFTER INSERT ON audit_logs WHEN NEW.action='user.totp_disabled' BEGIN INSERT INTO totp_http_deferred VALUES('missing'); END")
			} else {
				managementServerExec(t, f.s, "CREATE TRIGGER totp_http_fault "+boundary+" BEGIN SELECT RAISE(ABORT,'synthetic SQLite secret outage'); END")
			}
			done := lifecycleRequest(t, f.s, "POST", testTOTPDisablePath, f.adminToken, model.TOTPDisableRequest{UserID: f.viewerID, AdminTOTPCode: validTOTPCode(t, *secret, time.Now())})
			if done.Code != 500 || strings.Contains(done.Body.String(), "SQLite") || before != totpDurableState(t, f.s, f.viewerID) {
				t.Fatalf("factor removal partially committed or misclassified failure: %d %s", done.Code, done.Body.String())
			}
		})
	}
}

func TestTOTPPersistenceErrorMapsOnlyKnownErrors(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
	}{
		{store.ErrSecurityConflict, 409}, {store.ErrProtectedChange, 403}, {store.ErrAccountManagementActor, 403},
		{store.ErrTemporaryPasswordExpired, 401}, {store.ErrLocalPasswordOnly, 400}, {errors.New("invalid required database secret"), 500},
	} {
		response := httptest.NewRecorder()
		totpPersistenceError(response, test.err)
		if response.Code != test.status || strings.Contains(response.Body.String(), "database secret") {
			t.Fatalf("wrong error mapping: %d %s", response.Code, response.Body.String())
		}
	}
}
