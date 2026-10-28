package store_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// Capture complete persisted rows, including replaced history and recovery
// grants, so a failure cannot hide behind unchanged row counts.
func breakGlassState(t *testing.T, s *store.Store) string {
	t.Helper()
	state := map[string][][]any{}
	for _, table := range []string{"users", "_config", "password_history", "sessions", "api_tokens", "application_login_anchors", "application_sessions", "application_launch_tickets", "audit_logs", "local_break_glass_recoveries", "security_password_recoveries", "security_mfa_recoveries", "stepup_proofs", "security_approvals"} {
		rows, err := s.DB().Query("SELECT * FROM " + table + " ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(cols))
			pointers := make([]any, len(cols))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			state[table] = append(state[table], values)
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

func installBreakGlassApplicationAuthority(t *testing.T, s *store.Store) {
	t.Helper()
	managementExec(t, s, `INSERT INTO applications(id,slug,public_hostname,name,config_version,enabled,config_json) VALUES('app','app','app.invalid','App',1,1,'{}')`)
	managementExec(t, s, `INSERT INTO application_sessions(id,credential_digest,app_id,user_id,anchor_id,config_version,access_revision,created_at,last_seen_at,expires_at) VALUES('app-session','digest','app','target','anchor',1,1,1,1,9999999999999)`)
	managementExec(t, s, `INSERT INTO application_launch_tickets(digest,app_id,user_id,anchor_id,hostname,path,config_version,access_revision,expires_at) VALUES('ticket','app','target','anchor','app.invalid','/',1,1,9999999999999)`)
}

func TestBreakGlassResetRollsBackEveryStorageBoundary(t *testing.T) {
	boundaries := []string{
		"BEFORE INSERT ON password_history",
		"BEFORE DELETE ON password_history",
		"BEFORE DELETE ON password_history WHEN OLD.password_hash='older'",
		"BEFORE UPDATE OF password_hash ON users",
		"BEFORE UPDATE OF totp_secret ON users",
		"BEFORE UPDATE OF token_generation ON users",
		"BEFORE UPDATE OF ssh_credential_generation ON users",
		"BEFORE INSERT ON _config WHEN NEW.key='initial_setup_completed'",
		"BEFORE UPDATE ON api_tokens",
		"BEFORE UPDATE ON sessions",
		"BEFORE UPDATE ON application_login_anchors",
		"BEFORE UPDATE ON application_sessions",
		"BEFORE DELETE ON application_launch_tickets",
		"BEFORE DELETE ON security_password_recoveries",
		"BEFORE DELETE ON security_mfa_recoveries",
		"BEFORE INSERT ON audit_logs",
		"BEFORE INSERT ON local_break_glass_recoveries",
		"commit",
	}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			f := newManagementMutationFixture(t, "reset")
			installBreakGlassApplicationAuthority(t, f.s)
			managementExec(t, f.s, `INSERT INTO password_history(id,user_id,password_hash) VALUES('older','target','older')`)
			settings := f.s.GetAuditSettings()
			settings.PasswordHistoryCount = 1
			if err := f.s.UpdateAuditSettings(settings); err != nil {
				t.Fatal(err)
			}
			managementExec(t, f.s, `INSERT INTO password_history(id,user_id,password_hash) VALUES('legacy','target','h')`)
			// Use an existing applied change solely as a fixture for stale grants.
			managementExec(t, f.s, `INSERT INTO security_changes(id,revision,requester_id,requester_person,requester_generation,expected_version,digest,reason,payload,state,created_at,expires_at) VALUES('old',1,'actor','actor',0,1,?,'test','{}','applied',0,9999999999)`, strings.Repeat("0", 64))
			managementExec(t, f.s, `INSERT INTO security_password_recoveries VALUES('target','old','h')`)
			managementExec(t, f.s, `INSERT INTO security_mfa_recoveries VALUES('target','old',0)`)
			before := breakGlassState(t, f.s)
			if boundary == "commit" {
				managementExec(t, f.s, `CREATE TABLE break_glass_deferred_fault(user_id TEXT REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED)`)
				managementExec(t, f.s, `CREATE TRIGGER break_glass_fault AFTER INSERT ON local_break_glass_recoveries BEGIN INSERT INTO break_glass_deferred_fault VALUES('missing'); END`)
			} else {
				managementExec(t, f.s, "CREATE TRIGGER break_glass_fault "+boundary+" BEGIN SELECT RAISE(ABORT,'synthetic break-glass failure'); END")
			}
			err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: f.user.ID, ExpectedGeneration: f.user.TokenGeneration}, managementReplacementHash, f.now)
			if err == nil {
				t.Fatal("storage fault reported success")
			}
			if after := breakGlassState(t, f.s); after != before {
				t.Fatal("failed reset changed persisted state")
			}
			managementExec(t, f.s, "DROP TRIGGER break_glass_fault")
			if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: f.user.ID, ExpectedGeneration: f.user.TokenGeneration}, managementReplacementHash, f.now); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBreakGlassResetProtectedLocalAndLDAPBoundary(t *testing.T) {
	for _, provider := range []model.AuthProvider{model.AuthProviderLocal, model.AuthProviderLDAP} {
		for _, protected := range []bool{false, true} {
			t.Run(string(provider)+map[bool]string{false: "/ordinary", true: "/protected"}[protected], func(t *testing.T) {
				f := newManagementMutationFixture(t, "reset")
				installBreakGlassApplicationAuthority(t, f.s)
				if protected {
					managementExec(t, f.s, "INSERT INTO user_roles(user_id,role) VALUES('target','original-reader')")
				}
				managementExec(t, f.s, "UPDATE users SET auth_provider=? WHERE id='target'", provider)
				before := mustGetUser(t, f.s, "target")
				state := breakGlassState(t, f.s)
				err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: before.ID, ExpectedGeneration: before.TokenGeneration}, managementReplacementHash, f.now)
				if provider == model.AuthProviderLDAP {
					if !errors.Is(err, store.ErrLocalPasswordOnly) || state != breakGlassState(t, f.s) {
						t.Fatalf("LDAP changed or wrong refusal: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				after := mustGetUser(t, f.s, "target")
				if after.TOTPEnabled || after.TOTPSecret != nil || !after.MustChangePassword || after.TempPasswordExpiresAt == nil || after.TokenGeneration != before.TokenGeneration+1 || after.SSHCredentialGeneration != before.SSHCredentialGeneration+1 {
					t.Fatal("incomplete reset")
				}
				if !after.TempPasswordExpiresAt.Equal(f.now.Add(72 * time.Hour)) {
					t.Fatal("default expiry not applied")
				}
				for _, query := range []string{"SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL", "SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL", "SELECT COUNT(*) FROM application_login_anchors WHERE revoked_at IS NULL", "SELECT COUNT(*) FROM application_sessions WHERE ended_at IS NULL", "SELECT COUNT(*) FROM application_launch_tickets"} {
					var n int
					if err := f.s.DB().QueryRow(query).Scan(&n); err != nil || n != 0 {
						t.Fatalf("authority survived: %s: %d %v", query, n, err)
					}
				}
				assertPasswordHistoryHashes(t, f.s, "target", []string{before.PasswordHash})
				if protected {
					secret := "new-secret"
					if err := f.s.UpdateUserTOTP(after.ID, &secret, false, after.TokenGeneration); err != nil {
						t.Fatal(err)
					}
					after = mustGetUser(t, f.s, "target")
					_, err := f.s.CompleteApprovedPasswordRecoveryAudited(store.PasswordRecoverySnapshot{UserID: after.ID, PasswordHash: after.PasswordHash, SecurityRevision: after.SecurityRevision, TokenGeneration: after.TokenGeneration}, "permanent", f.now, 1, f.entry)
					if err != nil {
						t.Fatal(err)
					}
					after = mustGetUser(t, f.s, "target")
					if err := f.s.UpdateUserTOTP(after.ID, &secret, true, after.TokenGeneration); err != nil {
						t.Fatal(err)
					}
					if err := f.s.UpdateUserTOTP(after.ID, nil, false); !errors.Is(err, store.ErrProtectedChange) {
						t.Fatalf("consumed recovery bypassed protection: %v", err)
					}
				}
			})
		}
	}
}

func TestBreakGlassResetConfiguredRetentionTTLAndRepeatedTemporary(t *testing.T) {
	f := newManagementMutationFixture(t, "reset")
	settings := f.s.GetAuditSettings()
	settings.PasswordHistoryCount, settings.TemporaryPasswordTTLHours = 1, 3
	if err := f.s.UpdateAuditSettings(settings); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{"first-temporary", "second-temporary", "third-temporary"} {
		u := mustGetUser(t, f.s, f.user.ID)
		if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration}, hash, f.now); err != nil {
			t.Fatal(err)
		}
		assertPasswordHistoryHashes(t, f.s, u.ID, []string{f.user.PasswordHash})
		got := mustGetUser(t, f.s, u.ID)
		if !got.TempPasswordExpiresAt.Equal(f.now.Add(3 * time.Hour)) {
			t.Fatal("configured expiry ignored")
		}
	}
	u := mustGetUser(t, f.s, f.user.ID)
	state := breakGlassState(t, f.s)
	if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration - 1}, "stale", f.now); !errors.Is(err, store.ErrSecurityConflict) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state, breakGlassState(t, f.s)) {
		t.Fatal("stale reset changed state")
	}
}

func TestBreakGlassRepeatedResetGrantFailureRollsBack(t *testing.T) {
	f := newManagementMutationFixture(t, "reset")
	if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: f.user.ID, ExpectedGeneration: f.user.TokenGeneration}, "first-temporary", f.now); err != nil {
		t.Fatal(err)
	}
	u := mustGetUser(t, f.s, f.user.ID)
	before := breakGlassState(t, f.s)
	managementExec(t, f.s, `CREATE TRIGGER break_glass_repeat_fault BEFORE UPDATE ON local_break_glass_recoveries BEGIN SELECT RAISE(ABORT,'synthetic replacement grant failure'); END`)
	if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration}, "second-temporary", f.now); err == nil {
		t.Fatal("replacement grant failure reported success")
	}
	if before != breakGlassState(t, f.s) {
		t.Fatal("failed repeated reset changed the existing recovery")
	}
}

func TestBreakGlassRevokedMFAGrantCannotBeRevivedByApprovedPasswordCompletion(t *testing.T) {
	f := newManagementMutationFixture(t, "reset")
	managementExec(t, f.s, `INSERT INTO user_roles(user_id,role) VALUES('target','original-reader')`)
	u := mustGetUser(t, f.s, f.user.ID)
	if err := f.s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration}, "temporary", f.now); err != nil {
		t.Fatal(err)
	}
	managementExec(t, f.s, `UPDATE users SET token_generation=token_generation+1 WHERE id='target'`)
	managementExec(t, f.s, `INSERT INTO security_changes(id,revision,requester_id,requester_person,requester_generation,expected_version,digest,reason,payload,state,created_at,expires_at,result_ref) VALUES('approved',1,'actor','actor',0,1,?,'test','{}','applied',0,9999999999,'result')`, strings.Repeat("0", 64))
	managementExec(t, f.s, `INSERT INTO security_password_recoveries VALUES('target','approved','temporary')`)
	u = mustGetUser(t, f.s, u.ID)
	if _, err := f.s.CompleteApprovedPasswordRecoveryAudited(store.PasswordRecoverySnapshot{UserID: u.ID, PasswordHash: u.PasswordHash, SecurityRevision: u.SecurityRevision, TokenGeneration: u.TokenGeneration}, "permanent", f.now, 1, f.entry); err != nil {
		t.Fatal(err)
	}
	u = mustGetUser(t, f.s, u.ID)
	secret := "must-not-install"
	if err := f.s.UpdateUserTOTP(u.ID, &secret, false, u.TokenGeneration); !errors.Is(err, store.ErrProtectedChange) {
		t.Fatalf("revoked shell MFA grant revived: %v", err)
	}
}

func TestBreakGlassConcurrentStoreResetsCommitOneGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	first, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	u := newLifecycleUser(t, first, "target", "target", model.RoleAdmin)
	second, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	start := make(chan struct{})
	results := make(chan error, 2)
	now := time.Now().UTC()
	for i, s := range []*store.Store{first, second} {
		go func() {
			<-start
			results <- s.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration}, []string{"temporary-one", "temporary-two"}[i], now)
		}()
	}
	close(start)
	var successes, conflicts int
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, store.ErrSecurityConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent reset: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	assertPasswordHistoryHashes(t, first, u.ID, []string{u.PasswordHash})
	after := mustGetUser(t, first, u.ID)
	if after.TokenGeneration != u.TokenGeneration+1 {
		t.Fatal("concurrent reset committed extra generations")
	}
	var grants int
	if err := first.DB().QueryRow(`SELECT COUNT(*) FROM local_break_glass_recoveries r JOIN users u ON u.id=r.user_id WHERE r.password_hash=u.password_hash AND r.token_generation=u.token_generation`).Scan(&grants); err != nil || grants != 1 {
		t.Fatalf("recovery grant not bound to winning generation: %v", err)
	}
	action := model.AuditUserTOTPReset
	_, count, err := first.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 10})
	if err != nil || count != 1 {
		t.Fatal("concurrent reset recorded extra audits")
	}
}
