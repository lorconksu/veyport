package server

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

const (
	managementRecoveryEndpoint = "/api/auth/password/recovery"
	managementValidPermanent   = "ValidPermanent!Password123"
)

func managementServerExec(t *testing.T, s *Server, query string, args ...any) {
	t.Helper()
	if _, err := s.store.DB().Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func managementRecoveryFixture(t *testing.T) (*lifecycleFixture, string) {
	t.Helper()
	f := newLifecycleFixture(t)
	managementEnableExistingMFA(t, f)
	reset := managementReset(t, f)
	return f, managementRecovery(t, f, reset["temporary_password"].(string))
}

func assertManagementRecoveryUnchanged(t *testing.T, f *lifecycleFixture, before *model.User) {
	t.Helper()
	live := managementUser(t, f)
	if live.PasswordHash != before.PasswordHash || live.TokenGeneration != before.TokenGeneration || live.SecurityRevision != before.SecurityRevision || !live.MustChangePassword || live.SSHCredentialGeneration != before.SSHCredentialGeneration {
		t.Fatal("refused recovery changed credential authority")
	}
}

func TestAccountManagementErrorResponsesDoNotExposeStorageDetails(t *testing.T) {
	s := testServer(t)
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{"actor", store.ErrAccountManagementActor, 403}, {"protected", store.ErrProtectedChange, 403}, {"revision", store.ErrSecurityConflict, 409}, {"disabled", store.ErrAccountDisabled, 409},
		{"expired", store.ErrTemporaryPasswordExpired, 401}, {"directory", store.ErrLocalPasswordOnly, 400}, {"missing", errors.New("user not found"), 404}, {"storage", errors.New("private SQL storage detail"), 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			s.accountManagementError(response, test.err)
			if response.Code != test.status || strings.Contains(response.Body.String(), "private SQL") {
				t.Fatalf("unsafe account error mapping: status=%d", response.Code)
			}
		})
	}
}

func TestAccountManagementStaleRefusalAuditBindsActorAndTarget(t *testing.T) {
	f := newLifecycleFixture(t)
	request := httptest.NewRequest("POST", "/api/users/"+f.viewerID+"/password-reset", nil)
	f.s.auditAccountManagementRefusal(request, f.adminID, f.viewerID, model.AuditUserPasswordReset, store.ErrSecurityConflict)
	var outcome, detail, actor, target string
	if err := f.s.store.DB().QueryRow("SELECT outcome,detail,user_id,target FROM audit_logs WHERE action=? AND target=? ORDER BY rowid DESC LIMIT 1", model.AuditUserPasswordReset, f.viewerID).Scan(&outcome, &detail, &actor, &target); err != nil {
		t.Fatal(err)
	}
	if outcome != model.AuditOutcomeFailure || detail != "stale account revision" || actor != f.adminID || target != f.viewerID {
		t.Fatal("stale reset audit lost outcome or identity binding")
	}
}

func TestAccountManagementMissingResetTargetIsNotFound(t *testing.T) {
	f := newLifecycleFixture(t)
	response := lifecycleRequest(t, f.s, "POST", "/api/users/missing-target/password-reset", f.adminToken, map[string]int{"expected_revision": 0})
	if response.Code != 404 || managementJSON(t, response)["temporary_password"] != nil {
		t.Fatal("missing account reset disclosed credential or incorrect refusal")
	}
}

func TestAccountManagementFailedResetReturnsNoSecretAndAllowsExplicitRetry(t *testing.T) {
	f := newLifecycleFixture(t)
	before := managementUser(t, f)
	managementServerExec(t, f.s, "CREATE TRIGGER fail_reset_password BEFORE UPDATE OF password_hash ON users BEGIN SELECT RAISE(ABORT,'synthetic reset failure'); END")
	response := lifecycleRequest(t, f.s, "POST", "/api/users/"+f.viewerID+"/password-reset", f.adminToken, map[string]int{"expected_revision": before.TokenGeneration})
	if response.Code != 500 || managementJSON(t, response)["temporary_password"] != nil {
		t.Fatal("uncommitted reset returned a usable credential")
	}
	after := managementUser(t, f)
	if after.PasswordHash != before.PasswordHash || after.TokenGeneration != before.TokenGeneration || after.SecurityRevision != before.SecurityRevision {
		t.Fatal("failed reset changed credentials")
	}
	var successes int
	if err := f.s.store.DB().QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action=? AND target=? AND outcome='success'", model.AuditUserPasswordReset, f.viewerID).Scan(&successes); err != nil || successes != 0 {
		t.Fatal("failed reset recorded a committed success")
	}
	managementServerExec(t, f.s, "DROP TRIGGER fail_reset_password")
	managementReset(t, f)
}

func TestAccountManagementRecoveryInvalidInputsPreserveAuthority(t *testing.T) {
	f, recovery := managementRecoveryFixture(t)
	before := managementUser(t, f)
	for _, test := range []struct {
		name   string
		body   any
		status int
	}{
		{"malformed JSON", "{", 400}, {"weak password", map[string]string{"new_password": "weak"}, 400},
		{"bcrypt cannot encode supplied password", map[string]string{"new_password": strings.Repeat("Long!Password123", 6)}, 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := lifecycleRequest(t, f.s, "POST", managementRecoveryEndpoint, recovery, test.body)
			if response.Code != test.status {
				t.Fatalf("invalid recovery input status=%d wanted=%d", response.Code, test.status)
			}
			assertManagementRecoveryUnchanged(t, f, before)
		})
	}
	completed := lifecycleRequest(t, f.s, "POST", managementRecoveryEndpoint, recovery, map[string]string{"new_password": managementValidPermanent})
	if completed.Code != 200 {
		t.Fatal("invalid inputs consumed authority needed for explicit valid retry")
	}
}

func TestAccountManagementRecoveryStorageRefusalsPreserveTemporaryState(t *testing.T) {
	for _, fault := range []struct{ name, sql string }{
		{"history lookup", "DROP TABLE password_history"},
		{"protected identity lookup", "DROP TABLE security_nominations"},
		{"authoritative completion", "CREATE TRIGGER fail_recovery_write BEFORE UPDATE OF password_hash ON users BEGIN SELECT RAISE(ABORT,'synthetic recovery write failure'); END"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			f, recovery := managementRecoveryFixture(t)
			before := managementUser(t, f)
			body := &managementDelayedBody{reader: strings.NewReader(string(mustMarshal(t, map[string]string{"new_password": managementValidPermanent}))), before: func() { managementServerExec(t, f.s, fault.sql) }}
			request := httptest.NewRequest("POST", managementRecoveryEndpoint, body)
			request.Header.Set("Authorization", testBearerPrefix+recovery)
			response := httptest.NewRecorder()
			f.s.routes().ServeHTTP(response, request)
			if response.Code != 500 || managementJSON(t, response)["requires_login"] != nil {
				t.Fatalf("failed authoritative recovery status=%d", response.Code)
			}
			assertManagementRecoveryUnchanged(t, f, before)
		})
	}
}

func TestAccountManagementRecoveryAndPasswordStageHonorNewDormancy(t *testing.T) {
	f := newLifecycleFixture(t)
	managementEnableExistingMFA(t, f)
	reset := managementReset(t, f)
	password := reset["temporary_password"].(string)
	challenge := managementChallenge(t, f, password)
	recovery := managementRecovery(t, f, password)
	before := managementUser(t, f)
	managementServerExec(t, f.s, "UPDATE users SET created_at=datetime('now','-60 days'),last_activity_at=NULL,reactivated_at=NULL WHERE id=?", f.viewerID)
	response := lifecycleRequest(t, f.s, "POST", managementRecoveryEndpoint, recovery, map[string]string{"new_password": managementValidPermanent})
	if response.Code != 401 || !strings.Contains(response.Body.String(), "dormant") {
		t.Fatal("recovery bypassed newly effective dormancy")
	}
	if _, _, _, _, err := f.s.authenticateRequestToken(challenge); err == nil {
		t.Fatal("password-stage authority bypassed newly effective dormancy")
	}
	assertManagementRecoveryUnchanged(t, f, before)
}

func TestAccountManagementRecoveryExpiryAndDeadlineCap(t *testing.T) {
	s := testServer(t)
	now := s.now()
	expired := now.Add(-time.Second)
	user := &model.User{ID: "temporary", Role: model.RoleViewer, MustChangePassword: true, TempPasswordExpiresAt: &expired}
	refused := httptest.NewRecorder()
	s.respondPasswordRecovery(refused, user)
	if refused.Code != 401 {
		t.Fatal("expired temporary state issued recovery authority")
	}
	expires := now.Add(time.Minute)
	user.TempPasswordExpiresAt = &expires
	response := httptest.NewRecorder()
	s.respondPasswordRecovery(response, user)
	if response.Code != 200 {
		t.Fatal("unexpired temporary state refused recovery authority")
	}
	token := managementJSON(t, response)["recovery_token"].(string)
	claims, err := auth.ValidateToken(s.jwtSecret, token)
	if err != nil || claims.TokenType != auth.TokenTypePasswordRecovery || claims.ExpiresAt.Time.After(expires) {
		t.Fatal("recovery challenge exceeded temporary credential expiry")
	}
}

func TestAccountManagementUnavailableProtectionMetadataFailsClosed(t *testing.T) {
	f := newLifecycleFixture(t)
	managementServerExec(t, f.s, "DROP TABLE security_nominations")
	response := lifecycleRequest(t, f.s, "GET", "/api/users", f.adminToken, nil)
	if response.Code != 500 || managementJSON(t, response)["users"] != nil {
		t.Fatal("unknown protected metadata was presented as ordinary account authority")
	}
}

func TestAccountManagementActorSnapshotRejectsInvalidAndDeletedIdentity(t *testing.T) {
	s := testServer(t)
	malformed := httptest.NewRequest("POST", "/api/users/target/reactivate", nil)
	malformed.Header.Set("Authorization", testBearerPrefix+"invalid")
	if actor := s.accountManagementActor(malformed); actor != (store.AccountManagementActor{}) {
		t.Fatal("invalid credential returned administrator snapshot")
	}
	token, err := auth.GenerateTokenWithExpiry(s.jwtSecret, "deleted-principal", string(model.RoleAdmin), auth.TokenTypeAccess, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	missing := httptest.NewRequest("POST", "/api/users/target/reactivate", nil)
	missing.Header.Set("Authorization", testBearerPrefix+token)
	if actor := s.accountManagementActor(missing); actor != (store.AccountManagementActor{}) {
		t.Fatal("deleted principal returned administrator snapshot")
	}
}

func TestAccountManagementSetupReplayCannotReplaceEnabledMFA(t *testing.T) {
	s := testServer(t)
	registerAndGetAdminToken(t, s)
	user, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.GenerateSetupToken(s.jwtSecret, user.ID, string(user.Role), user.TokenGeneration)
	if err != nil {
		t.Fatal(err)
	}
	response := lifecycleRequest(t, s, "POST", "/api/auth/totp/enable", token, model.TOTPEnableRequest{Code: "000000"})
	if response.Code != 409 {
		t.Fatalf("completed MFA setup replay status=%d", response.Code)
	}
	after, err := s.store.GetUserByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.TOTPEnabled || after.SecurityRevision != user.SecurityRevision || after.TOTPSecret == nil || *after.TOTPSecret != *user.TOTPSecret {
		t.Fatal("setup replay replaced configured MFA")
	}
}
